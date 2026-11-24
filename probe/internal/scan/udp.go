package scan

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// ---- minimal BER/ASN.1 for SNMP v2c ------------------------------------------

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func berTLV(tag byte, val []byte) []byte {
	return append(append([]byte{tag}, berLen(len(val))...), val...)
}

func berInt(v int) []byte {
	if v == 0 {
		return berTLV(0x02, []byte{0})
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append([]byte{byte(x & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTLV(0x02, b)
}

func berOID(oid string) ([]byte, error) {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, errors.New("short oid")
	}
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		nums[i] = n
	}
	b := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		var enc []byte
		enc = append(enc, byte(n&0x7f))
		for n >>= 7; n > 0; n >>= 7 {
			enc = append([]byte{byte(0x80 | (n & 0x7f))}, enc...)
		}
		b = append(b, enc...)
	}
	return berTLV(0x06, b), nil
}

// BuildSNMPGet builds an SNMPv2c GetRequest for one OID.
func BuildSNMPGet(community string, requestID int, oid string) ([]byte, error) {
	o, err := berOID(oid)
	if err != nil {
		return nil, err
	}
	varbind := berTLV(0x30, append(o, 0x05, 0x00)) // OID, NULL
	varbinds := berTLV(0x30, varbind)
	pdu := berTLV(0xa0, append(append(append(berInt(requestID), berInt(0)...), berInt(0)...), varbinds...))
	msg := append(berInt(1), berTLV(0x04, []byte(community))...) // version 1 == v2c
	return berTLV(0x30, append(msg, pdu...)), nil
}

type berNode struct {
	tag      byte
	val      []byte
	children []berNode
}

func berParse(b []byte, depth int) ([]berNode, error) {
	var out []berNode
	for len(b) > 0 {
		if len(b) < 2 || depth > 10 {
			return nil, errors.New("ber: truncated")
		}
		tag := b[0]
		l := int(b[1])
		hdr := 2
		if l&0x80 != 0 {
			nb := l & 0x7f
			if nb == 0 || nb > 3 || len(b) < 2+nb {
				return nil, errors.New("ber: bad length")
			}
			l = 0
			for _, x := range b[2 : 2+nb] {
				l = l<<8 | int(x)
			}
			hdr += nb
		}
		if hdr+l > len(b) {
			return nil, errors.New("ber: truncated value")
		}
		n := berNode{tag: tag, val: b[hdr : hdr+l]}
		if tag&0x20 != 0 { // constructed
			kids, err := berParse(n.val, depth+1)
			if err != nil {
				return nil, err
			}
			n.children = kids
		}
		out = append(out, n)
		b = b[hdr+l:]
	}
	return out, nil
}

// ParseSNMPResponse returns the first varbind value as a string if it is an OCTET STRING.
func ParseSNMPResponse(b []byte) (string, bool) {
	nodes, err := berParse(b, 0)
	if err != nil || len(nodes) != 1 || nodes[0].tag != 0x30 || len(nodes[0].children) < 3 {
		return "", false
	}
	pdu := nodes[0].children[2]
	if pdu.tag != 0xa2 || len(pdu.children) < 4 { // GetResponse
		return "", false
	}
	vbs := pdu.children[3]
	if len(vbs.children) == 0 || len(vbs.children[0].children) < 2 {
		return "", true
	}
	v := vbs.children[0].children[1]
	if v.tag == 0x04 {
		return sanitize(v.val), true
	}
	return "", true
}

// ---- UDP checks ----------------------------------------------------------------

func udpExchange(addr string, payload []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// udpChecks probes DNS(53), NTP(123), SNMP(161) and SSDP(1900).
func (s *Scanner) udpChecks(ip string, tr *TargetResult) {
	to := s.opts.UDPTimeout
	// DNS open resolver
	s.limiter.wait()
	if responded, recursive := checkOpenResolver(net.JoinHostPort(ip, "53"), to); responded {
		tr.Services = append(tr.Services, Service{Port: 53, Proto: "udp", State: "open", Service: "dns",
			Banner: map[bool]string{true: "recursion available", false: "authoritative/refused recursion"}[recursive]})
		if recursive {
			tr.Issues = append(tr.Issues, Issue{ID: "dns_open_resolver", Severity: "medium", Port: 53,
				Title:  "Open DNS resolver",
				Detail: "The server answers recursive queries from the internet and can be abused for DNS amplification DDoS and cache-poisoning attempts. Restrict recursion to internal clients."})
		}
	}
	// NTP mode 3 client request
	s.limiter.wait()
	ntp := make([]byte, 48)
	ntp[0] = 0x1b // LI=0 VN=3 Mode=3
	if r, err := udpExchange(net.JoinHostPort(ip, "123"), ntp, to); err == nil && len(r) >= 48 && r[0]&0x07 == 4 {
		tr.Services = append(tr.Services, Service{Port: 123, Proto: "udp", State: "open", Service: "ntp",
			Banner: "stratum " + strconv.Itoa(int(r[1]))})
		tr.Issues = append(tr.Issues, Issue{ID: "ntp_exposed", Severity: "info", Port: 123,
			Title: "NTP server reachable from the internet", Detail: "Make sure monlist/mode 6-7 queries are disabled (noquery) to prevent amplification abuse."})
	}
	// SNMP v2c "public"
	s.limiter.wait()
	if q, err := BuildSNMPGet("public", 0x5a4d, "1.3.6.1.2.1.1.1.0"); err == nil {
		if r, err := udpExchange(net.JoinHostPort(ip, "161"), q, to); err == nil {
			if descr, ok := ParseSNMPResponse(r); ok {
				tr.Services = append(tr.Services, Service{Port: 161, Proto: "udp", State: "open", Service: "snmp",
					Product: "SNMPv2c", Banner: descr})
				tr.Issues = append(tr.Issues, Issue{ID: "snmp_public_community", Severity: "high", Port: 161,
					Title:  "SNMP answers the default 'public' community from the internet",
					Detail: "Anyone can read device configuration, interfaces, routes and often ARP tables. Block SNMP at the edge and use SNMPv3 with authentication."})
			}
		}
	}
	// SSDP / UPnP
	s.limiter.wait()
	msearch := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
	if r, err := udpExchange(net.JoinHostPort(ip, "1900"), []byte(msearch), to); err == nil && strings.HasPrefix(string(r), "HTTP/1.1 200") {
		server := ""
		for _, line := range strings.Split(string(r), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "server") {
				server = strings.TrimSpace(v)
			}
		}
		tr.Services = append(tr.Services, Service{Port: 1900, Proto: "udp", State: "open", Service: "upnp", Product: server,
			Banner: sanitize([]byte(server))})
		tr.Issues = append(tr.Issues, Issue{ID: "upnp_exposed", Severity: "high", Port: 1900,
			Title:  "UPnP/SSDP responds on the internet-facing address",
			Detail: "SSDP on WAN enables reflection DDoS and on many routers exposes IGD control that lets anyone open ports. Disable UPnP on the WAN interface."})
	}
}
