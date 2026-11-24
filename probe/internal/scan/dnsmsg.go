package scan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Minimal DNS wire-format support (RFC 1035) for the queries the standard
// library cannot do: CAA, AXFR, and raw recursion tests against a target.

const (
	dnsTypeA     uint16 = 1
	dnsTypeNS    uint16 = 2
	dnsTypeCNAME uint16 = 5
	dnsTypeSOA   uint16 = 6
	dnsTypeTXT   uint16 = 16
	dnsTypeAAAA  uint16 = 28
	dnsTypeAXFR  uint16 = 252
	dnsTypeCAA   uint16 = 257
	dnsClassIN   uint16 = 1

	dnsFlagQR = 0x8000
	dnsFlagAA = 0x0400
	dnsFlagTC = 0x0200
	dnsFlagRD = 0x0100
	dnsFlagRA = 0x0080
)

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte // raw RDATA
	Value string // decoded for A/AAAA/CNAME/NS/TXT/CAA
}

type dnsMsg struct {
	ID        uint16
	Flags     uint16
	Questions []dnsQuestion
	Answers   []dnsRR
	NSCount   uint16
	ARCount   uint16
}

func (m *dnsMsg) rcode() int { return int(m.Flags & 0x000f) }

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var b []byte
	if name == "" {
		return []byte{0}, nil
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label in %q", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	if len(b) > 254 {
		return nil, fmt.Errorf("name too long: %q", name)
	}
	return append(b, 0), nil
}

// pack encodes a message (names uncompressed).
func (m *dnsMsg) pack() ([]byte, error) {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], m.ID)
	binary.BigEndian.PutUint16(b[2:], m.Flags)
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(b[8:], m.NSCount)
	binary.BigEndian.PutUint16(b[10:], m.ARCount)
	for _, q := range m.Questions {
		n, err := encodeName(q.Name)
		if err != nil {
			return nil, err
		}
		b = append(b, n...)
		b = binary.BigEndian.AppendUint16(b, q.Type)
		b = binary.BigEndian.AppendUint16(b, q.Class)
	}
	for _, rr := range m.Answers {
		n, err := encodeName(rr.Name)
		if err != nil {
			return nil, err
		}
		b = append(b, n...)
		b = binary.BigEndian.AppendUint16(b, rr.Type)
		b = binary.BigEndian.AppendUint16(b, rr.Class)
		b = binary.BigEndian.AppendUint32(b, rr.TTL)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rr.Data)))
		b = append(b, rr.Data...)
	}
	return b, nil
}

func buildQuery(id uint16, name string, qtype uint16, recursionDesired bool) ([]byte, error) {
	m := dnsMsg{ID: id, Questions: []dnsQuestion{{Name: name, Type: qtype, Class: dnsClassIN}}}
	if recursionDesired {
		m.Flags |= dnsFlagRD
	}
	return m.pack()
}

var errDNSShort = errors.New("dns: message truncated")

// readName decodes a possibly-compressed name starting at off; returns the
// name and the offset just past it in the original (uncompressed) position.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0
	for {
		if off >= len(msg) {
			return "", 0, errDNSShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if next < 0 {
				next = off
			}
			return strings.Join(labels, "."), next, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errDNSShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > 32 || ptr >= len(msg) {
				return "", 0, errors.New("dns: bad compression pointer")
			}
			off = ptr
		case l&0xc0 != 0:
			return "", 0, errors.New("dns: unsupported label type")
		default:
			off++
			if off+l > len(msg) {
				return "", 0, errDNSShort
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		}
	}
}

func parseMsg(msg []byte) (*dnsMsg, error) {
	if len(msg) < 12 {
		return nil, errDNSShort
	}
	m := &dnsMsg{
		ID:      binary.BigEndian.Uint16(msg[0:]),
		Flags:   binary.BigEndian.Uint16(msg[2:]),
		NSCount: binary.BigEndian.Uint16(msg[8:]),
		ARCount: binary.BigEndian.Uint16(msg[10:]),
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(msg) {
			return nil, errDNSShort
		}
		m.Questions = append(m.Questions, dnsQuestion{name, binary.BigEndian.Uint16(msg[n:]), binary.BigEndian.Uint16(msg[n+2:])})
		off = n + 4
	}
	for i := 0; i < an; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n+10 > len(msg) {
			return nil, errDNSShort
		}
		rr := dnsRR{
			Name:  name,
			Type:  binary.BigEndian.Uint16(msg[n:]),
			Class: binary.BigEndian.Uint16(msg[n+2:]),
			TTL:   binary.BigEndian.Uint32(msg[n+4:]),
		}
		rdlen := int(binary.BigEndian.Uint16(msg[n+8:]))
		start := n + 10
		if start+rdlen > len(msg) {
			return nil, errDNSShort
		}
		rr.Data = msg[start : start+rdlen]
		rr.Value = decodeRData(msg, start, rr)
		m.Answers = append(m.Answers, rr)
		off = start + rdlen
	}
	return m, nil
}

func decodeRData(msg []byte, start int, rr dnsRR) string {
	d := rr.Data
	switch rr.Type {
	case dnsTypeA:
		if len(d) == 4 {
			return net.IP(d).String()
		}
	case dnsTypeAAAA:
		if len(d) == 16 {
			return net.IP(d).String()
		}
	case dnsTypeCNAME, dnsTypeNS:
		if n, _, err := readName(msg, start); err == nil {
			return n
		}
	case dnsTypeTXT:
		var parts []string
		for i := 0; i < len(d); {
			l := int(d[i])
			if i+1+l > len(d) {
				break
			}
			parts = append(parts, string(d[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(parts, "")
	case dnsTypeCAA:
		if len(d) >= 2 {
			tl := int(d[1])
			if 2+tl <= len(d) {
				return fmt.Sprintf("%d %s %q", d[0], d[2:2+tl], d[2+tl:])
			}
		}
	}
	return ""
}

// encodeCAA builds CAA RDATA (used by tests and fixtures).
func encodeCAA(flags byte, tag, value string) []byte {
	b := []byte{flags, byte(len(tag))}
	b = append(b, tag...)
	return append(b, value...)
}

// encodeTXT builds TXT RDATA from one string (split into 255-byte chunks).
func encodeTXT(s string) []byte {
	var b []byte
	for len(s) > 255 {
		b = append(b, 255)
		b = append(b, s[:255]...)
		s = s[255:]
	}
	b = append(b, byte(len(s)))
	return append(b, s...)
}

func dnsExchangeUDP(server string, query []byte, timeout time.Duration) (*dnsMsg, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	m, err := parseMsg(buf[:n])
	if err != nil {
		return nil, err
	}
	if m.ID != binary.BigEndian.Uint16(query) {
		return nil, errors.New("dns: id mismatch")
	}
	return m, nil
}

func dnsExchangeTCP(server string, query []byte, timeout time.Duration) (*dnsMsg, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return parseMsg(resp)
}

// systemNameserver returns the first nameserver from /etc/resolv.conf, or a public fallback.
func systemNameserver() string {
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				return net.JoinHostPort(f[1], "53")
			}
		}
	}
	return "1.1.1.1:53"
}
