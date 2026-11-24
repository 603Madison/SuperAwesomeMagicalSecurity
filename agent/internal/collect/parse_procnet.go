package collect

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

// ProcNetEntry is one socket from /proc/net/{tcp,tcp6,udp,udp6}.
type ProcNetEntry struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string // LISTEN, ESTABLISHED, ...
	UID        int
	Inode      uint64
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// parseHexAddr decodes "0100007F:0016" (IPv4) or a 32-hex-char IPv6 address.
// The kernel prints each 32-bit word in host (little-endian) byte order.
func parseHexAddr(s string) (string, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, errors.New("bad addr")
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, err
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, errors.New("bad ip")
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 {
		// IPv4-mapped IPv6 (::ffff:a.b.c.d) -> show as IPv4
		return v4.String(), int(p), nil
	}
	return ip.String(), int(p), nil
}

// ParseProcNet parses a /proc/net/tcp-style table. udp=true maps the UDP
// "unconnected" state (07) to LISTEN.
func ParseProcNet(r io.Reader, udp bool) []ProcNetEntry {
	var out []ProcNetEntry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, err := parseHexAddr(f[1])
		if err != nil {
			continue
		}
		rip, rport, err := parseHexAddr(f[2])
		if err != nil {
			continue
		}
		state := tcpStates[strings.ToUpper(f[3])]
		if udp {
			if f[3] == "07" {
				state = "LISTEN"
			} else if f[3] == "01" {
				state = "ESTABLISHED"
			}
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, ProcNetEntry{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport,
			State: state, UID: uid, Inode: inode})
	}
	return out
}

// IsLoopback reports whether ip is a loopback address.
func IsLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}
