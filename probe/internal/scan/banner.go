package scan

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// portNames maps well-known ports to service names when nothing better is known.
var portNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 500: "ike", 514: "rsh", 587: "submission", 623: "ipmi", 636: "ldaps", 873: "rsync",
	993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
	1900: "upnp", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd",
	3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http", 5432: "postgresql", 5601: "kibana",
	5672: "amqp", 5900: "vnc", 5901: "vnc", 5902: "vnc", 5903: "vnc", 5984: "couchdb", 5985: "winrm",
	5986: "winrm-https", 6379: "redis", 6443: "kubernetes-api", 8006: "https", 8080: "http",
	8081: "http", 8086: "influxdb", 8123: "http", 8443: "https", 8834: "https", 8888: "http",
	9000: "http", 9090: "http", 9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch",
	9443: "https", 10000: "http", 10250: "kubelet", 10255: "kubelet", 10443: "https",
	11211: "memcached", 15672: "http", 27017: "mongodb", 27018: "mongodb", 32400: "http",
}

var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 853: true, 989: true, 990: true, 992: true,
	993: true, 994: true, 995: true, 2376: true, 5986: true, 6443: true, 8006: true, 8443: true,
	8834: true, 9443: true, 10250: true, 10443: true}

var httpPorts = map[int]bool{80: true, 81: true, 443: true, 591: true, 3000: true, 5000: true, 5001: true,
	5601: true, 8000: true, 8006: true, 8008: true, 8080: true, 8081: true, 8088: true, 8123: true,
	8443: true, 8834: true, 8880: true, 8888: true, 9000: true, 9090: true, 9200: true, 9443: true,
	10000: true, 10443: true, 15672: true, 2375: true, 2379: true, 32400: true}

// sanitize keeps printable characters and truncates to 256 chars.
func sanitize(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if r == '\r' {
			continue
		}
		if r == '\n' || r == '\t' {
			sb.WriteRune(' ')
			continue
		}
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}
	s := strings.Join(strings.Fields(sb.String()), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// ParseSSHBanner parses "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" -> ("OpenSSH", "8.9p1", "2.0").
func ParseSSHBanner(banner string) (product, version, proto string) {
	line := strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])
	if !strings.HasPrefix(line, "SSH-") {
		return "", "", ""
	}
	parts := strings.SplitN(line, "-", 3)
	if len(parts) < 3 {
		return "", "", ""
	}
	proto = parts[1]
	sw := strings.Fields(parts[2])
	if len(sw) == 0 {
		return "", "", proto
	}
	if p, v, ok := strings.Cut(sw[0], "_"); ok {
		return p, v, proto
	}
	return sw[0], "", proto
}

var leadingVersion = regexp.MustCompile(`^(\d+)\.(\d+)`)

// versionLess reports whether version v is older than major.minor (false if unparsable).
func versionLess(v string, major, minor int) bool {
	m := leadingVersion.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	return a < major || (a == major && b < minor)
}

// ParseMySQLHandshake parses a MySQL/MariaDB server greeting packet.
// Returns product, version, and (for error packets) the server message.
func ParseMySQLHandshake(pkt []byte) (product, version, message string, ok bool) {
	if len(pkt) < 5 {
		return "", "", "", false
	}
	plen := int(pkt[0]) | int(pkt[1])<<8 | int(pkt[2])<<16
	if plen < 1 || plen > 1<<16 || pkt[3] != 0 {
		return "", "", "", false
	}
	payload := pkt[4:]
	if len(payload) > plen {
		payload = payload[:plen]
	}
	switch payload[0] {
	case 0x0a: // protocol v10 handshake
		end := bytes.IndexByte(payload[1:], 0)
		if end < 0 {
			return "", "", "", false
		}
		ver := string(payload[1 : 1+end])
		product = "MySQL"
		if strings.Contains(strings.ToLower(ver), "mariadb") {
			product = "MariaDB"
			// "5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1" -> 10.6.12
			ver = strings.TrimPrefix(ver, "5.5.5-")
			if i := strings.Index(strings.ToLower(ver), "-mariadb"); i > 0 {
				ver = ver[:i]
			}
		}
		return product, ver, "", true
	case 0xff: // error packet: 0xff, code(2), [#sqlstate], message
		if len(payload) < 3 {
			return "MySQL", "", "", true
		}
		msg := payload[3:]
		if len(msg) > 0 && msg[0] == '#' && len(msg) >= 6 {
			msg = msg[6:]
		}
		return "MySQL", "", sanitize(msg), true
	}
	return "", "", "", false
}

var (
	reFTPProduct  = regexp.MustCompile(`(?i)\(?(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service|wu-ftpd)[ /]?([\d.a-z]*)`)
	reSMTPProduct = regexp.MustCompile(`(?i)(Postfix|Exim|Sendmail|Microsoft ESMTP MAIL Service|Exchange|OpenSMTPD|qmail|Haraka)[ /]?([\d.]*)`)
	reIMAPProduct = regexp.MustCompile(`(?i)(Dovecot|Courier|Cyrus|Zimbra|Exchange)`)
)

// classifyGreeting identifies a service from data the server sent unprompted.
func classifyGreeting(port int, data []byte, svc *Service) bool {
	if len(data) == 0 {
		return false
	}
	text := string(data)
	switch {
	case strings.HasPrefix(text, "SSH-"):
		svc.Service = "ssh"
		svc.Product, svc.Version, _ = ParseSSHBanner(text)
		svc.Banner = sanitize([]byte(strings.SplitN(text, "\n", 2)[0]))
		return true
	case strings.HasPrefix(text, "RFB "):
		svc.Service, svc.Product = "vnc", "VNC"
		svc.Version = strings.TrimSpace(strings.TrimPrefix(sanitize(data), "RFB "))
		svc.Banner = sanitize(data)
		return true
	case data[0] == 0xff && len(data) >= 3 && data[1] >= 0xfb && data[1] <= 0xfe:
		svc.Service, svc.Product = "telnet", "Telnet"
		svc.Banner = sanitize(data[3:])
		return true
	case strings.HasPrefix(text, "+OK"):
		svc.Service = "pop3"
		svc.Banner = sanitize(data)
		if m := reIMAPProduct.FindStringSubmatch(text); m != nil {
			svc.Product = m[1]
		}
		return true
	case strings.HasPrefix(text, "* OK") || strings.HasPrefix(text, "* PREAUTH"):
		svc.Service = "imap"
		svc.Banner = sanitize(data)
		if m := reIMAPProduct.FindStringSubmatch(text); m != nil {
			svc.Product = m[1]
		}
		return true
	case strings.HasPrefix(text, "220"):
		svc.Banner = sanitize(data)
		up := strings.ToUpper(text)
		if port == 21 || strings.Contains(up, "FTP") {
			svc.Service = "ftp"
			if m := reFTPProduct.FindStringSubmatch(text); m != nil {
				svc.Product, svc.Version = m[1], m[2]
			}
		} else {
			svc.Service = "smtp"
			if m := reSMTPProduct.FindStringSubmatch(text); m != nil {
				svc.Product, svc.Version = m[1], m[2]
			}
		}
		return true
	}
	if p, v, msg, ok := ParseMySQLHandshake(data); ok {
		svc.Service, svc.Product, svc.Version = "mysql", p, v
		svc.Banner = msg
		if msg == "" {
			svc.Banner = p + " " + v
		}
		return true
	}
	if port == 23 {
		svc.Service, svc.Product = "telnet", "Telnet"
		svc.Banner = sanitize(data)
		return true
	}
	svc.Banner = sanitize(data)
	return false
}

// rdpConnectionRequest is an X.224 Connection Request with an RDP negotiation request (TLS|CredSSP).
var rdpConnectionRequest = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}

// postgresSSLRequest asks a PostgreSQL server whether it supports TLS.
var postgresSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

type activeProbe struct {
	send     []byte
	classify func(resp []byte, svc *Service) bool
}

func activeProbeFor(port int, host string) activeProbe {
	switch port {
	case 6379, 6380:
		return activeProbe{[]byte("PING\r\n"), classifyRedis}
	case 11211:
		return activeProbe{[]byte("version\r\n"), func(r []byte, s *Service) bool {
			if t := string(r); strings.HasPrefix(t, "VERSION ") {
				s.Service, s.Product = "memcached", "Memcached"
				s.Version = strings.TrimSpace(strings.TrimPrefix(sanitize(r), "VERSION "))
				s.Banner = sanitize(r)
				s.unauthenticated = true
				return true
			}
			return false
		}}
	case 3389:
		return activeProbe{rdpConnectionRequest, func(r []byte, s *Service) bool {
			// TPKT header v3 + X.224 Connection Confirm (0xd0)
			if len(r) >= 6 && r[0] == 0x03 && r[1] == 0x00 && r[5]&0xf0 == 0xd0 {
				s.Service, s.Product = "rdp", "Microsoft Terminal Services"
				return true
			}
			return false
		}}
	case 5432:
		return activeProbe{postgresSSLRequest, func(r []byte, s *Service) bool {
			if len(r) >= 1 && (r[0] == 'S' || r[0] == 'N') {
				s.Service, s.Product = "postgresql", "PostgreSQL"
				s.Banner = map[byte]string{'S': "TLS supported", 'N': "TLS not supported"}[r[0]]
				return true
			}
			return false
		}}
	}
	// default: plaintext HTTP request; many unknown services are web servers
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: sams-probe\r\nConnection: close\r\n\r\n"
	return activeProbe{[]byte(req), func(r []byte, s *Service) bool {
		if strings.HasPrefix(string(r), "HTTP/") {
			s.Service = "http"
			for _, line := range strings.Split(string(r), "\n") {
				if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "server") {
					s.Product = strings.TrimSpace(v)
					s.Banner = sanitize([]byte("Server: " + s.Product))
				}
			}
			return true
		}
		if strings.HasPrefix(string(r), "-ERR") || strings.HasPrefix(string(r), "-NOAUTH") {
			return classifyRedis(r, s)
		}
		if len(r) > 0 {
			s.Banner = sanitize(r)
		}
		return false
	}}
}

func classifyRedis(r []byte, s *Service) bool {
	t := string(r)
	switch {
	case strings.HasPrefix(t, "+PONG"):
		s.Service, s.Product = "redis", "Redis"
		s.Banner = "PING answered without authentication"
		s.unauthenticated = true
		return true
	case strings.HasPrefix(t, "-NOAUTH"), strings.HasPrefix(t, "-ERR") && strings.Contains(strings.ToLower(t), "auth"):
		s.Service, s.Product = "redis", "Redis"
		s.Banner = sanitize(r)
		return true
	case strings.HasPrefix(t, "-DENIED"):
		s.Service, s.Product = "redis", "Redis"
		s.Banner = sanitize(r)
		return true
	}
	return false
}

// grabBanner connects, waits briefly for a greeting, and if none arrives sends
// a harmless protocol-appropriate probe. It never authenticates.
func (s *Scanner) grabBanner(ip string, host string, port int, svc *Service) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, s.opts.ConnectTimeout)
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(s.opts.GreetingTimeout))
	n, _ := conn.Read(buf)
	if n > 0 {
		if classifyGreeting(port, buf[:n], svc) {
			return
		}
		// e.g. MySQL greetings can arrive split; nothing more to do
		if svc.Banner != "" {
			return
		}
	}
	if tlsPorts[port] {
		return // a TLS port is handled by the TLS check
	}
	ap := activeProbeFor(port, host)
	_ = conn.SetDeadline(time.Now().Add(s.opts.IOTimeout))
	if _, err := conn.Write(ap.send); err != nil {
		return
	}
	n, _ = conn.Read(buf)
	if n > 0 {
		ap.classify(buf[:n], svc)
	}
}
