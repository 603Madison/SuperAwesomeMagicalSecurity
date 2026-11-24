package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func issueIDs(is []Issue) map[string]string {
	m := map[string]string{}
	for _, i := range is {
		m[i.ID] = i.Severity
	}
	return m
}

func TestEvaluateSPF(t *testing.T) {
	cases := []struct {
		txt  []string
		want map[string]string
	}{
		{nil, map[string]string{"dns_spf_missing": "medium"}},
		{[]string{"google-site-verification=x", "v=spf1 include:_spf.google.com -all"}, map[string]string{}},
		{[]string{"v=spf1 include:x ~all"}, map[string]string{}},
		{[]string{"v=spf1 +all"}, map[string]string{"dns_spf_permissive": "high"}},
		{[]string{"v=spf1 a mx all"}, map[string]string{"dns_spf_permissive": "high"}},
		{[]string{"v=spf1 ?all"}, map[string]string{"dns_spf_permissive": "medium"}},
		{[]string{"v=spf1 mx"}, map[string]string{"dns_spf_permissive": "low"}},
		{[]string{"v=spf1 redirect=_spf.example.com"}, map[string]string{}},
		{[]string{"v=spf1 -all", "v=spf1 mx -all"}, map[string]string{"dns_spf_multiple": "medium"}},
	}
	for _, c := range cases {
		_, issues := EvaluateSPF(c.txt)
		got := issueIDs(issues)
		if len(got) != len(c.want) {
			t.Errorf("%v: got %v want %v", c.txt, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%v: got %v want %v", c.txt, got, c.want)
			}
		}
	}
}

func TestEvaluateDMARC(t *testing.T) {
	_, _, is := EvaluateDMARC(nil)
	if issueIDs(is)["dns_dmarc_missing"] != "medium" {
		t.Error("missing DMARC not flagged")
	}
	_, p, is := EvaluateDMARC([]string{"v=DMARC1; p=none; rua=mailto:d@example.com"})
	if p != "none" || issueIDs(is)["dns_dmarc_none"] != "low" {
		t.Errorf("p=none: %q %v", p, is)
	}
	_, p, is = EvaluateDMARC([]string{"v=DMARC1; p=reject; pct=100"})
	if p != "reject" || len(is) != 0 {
		t.Errorf("p=reject: %q %v", p, is)
	}
	_, _, is = EvaluateDMARC([]string{"v=DMARC1; p=quarantine; pct=25"})
	if issueIDs(is)["dns_dmarc_partial"] == "" {
		t.Errorf("pct not flagged: %v", is)
	}
	_, _, is = EvaluateDMARC([]string{"v=DMARC1; rua=mailto:x@y"})
	if issueIDs(is)["dns_dmarc_invalid"] == "" {
		t.Errorf("invalid not flagged: %v", is)
	}
}

func TestParseSSHBanner(t *testing.T) {
	p, v, proto := ParseSSHBanner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
	if p != "OpenSSH" || v != "8.9p1" || proto != "2.0" {
		t.Fatalf("got %q %q %q", p, v, proto)
	}
	p, v, _ = ParseSSHBanner("SSH-2.0-dropbear_2020.81")
	if p != "dropbear" || v != "2020.81" {
		t.Fatalf("dropbear: %q %q", p, v)
	}
	if !versionLess("7.4p1", 8, 0) || versionLess("8.9p1", 8, 0) || versionLess("garbage", 8, 0) {
		t.Fatal("versionLess")
	}
	is := serviceIssues(Service{Port: 22, Service: "ssh", Product: "OpenSSH", Version: "7.4", Banner: "SSH-2.0-OpenSSH_7.4"})
	if issueIDs(is)["ssh_outdated"] != "medium" || issueIDs(is)["ssh_exposed"] != "info" {
		t.Fatalf("ssh issues: %v", is)
	}
}

// mysqlGreeting builds a protocol-10 handshake packet.
func mysqlGreeting(ver string) []byte {
	payload := append([]byte{0x0a}, ver...)
	payload = append(payload, 0)
	payload = append(payload, 1, 0, 0, 0) // thread id
	payload = append(payload, []byte("abcdefgh")...)
	payload = append(payload, 0, 0xff, 0xf7)
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0}
	return append(hdr, payload...)
}

func TestParseMySQLHandshake(t *testing.T) {
	p, v, _, ok := ParseMySQLHandshake(mysqlGreeting("8.0.36-0ubuntu0.22.04.1"))
	if !ok || p != "MySQL" || v != "8.0.36-0ubuntu0.22.04.1" {
		t.Fatalf("mysql: %v %q %q", ok, p, v)
	}
	p, v, _, ok = ParseMySQLHandshake(mysqlGreeting("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1"))
	if !ok || p != "MariaDB" || v != "10.6.12" {
		t.Fatalf("mariadb: %v %q %q", ok, p, v)
	}
	msg := "Host '1.2.3.4' is not allowed to connect to this MySQL server"
	errPkt := append([]byte{0xff, 0x6a, 0x04}, msg...)
	pkt := append([]byte{byte(len(errPkt)), 0, 0, 0}, errPkt...)
	p, _, m, ok := ParseMySQLHandshake(pkt)
	if !ok || p != "MySQL" || m != msg {
		t.Fatalf("error packet: %v %q %q", ok, p, m)
	}
	if _, _, _, ok := ParseMySQLHandshake([]byte("SSH-2.0-x")); ok {
		t.Fatal("ssh parsed as mysql")
	}
	var svc Service
	if !classifyGreeting(3306, mysqlGreeting("8.0.36"), &svc) || svc.Service != "mysql" {
		t.Fatalf("classify: %+v", svc)
	}
}

func TestClassifyGreetings(t *testing.T) {
	cases := []struct {
		port             int
		data             string
		service, product string
	}{
		{21, "220 (vsFTPd 3.0.3)\r\n", "ftp", "vsFTPd"},
		{25, "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "smtp", "Postfix"},
		{110, "+OK Dovecot ready.\r\n", "pop3", "Dovecot"},
		{143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", "imap", "Dovecot"},
		{5900, "RFB 003.008\n", "vnc", "VNC"},
		{23, "\xff\xfd\x18\xff\xfd\x20login: ", "telnet", "Telnet"},
	}
	for _, c := range cases {
		var svc Service
		if !classifyGreeting(c.port, []byte(c.data), &svc) || svc.Service != c.service || svc.Product != c.product {
			t.Errorf("%d %q -> %+v", c.port, c.data, svc)
		}
	}
	var r Service
	if !classifyRedis([]byte("+PONG\r\n"), &r) || !r.unauthenticated {
		t.Error("redis +PONG")
	}
	is := serviceIssues(Service{Port: 6379, Service: "redis", unauthenticated: true})
	if issueIDs(is)["redis_unauthenticated"] != "critical" {
		t.Errorf("redis issues %v", is)
	}
}

func TestSNMPEncoding(t *testing.T) {
	pkt, err := BuildSNMPGet("public", 0x5a4d, "1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	// Known-good encoding of an SNMPv2c GetRequest for sysDescr.0, request-id 0x5a4d.
	want := []byte{0x30, 0x27, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x1a, 0x02, 0x02, 0x5a, 0x4d, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00}
	if !bytes.Equal(pkt, want) {
		t.Fatalf("snmp get:\n got % x\nwant % x", pkt, want)
	}
	// multi-byte OID arcs and long lengths
	o, _ := berOID("1.3.6.1.4.1.311.21")
	if !bytes.Equal(o, []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15}) {
		t.Fatalf("oid % x", o)
	}
	if !bytes.Equal(berLen(300), []byte{0x82, 0x01, 0x2c}) {
		t.Fatalf("berLen % x", berLen(300))
	}
	// Build a GetResponse by rewriting the PDU tag and value, then parse it.
	descr := "Linux edge 5.15.0 #1 SMP x86_64"
	o2, _ := berOID("1.3.6.1.2.1.1.1.0")
	vb := berTLV(0x30, berTLV(0x30, append(o2, berTLV(0x04, []byte(descr))...)))
	pdu := berTLV(0xa2, append(append(append(berInt(0x5a4d), berInt(0)...), berInt(0)...), vb...))
	resp := berTLV(0x30, append(append(berInt(1), berTLV(0x04, []byte("public"))...), pdu...))
	got, ok := ParseSNMPResponse(resp)
	if !ok || got != descr {
		t.Fatalf("parse response: %v %q", ok, got)
	}
	if _, ok := ParseSNMPResponse(pkt); ok {
		t.Fatal("GetRequest parsed as response")
	}
}

func TestDNSRoundTrip(t *testing.T) {
	q, err := buildQuery(0x1234, "example.com", dnsTypeCAA, true)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseMsg(q)
	if err != nil || m.ID != 0x1234 || m.Flags&dnsFlagRD == 0 || len(m.Questions) != 1 ||
		m.Questions[0].Name != "example.com" || m.Questions[0].Type != dnsTypeCAA {
		t.Fatalf("query round trip: %+v %v", m, err)
	}
	resp := dnsMsg{ID: 7, Flags: dnsFlagQR | dnsFlagRA, Questions: []dnsQuestion{{"example.com", dnsTypeTXT, dnsClassIN}},
		Answers: []dnsRR{
			{Name: "example.com", Type: dnsTypeTXT, Class: dnsClassIN, TTL: 60, Data: encodeTXT("v=spf1 -all")},
			{Name: "example.com", Type: dnsTypeA, Class: dnsClassIN, TTL: 60, Data: []byte{93, 184, 216, 34}},
			{Name: "example.com", Type: dnsTypeCAA, Class: dnsClassIN, TTL: 60, Data: encodeCAA(0, "issue", "letsencrypt.org")},
		}}
	b, err := resp.pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err = parseMsg(b)
	if err != nil || len(m.Answers) != 3 {
		t.Fatalf("parse: %v %+v", err, m)
	}
	if m.Answers[0].Value != "v=spf1 -all" || m.Answers[1].Value != "93.184.216.34" || m.Answers[2].Value != `0 issue "letsencrypt.org"` {
		t.Fatalf("values: %q %q %q", m.Answers[0].Value, m.Answers[1].Value, m.Answers[2].Value)
	}
	// compression pointer: name at offset 12 ("example.com"), answer name = pointer 0xc00c
	comp := append([]byte{}, b[:12+13+4]...) // header + question
	binary.BigEndian.PutUint16(comp[6:], 1)  // ancount=1
	comp = append(comp, 0xc0, 0x0c)
	comp = binary.BigEndian.AppendUint16(comp, dnsTypeCNAME)
	comp = binary.BigEndian.AppendUint16(comp, dnsClassIN)
	comp = binary.BigEndian.AppendUint32(comp, 30)
	target := []byte{3, 'w', 'w', 'w', 0xc0, 0x0c}
	comp = binary.BigEndian.AppendUint16(comp, uint16(len(target)))
	comp = append(comp, target...)
	m, err = parseMsg(comp)
	if err != nil || m.Answers[0].Name != "example.com" || m.Answers[0].Value != "www.example.com" {
		t.Fatalf("compressed: %v %+v", err, m)
	}
	// pointer loop must not hang
	loop := append([]byte{}, comp[:12]...)
	binary.BigEndian.PutUint16(loop[4:], 1)
	binary.BigEndian.PutUint16(loop[6:], 0)
	loop = append(loop, 0xc0, 0x0c, 0, 1, 0, 1)
	if _, err := parseMsg(loop); err == nil {
		t.Fatal("pointer loop accepted")
	}
	if _, err := parseMsg(b[:20]); err == nil {
		t.Fatal("truncated accepted")
	}
}

// fakeDNSServer answers every TCP query (AXFR) with the given answers.
func fakeAXFRServer(t *testing.T, answers []dnsRR) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				qm, err := parseMsg(q)
				if err != nil {
					return
				}
				resp := dnsMsg{ID: qm.ID, Flags: dnsFlagQR | dnsFlagAA, Questions: qm.Questions, Answers: answers}
				if len(answers) == 0 {
					resp.Flags |= 5 // REFUSED
				}
				b, _ := resp.pack()
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestAXFR(t *testing.T) {
	open := fakeAXFRServer(t, []dnsRR{{Name: "example.com", Type: dnsTypeA, Class: dnsClassIN, TTL: 1, Data: []byte{1, 2, 3, 4}}})
	ok, err := checkAXFR(open, "example.com", 2*time.Second)
	if err != nil || !ok {
		t.Fatalf("open server: %v %v", ok, err)
	}
	closed := fakeAXFRServer(t, nil)
	ok, err = checkAXFR(closed, "example.com", 2*time.Second)
	if err != nil || ok {
		t.Fatalf("refusing server: %v %v", ok, err)
	}
}

func TestOpenResolverCheck(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			qm, err := parseMsg(buf[:n])
			if err != nil {
				continue
			}
			resp := dnsMsg{ID: qm.ID, Flags: dnsFlagQR | dnsFlagRD | dnsFlagRA, Questions: qm.Questions,
				Answers: []dnsRR{{Name: "example.com", Type: dnsTypeA, Class: dnsClassIN, TTL: 1, Data: []byte{93, 184, 216, 34}}}}
			b, _ := resp.pack()
			pc.WriteTo(b, addr)
		}
	}()
	responded, recursive := checkOpenResolver(pc.LocalAddr().String(), 2*time.Second)
	if !responded || !recursive {
		t.Fatalf("got %v %v", responded, recursive)
	}
}

func TestFingerprintHTTP(t *testing.T) {
	cases := []struct {
		title, body string
		headers     map[string]string
		name, class string
	}{
		{"pfSense - Login", `<form><input type="password" name="passwordfld"></form>`, nil, "pfSense", "admin"},
		{"UniFi OS", `<div id="root"></div>`, nil, "UniFi OS", "admin"},
		{"", `<html><script src="/pve2/js/pvemanagerlib.js"></script>Proxmox Virtual Environment</html>`, nil, "Proxmox VE", "admin"},
		{"Sign in", `<input type=password>`, map[string]string{"X-Jenkins": "2.440"}, "Jenkins", "admin"},
		{"Grafana", "", nil, "Grafana", "app"},
		{"", `<a href="/+CSCOE+/logon.html">`, nil, "Cisco ASA / AnyConnect", "vpn"},
		{"Welcome", "", map[string]string{"WWW-Authenticate": `Basic realm="NETGEAR R7000"`}, "Router login", "router"},
		{"My blog", "<p>hello</p>", nil, "", ""},
	}
	for _, c := range cases {
		h := http.Header{}
		for k, v := range c.headers {
			h.Set(k, v)
		}
		name, class := FingerprintHTTP(c.title, c.body, h)
		if name != c.name || class != c.class {
			t.Errorf("%q: got %q/%q want %q/%q", c.title, name, class, c.name, c.class)
		}
	}
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	missing := MissingSecurityHeaders(h, true)
	if strings.Join(missing, ",") != "Strict-Transport-Security,Content-Security-Policy,X-Content-Type-Options,Referrer-Policy" {
		t.Errorf("missing: %v", missing)
	}
	if extractTitle("<html><TITLE>\n  Index of /backup </TITLE>") != "Index of /backup" {
		t.Error("title")
	}
}

// TestEndToEnd scans a local TLS web server (pfSense-like login, self-signed)
// and a local SSH-like banner service via the real scanner.
func TestEndToEnd(t *testing.T) {
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		io.WriteString(w, `<html><head><title>pfSense - Login</title></head><body><form><input type="password"></form></body></html>`)
	}))
	web.Config.ErrorLog = log.New(io.Discard, "", 0) // handshake probes are expected to fail noisily
	web.StartTLS()
	defer web.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_7.4\r\n"))
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	webPort := web.Listener.Addr().(*net.TCPAddr).Port
	sshPort := ln.Addr().(*net.TCPAddr).Port
	// a closed port to exercise the refused path
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := Run(ctx, []string{"127.0.0.1"}, Options{
		Ports: []int{webPort, sshPort, closedPort}, Checks: []string{"tcp", "banner", "tls", "http"},
		RatePerSec: 500, AllowPrivate: true, GreetingTimeout: 500 * time.Millisecond,
	})
	if len(res.Targets) != 1 {
		t.Fatalf("targets: %+v", res.Targets)
	}
	tr := res.Targets[0]
	if !tr.Reachable || len(tr.Services) != 2 {
		t.Fatalf("services: %+v", tr)
	}
	byPort := map[int]Service{}
	for _, s := range tr.Services {
		byPort[s.Port] = s
	}
	ssh := byPort[sshPort]
	if ssh.Service != "ssh" || ssh.Product != "OpenSSH" || ssh.Version != "7.4" {
		t.Errorf("ssh: %+v", ssh)
	}
	w := byPort[webPort]
	if w.Service != "https" || w.TLS == nil || w.HTTP == nil {
		t.Fatalf("web: %+v", w)
	}
	if w.HTTP["login_page"] != "pfSense" || w.HTTP["status"] != 200 || w.TLS["self_signed"] != true {
		// httptest's built-in certificate is self-signed ("Acme Co")
		t.Errorf("web details: http=%v tls=%v", w.HTTP, w.TLS)
	}
	if w.TLS["trusted"] != false {
		t.Errorf("httptest cert should be untrusted: %v", w.TLS)
	}
	ids := issueIDs(tr.Issues)
	for _, want := range []string{"admin_panel_exposed", "ssh_outdated", "http_missing_hsts", "tls_cert_self_signed", "tls_weak_cipher"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing issue %s; have %v", want, ids)
		}
	}
	// JSON must match the server contract (lists never null).
	b, _ := json.Marshal(res)
	var generic map[string]any
	_ = json.Unmarshal(b, &generic)
	tgt := generic["targets"].([]any)[0].(map[string]any)
	for _, k := range []string{"target", "resolved", "reachable", "services", "dns", "issues"} {
		if tgt[k] == nil {
			t.Errorf("field %s is null/missing in %s", k, b)
		}
	}
	if !strings.Contains(string(b), `"probe_public_ip"`) || !strings.Contains(string(b), `"port":`+strconv.Itoa(webPort)) {
		t.Errorf("json: %s", b)
	}
}

func TestRefusedTargetsReported(t *testing.T) {
	res := Run(context.Background(), []string{"10.0.0.1"}, Options{Ports: []int{22}})
	if len(res.Targets) != 1 || res.Targets[0].Issues[0].ID != "scope_refused" || res.Targets[0].Reachable {
		t.Fatalf("%+v", res.Targets)
	}
}
