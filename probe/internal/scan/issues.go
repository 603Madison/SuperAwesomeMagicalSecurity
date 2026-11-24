package scan

import "strconv"

type exposureRule struct {
	id, severity, title, detail string
}

// exposureRules flag services that should essentially never face the internet.
var exposureRules = map[string]exposureRule{
	"telnet":         {"telnet_exposed", "high", "Telnet exposed", "Telnet sends credentials in cleartext and is a favourite of IoT botnets. Disable it; use SSH over a VPN."},
	"ftp":            {"ftp_exposed", "medium", "FTP exposed", "FTP sends credentials in cleartext. Replace with SFTP, or restrict to known sources."},
	"smb":            {"smb_exposed", "critical", "SMB (445) exposed", "SMB on the internet enables ransomware worms (EternalBlue, SMBGhost) and credential relay. Block 445 at the edge."},
	"netbios-ssn":    {"smb_exposed", "high", "NetBIOS/SMB (139) exposed", "Block NetBIOS/SMB at the edge."},
	"msrpc":          {"msrpc_exposed", "high", "Microsoft RPC (135) exposed", "RPC endpoint mapper leaks host information and has a history of wormable bugs. Block at the edge."},
	"rdp":            {"rdp_exposed", "high", "RDP exposed", "Internet-facing RDP is the #1 ransomware entry point (brute force, BlueKeep-class bugs). Put it behind a VPN or RD Gateway with MFA."},
	"vnc":            {"vnc_exposed", "high", "VNC exposed", "VNC often has weak or no authentication. Tunnel it over SSH/VPN."},
	"winrm":          {"winrm_exposed", "high", "WinRM exposed", "Remote PowerShell from the internet invites credential attacks. Restrict to management networks."},
	"winrm-https":    {"winrm_exposed", "high", "WinRM (HTTPS) exposed", "Remote PowerShell from the internet invites credential attacks. Restrict to management networks."},
	"memcached":      {"memcached_exposed", "high", "Memcached exposed", "Unauthenticated cache access and a massive UDP amplification vector. Bind to localhost/internal only."},
	"mongodb":        {"mongodb_exposed", "high", "MongoDB exposed", "Internet-facing MongoDB instances are routinely wiped and ransomed. Bind internally and enable auth."},
	"elasticsearch":  {"elasticsearch_exposed", "high", "Elasticsearch exposed", "Exposed clusters leak entire datasets. Bind internally and enable security features."},
	"couchdb":        {"database_exposed", "high", "CouchDB exposed", "Databases should not be reachable from the internet."},
	"influxdb":       {"database_exposed", "medium", "InfluxDB exposed", "Databases should not be reachable from the internet."},
	"mysql":          {"database_exposed", "high", "MySQL/MariaDB exposed", "Databases should not be reachable from the internet; brute force and auth-bypass bugs follow. Restrict to app servers/VPN."},
	"postgresql":     {"database_exposed", "high", "PostgreSQL exposed", "Databases should not be reachable from the internet. Restrict pg_hba.conf and the firewall to app servers/VPN."},
	"mssql":          {"database_exposed", "high", "Microsoft SQL Server exposed", "Databases should not be reachable from the internet."},
	"oracle":         {"database_exposed", "high", "Oracle TNS listener exposed", "Databases should not be reachable from the internet."},
	"redis":          {"redis_exposed", "high", "Redis exposed", "Redis is designed for trusted networks. Bind internally, require AUTH/ACLs, use protected-mode."},
	"docker":         {"docker_api_exposed", "critical", "Docker Engine API exposed", "Port 2375 gives root on the host to anyone. Disable the TCP socket or use mutual-TLS on 2376 behind a firewall."},
	"docker-tls":     {"docker_api_exposed", "high", "Docker Engine API (TLS) exposed", "Even with TLS, the Docker API should not face the internet."},
	"etcd":           {"etcd_exposed", "critical", "etcd exposed", "etcd holds cluster secrets (Kubernetes secrets in plaintext). Restrict to control-plane nodes with mTLS."},
	"kubelet":        {"kubelet_exposed", "high", "Kubelet API exposed", "The kubelet API can allow exec into pods if anonymous auth is enabled. Firewall 10250/10255."},
	"kubernetes-api": {"kubernetes_api_exposed", "medium", "Kubernetes API server exposed", "Restrict the API server to admin networks/VPN and keep anonymous auth disabled."},
	"rpcbind":        {"rpc_nfs_exposed", "high", "RPC portmapper exposed", "rpcbind reveals NFS/RPC services and is used for amplification. Block at the edge."},
	"nfs":            {"rpc_nfs_exposed", "high", "NFS exposed", "NFS exports reachable from the internet can leak or allow modification of files."},
	"ipmi":           {"ipmi_exposed", "high", "IPMI/BMC exposed", "Out-of-band management (iDRAC/iLO/IPMI) has severe auth weaknesses. Never expose it."},
	"pptp":           {"pptp_exposed", "medium", "PPTP VPN exposed", "PPTP/MS-CHAPv2 is cryptographically broken. Migrate to WireGuard/IPsec/OpenVPN."},
	"mqtt":           {"mqtt_exposed", "medium", "MQTT broker exposed", "IoT brokers often allow anonymous publish/subscribe. Require auth and TLS (8883)."},
	"jetdirect":      {"printer_exposed", "medium", "Printer (JetDirect 9100) exposed", "Printers on the internet get abused for spam prints and as a pivot."},
	"amqp":           {"amqp_exposed", "medium", "AMQP broker exposed", "Message brokers should not face the internet."},
	"rsync":          {"rsync_exposed", "medium", "rsync daemon exposed", "rsync modules may be readable without auth."},
	"ldap":           {"ldap_exposed", "high", "LDAP exposed", "Directory services leak users/groups and enable password spraying. Restrict to internal networks."},
	"ssh":            {"ssh_exposed", "info", "SSH reachable from the internet", "Fine if intended: use key-only auth, disable root login, and consider fail2ban or a VPN."},
}

// serviceIssues derives exposure issues for one discovered service.
func serviceIssues(svc Service) []Issue {
	var out []Issue
	if r, ok := exposureRules[svc.Service]; ok {
		sev, title := r.severity, r.title
		if svc.unauthenticated {
			sev = "critical"
			title += " without authentication"
		}
		id := r.id
		if svc.Service == "redis" && svc.unauthenticated {
			id = "redis_unauthenticated"
		}
		out = append(out, Issue{ID: id, Severity: sev, Port: svc.Port, Title: title + " (port " + strconv.Itoa(svc.Port) + ")", Detail: r.detail})
	}
	if svc.Service == "ssh" {
		_, _, proto := ParseSSHBanner(svc.Banner)
		if proto == "1.5" || proto == "1.0" {
			out = append(out, Issue{ID: "ssh_protocol_v1", Severity: "high", Port: svc.Port,
				Title: "SSH protocol 1 offered", Detail: "SSH-1 is cryptographically broken. Disable it."})
		}
		if svc.Product == "OpenSSH" && versionLess(svc.Version, 8, 0) {
			out = append(out, Issue{ID: "ssh_outdated", Severity: "medium", Port: svc.Port,
				Title:  "Outdated OpenSSH " + svc.Version,
				Detail: "OpenSSH older than 8.0 is affected by multiple published vulnerabilities (e.g. user enumeration, scp issues). Update the OS packages (distro backports may already be patched; verify with the host agent)."})
		}
	}
	return out
}
