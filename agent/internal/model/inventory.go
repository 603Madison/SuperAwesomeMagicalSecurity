// Package model mirrors the server's pydantic Inventory contract
// (server/sams/models.py). JSON field names are the wire format.
//
// Slices and maps use omitempty: the server fills defaults for missing
// fields, but rejects explicit nulls for list fields.
package model

import "time"

type OSInfo struct {
	Family    string   `json:"family"`
	ID        string   `json:"id,omitempty"`
	IDLike    []string `json:"id_like,omitempty"`
	Name      string   `json:"name,omitempty"`
	Version   string   `json:"version,omitempty"`
	VersionID string   `json:"version_id,omitempty"`
	Codename  string   `json:"codename,omitempty"`
	Pretty    string   `json:"pretty,omitempty"`
}

type HostInfo struct {
	Hostname       string `json:"hostname"`
	FQDN           string `json:"fqdn,omitempty"`
	MachineID      string `json:"machine_id,omitempty"`
	OS             OSInfo `json:"os"`
	Kernel         string `json:"kernel,omitempty"`
	Arch           string `json:"arch,omitempty"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	Virtualization string `json:"virtualization,omitempty"`
	IsContainer    bool   `json:"is_container"`
	Domain         string `json:"domain,omitempty"`
}

type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Up        bool     `json:"up"`
}

type Listener struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Process string `json:"process,omitempty"`
	User    string `json:"user,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Package string `json:"package,omitempty"`
}

type Connection struct {
	Proto         string `json:"proto"`
	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	State         string `json:"state"`
	Process       string `json:"process,omitempty"`
	User          string `json:"user,omitempty"`
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Manager       string `json:"manager"`
	Arch          string `json:"arch,omitempty"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	Location      string `json:"location,omitempty"`
}

type User struct {
	Name          string   `json:"name"`
	UID           int      `json:"uid"`
	GID           int      `json:"gid"`
	Home          string   `json:"home,omitempty"`
	Shell         string   `json:"shell,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	LoginEnabled  bool     `json:"login_enabled"`
	PasswordState string   `json:"password_state"`
	IsAdmin       bool     `json:"is_admin"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
}

type SudoRule struct {
	Principal string   `json:"principal"`
	RunAs     string   `json:"runas"`
	Commands  []string `json:"commands,omitempty"`
	NoPasswd  bool     `json:"nopasswd"`
	Source    string   `json:"source,omitempty"`
}

type AuthorizedKey struct {
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
	File        string `json:"file,omitempty"`
}

type Credential struct {
	Kind        string         `json:"kind"`
	Owner       string         `json:"owner,omitempty"`
	Path        string         `json:"path,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Encrypted   *bool          `json:"encrypted,omitempty"`
	Identifier  string         `json:"identifier,omitempty"`
	Targets     []string       `json:"targets,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type KnownHost struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Hashed  bool   `json:"hashed"`
	KeyType string `json:"key_type,omitempty"`
}

type Datastore struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name,omitempty"`
	Path        string         `json:"path,omitempty"`
	Port        int            `json:"port"`
	Owner       string         `json:"owner,omitempty"`
	Sensitivity string         `json:"sensitivity,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type SSHDConfig struct {
	Present                bool     `json:"present"`
	Port                   int      `json:"port"`
	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	PubkeyAuthentication   string   `json:"pubkey_authentication,omitempty"`
	PermitEmptyPasswords   string   `json:"permit_empty_passwords,omitempty"`
	X11Forwarding          string   `json:"x11_forwarding,omitempty"`
	MaxAuthTries           int      `json:"max_auth_tries"`
	AllowUsers             []string `json:"allow_users,omitempty"`
}

type HostFirewall struct {
	Enabled        *bool  `json:"enabled,omitempty"`
	Backend        string `json:"backend,omitempty"`
	DefaultInbound string `json:"default_inbound,omitempty"`
	RuleCount      int    `json:"rule_count"`
}

type Hardening struct {
	SSHD                 SSHDConfig        `json:"sshd"`
	Firewall             HostFirewall      `json:"firewall"`
	SUIDBinaries         []string          `json:"suid_binaries,omitempty"`
	WorldWritable        []string          `json:"world_writable,omitempty"`
	WritablePathDirs     []string          `json:"writable_path_dirs,omitempty"`
	WritableRootCron     []string          `json:"writable_root_cron,omitempty"`
	AutoUpdates          *bool             `json:"auto_updates,omitempty"`
	AutoUpdatesMechanism string            `json:"auto_updates_mechanism,omitempty"`
	Sysctl               map[string]string `json:"sysctl,omitempty"`
	MACFramework         string            `json:"mac_framework,omitempty"`
	DiskEncryption       *bool             `json:"disk_encryption,omitempty"`
	SecureBoot           *bool             `json:"secure_boot,omitempty"`
	DockerSocket         map[string]any    `json:"docker_socket,omitempty"`
	PendingReboot        *bool             `json:"pending_reboot,omitempty"`
	AVEnabled            *bool             `json:"av_enabled,omitempty"`
	Extra                map[string]any    `json:"extra,omitempty"`
}

type Container struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	Image      string   `json:"image,omitempty"`
	Privileged bool     `json:"privileged"`
	Mounts     []string `json:"mounts,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

type Inventory struct {
	SchemaVersion  int             `json:"schema_version"`
	AgentVersion   string          `json:"agent_version"`
	CollectedAt    time.Time       `json:"collected_at"`
	Host           HostInfo        `json:"host"`
	Interfaces     []Interface     `json:"interfaces,omitempty"`
	Listeners      []Listener      `json:"listeners,omitempty"`
	Connections    []Connection    `json:"connections,omitempty"`
	Packages       []Package       `json:"packages,omitempty"`
	Users          []User          `json:"users,omitempty"`
	Groups         []Group         `json:"groups,omitempty"`
	SudoRules      []SudoRule      `json:"sudo_rules,omitempty"`
	AuthorizedKeys []AuthorizedKey `json:"authorized_keys,omitempty"`
	Credentials    []Credential    `json:"credentials,omitempty"`
	KnownHosts     []KnownHost     `json:"known_hosts,omitempty"`
	Datastores     []Datastore     `json:"datastores,omitempty"`
	Hardening      Hardening       `json:"hardening"`
	Containers     []Container     `json:"containers,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
}

// BoolPtr is a helper for optional booleans.
func BoolPtr(b bool) *bool { return &b }
