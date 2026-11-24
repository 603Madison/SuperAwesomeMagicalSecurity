"""Server configuration.

Loaded from (lowest to highest precedence): built-in defaults, a YAML file
(``SAMS_CONFIG`` or ``./sams.yaml``), then ``SAMS_*`` environment variables
for the most common scalars. Secrets (API keys, firewall passwords) are never
stored in the database: config references environment variable *names*
(``api_key_env: OPENAI_API_KEY``) and they are resolved at use time.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field


def env_secret(name: str) -> Optional[str]:
    """Read a secret from $NAME, or from the file named by $NAME_FILE (container secrets convention)."""
    if os.environ.get(name):
        return os.environ[name]
    path = os.environ.get(f"{name}_FILE")
    if path:
        try:
            return Path(path).read_text().strip() or None
        except OSError:
            return None
    return None


class VulnSettings(BaseModel):
    # online: query api.osv.dev (sends package names+versions to Google's OSV service)
    # offline: only use the local mirror synced with `sams vulndb sync` (nothing leaves the network)
    # hybrid: local mirror first, online for ecosystems not mirrored
    mode: str = "hybrid"
    osv_api: str = "https://api.osv.dev"
    osv_bulk: str = "https://osv-vulnerabilities.storage.googleapis.com"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_api: str = "https://api.first.org/data/v1/epss"
    enrich: bool = True              # fetch KEV + EPSS
    cache_ttl_hours: int = 24
    timeout_seconds: float = 30.0


class AIProviderSettings(BaseModel):
    name: str                        # free-form label, e.g. "claude", "local-llama"
    type: str                        # anthropic | openai | openai_compatible | ollama
    model: str
    base_url: Optional[str] = None   # for openai_compatible / ollama / proxies
    api_key_env: Optional[str] = None
    # privacy: "cloud" providers get identifiers redacted unless allow_sensitive is set
    locality: str = "cloud"          # cloud | local
    allow_sensitive: bool = False
    max_tokens: int = 16000
    effort: Optional[str] = None     # anthropic: low|medium|high|xhigh|max
    extra: dict[str, Any] = Field(default_factory=dict)

    def api_key(self) -> Optional[str]:
        return env_secret(self.api_key_env) if self.api_key_env else None


class AISettings(BaseModel):
    enabled: bool = True
    default_provider: Optional[str] = None
    providers: list[AIProviderSettings] = Field(default_factory=list)
    max_tool_iterations: int = 12
    # let the AI create (still approval-gated) patch tasks and change finding/alert status
    allow_write_tools: bool = False
    # expose an OpenAI-compatible endpoint (/v1/chat/completions) for LibreChat / Open WebUI
    openai_compat_endpoint: bool = True
    # MCP server over streamable HTTP mounted at /mcp
    mcp_http: bool = True
    # extra bearer tokens accepted by /mcp and /v1/chat/completions (besides the admin token),
    # e.g. one per MCP client / LibreChat instance so they can be revoked independently
    mcp_tokens: list[str] = Field(default_factory=list)


class SIEMSettings(BaseModel):
    syslog_udp_port: Optional[int] = 5514
    syslog_tcp_port: Optional[int] = 5514
    syslog_bind: str = "0.0.0.0"
    retention_days: int = 90
    extra_rules_dir: Optional[str] = None


class ExternalSettings(BaseModel):
    # cap on CIDR size admins may put in scope -- probes must not become internet scanners
    max_cidr_hosts: int = 256
    default_ports: str = "top100"
    rate_per_sec: int = 200
    job_ttl_hours: int = 12


class Settings(BaseModel):
    data_dir: Path = Path("./data")
    listen: str = "127.0.0.1"
    port: int = 8443
    public_url: str = ""             # URL agents/probes use (DMZ address)
    # where agent/probe binaries + SHA256SUMS + install.sh are served from (/downloads, /install.sh).
    # The container image ships them in /opt/sams/dist; otherwise <data_dir>/dist is used.
    dist_dir: Path = Path("/opt/sams/dist")
    admin_token: Optional[str] = None
    agent_collect_interval: int = 3600
    agent_log_sources: list[str] = Field(default_factory=lambda: [
        "/var/log/auth.log", "/var/log/secure", "journald"])
    vuln: VulnSettings = Field(default_factory=VulnSettings)
    ai: AISettings = Field(default_factory=AISettings)
    siem: SIEMSettings = Field(default_factory=SIEMSettings)
    external: ExternalSettings = Field(default_factory=ExternalSettings)
    # honour X-Forwarded-For (only when the server sits behind a reverse proxy you control)
    trust_proxy: bool = False
    # treat hosts without firewall data as reachable from each other (pessimistic default)
    assume_flat_network: bool = True

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sams.db"

    @property
    def signing_key_path(self) -> Path:
        return self.data_dir / "signing_key.pem"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"


def load_settings(path: Optional[str | Path] = None) -> Settings:
    data: dict[str, Any] = {}
    cfg_path = Path(path or os.environ.get("SAMS_CONFIG", "sams.yaml"))
    if cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text()) or {}
    env_map = {
        "SAMS_DATA_DIR": "data_dir", "SAMS_LISTEN": "listen", "SAMS_PORT": "port",
        "SAMS_PUBLIC_URL": "public_url", "SAMS_ADMIN_TOKEN": "admin_token", "SAMS_DIST_DIR": "dist_dir",
    }
    for env, key in env_map.items():
        val = env_secret(env)
        if val:
            data[key] = val
    if os.environ.get("SAMS_VULN_MODE"):
        data.setdefault("vuln", {})["mode"] = os.environ["SAMS_VULN_MODE"]
    return Settings.model_validate(data)
