# AI integration

SAMS can talk to the AI tools you already use, in both directions:

| Direction | What | Where |
|---|---|---|
| SAMS → LLM | The built-in **security analyst** runs a tool loop against any configured model: Anthropic Claude, OpenAI, Azure OpenAI, anything OpenAI-compatible (vLLM, LM Studio, LocalAI, OpenRouter, Groq, LiteLLM, Gemini), or Ollama | `sams/ai/providers.py`, `sams/ai/analyst.py` |
| LLM clients → SAMS | **MCP server** exposing SAMS tools, resources and prompts to Claude Desktop, Claude Code, LibreChat, Cursor, etc. (stdio or streamable HTTP at `/mcp`) | `sams/ai/mcp_server.py` |
| Chat UIs → SAMS | **OpenAI-compatible endpoint** (`/v1/models`, `/v1/chat/completions`, streaming), so LibreChat, Open WebUI, Jan or any OpenAI client can chat with the SAMS analyst | `sams/ai/openai_compat.py` |

All three share one tool registry (`sams/ai/tools.py`):

| Tool | Purpose |
|---|---|
| `posture_summary` | score/grade, per-host scores, finding and alert counts |
| `list_assets`, `get_asset` | inventory summary per host (OS, IPs, listeners, admins, sudo, credentials, datastores, hardening) |
| `list_findings`, `get_finding` | findings by asset/category/severity/status, with full evidence and remediation |
| `blast_radius` | "if this host were compromised, what could the attacker reach?" |
| `attack_paths` | likeliest paths from the internet (or any node) to critical assets |
| `remediation_plan` | fixes ranked by attack-path risk removed |
| `search_events`, `list_alerts`, `get_alert` | SIEM search and alert context |
| `firewall_overview` | firewall segments, rules, settings, port forwards and findings |
| `external_exposure` | what the off-network probes saw, plus inside-vs-outside discrepancies |
| `list_agents` | agents/probes and their last check-in |
| `create_patch_task` ✎, `set_finding_status` ✎, `acknowledge_alert` ✎ | **write tools**: only exposed when `ai.allow_write_tools: true` |

Write tools never bypass the human gate. Patch tasks are created `pending` and still need
approval in the SAMS UI before an agent receives them, and agents additionally require
`allow_patching: true` in their *local* config.

## Configuring providers (`sams.yaml`)

Secrets are referenced by environment-variable **name** (`api_key_env`). They never go in
the YAML or the database.

```yaml
ai:
  enabled: true
  default_provider: claude
  max_tool_iterations: 12
  allow_write_tools: false        # let the AI queue (approval-gated) patch tasks / change statuses
  mcp_tokens: []                  # extra bearer tokens for /mcp and /v1/* (admin_token always works)
  providers:
    # --- Anthropic Claude (official SDK) -------------------------------------
    - name: claude
      type: anthropic
      model: claude-opus-5-5
      api_key_env: ANTHROPIC_API_KEY
      effort: high                # low | medium | high | xhigh | max
      max_tokens: 16000
      locality: cloud             # identifiers are pseudonymized before leaving (see Privacy)

    # --- OpenAI -----------------------------------------------------------
    - name: openai
      type: openai
      model: gpt-5
      api_key_env: OPENAI_API_KEY
      extra: {reasoning_effort: medium}

    # --- Ollama, native API (fully local) -----------------------------------
    - name: local
      type: ollama
      model: qwen2.5:14b          # any tool-capable model: llama3.1, qwen2.5, mistral-nemo...
      base_url: http://ollama.lan:11434
      locality: local             # no redaction needed, nothing leaves your network
      extra: {keep_alive: 30m, options: {num_ctx: 32768}}

    # --- LM Studio (OpenAI-compatible) ------------------------------------
    - name: lmstudio
      type: openai_compatible
      model: qwen2.5-14b-instruct
      base_url: http://workstation.lan:1234/v1
      locality: local

    # --- vLLM ---------------------------------------------------------------
    - name: vllm
      type: openai_compatible
      model: meta-llama/Llama-3.3-70B-Instruct
      base_url: http://gpu01.lan:8000/v1
      api_key_env: VLLM_API_KEY   # if started with --api-key
      locality: local

    # --- OpenRouter -----------------------------------------------------------
    - name: openrouter
      type: openai_compatible
      model: anthropic/claude-opus-5.5
      base_url: https://openrouter.ai/api/v1
      api_key_env: OPENROUTER_API_KEY
      extra: {default_headers: {X-Title: SAMS}}

    # --- Azure OpenAI ---------------------------------------------------------
    - name: azure
      type: azure_openai
      model: my-gpt-deployment    # the *deployment* name
      base_url: https://my-resource.openai.azure.com
      api_key_env: AZURE_OPENAI_API_KEY
      extra: {api_version: "2024-10-21"}

    # --- Google Gemini via its OpenAI-compatible endpoint ----------------------
    - name: gemini
      type: openai_compatible
      model: gemini-2.5-pro
      base_url: https://generativelanguage.googleapis.com/v1beta/openai/
      api_key_env: GEMINI_API_KEY
```

Ollama can also be used through its OpenAI-compatible `/v1` endpoint (`type: openai_compatible`,
`base_url: http://host:11434/v1`). The native `ollama` type is preferred because it supports
Ollama-specific options (`keep_alive`, `num_ctx`).

### Claude specifics

The Anthropic adapter follows current API guidance:

* adaptive thinking, with depth controlled by `effort` (default `high`)
* streamed requests read with `get_final_message()`
* thinking blocks replayed unchanged across tool-loop turns
* all tool results returned in one message
* `is_error` results when a tool fails
* a prompt-cache breakpoint on the (stable) tools and system prompt, plus automatic caching of the growing conversation

On models that support it, the server-side **refusal fallback** (`fallbacks: "default"`) is
enabled. If the primary model declines a request, the API re-runs it on a fallback model in the
same call. Opt out with `extra: {fallbacks: false}`. When `base_url` points at a gateway or proxy,
beta parameters (fallbacks, `eager_input_streaming`) are off by default, because gateways may reject
them; re-enable with `extra: {fallbacks: default, eager_input_streaming: true}`.

## Privacy model

Security data is sensitive. For every provider with `locality: cloud` and
`allow_sensitive: false` (the default for cloud), the analyst pseudonymizes identifiers
**before** anything leaves SAMS:

| Real value | Sent to the model |
|---|---|
| `10.0.10.5`, `192.168.1.0/24` | `PRIV-IP-1`, `PRIV-IP-2/24` (private vs public is preserved) |
| `203.0.113.7` | `PUB-IP-1` |
| `web01.corp.example`, asset ids, firewall names | `HOST-1`, `HOST-2` |
| local user names (except system accounts like `root`, `www-data`) | `USER-1` |
| e-mail, MAC, SSH fingerprints, masked cloud key ids | `EMAIL-1`, `MAC-1`, `KEY-1`, `CRED-1` |

The mapping is stable within a conversation, so the model can reason about "HOST-2" across
tool calls. Tool-call arguments coming back are translated to real values before tools run,
and the final answer is translated back before you see it. CVE ids, package names, versions,
ports and finding keys pass through unchanged. Agents never send secret material to SAMS in
the first place, only metadata and fingerprints.

* `locality: local` (Ollama, LM Studio, vLLM on your network): no redaction.
* `allow_sensitive: true`: opt out of redaction for a cloud provider (e.g. one with a zero-data-retention agreement).
* **MCP and the OpenAI-compatible endpoint return real values to the client.** The client
  (Claude Desktop, LibreChat...) decides which model sees them. Use a local model in that
  client, or the built-in analyst, if that matters.

## LibreChat

### As a custom endpoint (chat with the SAMS analyst)

`librechat.yaml`:

```yaml
endpoints:
  custom:
    - name: "SAMS Security Analyst"
      apiKey: "${SAMS_API_TOKEN}"          # SAMS admin token or one of ai.mcp_tokens
      baseURL: "https://sams.dmz.example:8443/v1"
      models:
        default: ["sams-analyst", "sams-analyst-claude", "sams-analyst-local"]
        fetch: true                        # pulls GET /v1/models
      titleConvo: false                    # don't spend analyst runs on titles
      modelDisplayLabel: "SAMS"
      addParams:
        sams_progress: true                # stream "Looking up `tool`…" progress lines
```

### As an MCP server (LibreChat's own model uses the SAMS tools)

```yaml
mcpServers:
  sams:
    type: streamable-http
    url: https://sams.dmz.example:8443/mcp
    headers:
      Authorization: "Bearer ${SAMS_API_TOKEN}"
    timeout: 120000
```

Or launch it locally over stdio (LibreChat on the same host as SAMS):

```yaml
mcpServers:
  sams:
    type: stdio
    command: /opt/sams/.venv/bin/python
    args: ["-m", "sams.ai.mcp_server", "--config", "/etc/sams/sams.yaml"]
```

## Claude Desktop / Claude Code

Claude Desktop (`claude_desktop_config.json`), stdio:

```json
{
  "mcpServers": {
    "sams": {
      "command": "/opt/sams/.venv/bin/python",
      "args": ["-m", "sams.ai.mcp_server", "--config", "/etc/sams/sams.yaml"]
    }
  }
}
```

Claude Code, remote over HTTP:

```bash
claude mcp add --transport http sams https://sams.dmz.example:8443/mcp \
  --header "Authorization: Bearer $SAMS_API_TOKEN"
```

or stdio on the SAMS host:

```bash
claude mcp add sams -- /opt/sams/.venv/bin/python -m sams.ai.mcp_server --config /etc/sams/sams.yaml
```

The MCP server also offers **resources** (`sams://posture`, `sams://findings/open`,
`sams://assets`) and **prompts** (`triage_alert`, `harden_host`, `weekly_report`).

## Open WebUI and other OpenAI clients

Add an OpenAI connection with base URL `https://sams.dmz.example:8443/v1` and the SAMS token
as API key. The models `sams-analyst*` appear automatically. Any OpenAI SDK works:

```python
from openai import OpenAI
c = OpenAI(base_url="https://sams.dmz.example:8443/v1", api_key=SAMS_TOKEN)
print(c.chat.completions.create(model="sams-analyst",
      messages=[{"role": "user", "content": "What is exposed to the internet?"}]).choices[0].message.content)
```

## Python API

```python
from sams.ai import make_analyst
analyst = make_analyst(ctx)                 # default provider, or make_analyst(ctx, "local")
print(analyst.ask("If web01 were compromised, what could the attacker reach?").text)
analyst.triage_alert(42); analyst.explain_finding("vuln:host_x:dpkg:openssl")
analyst.executive_summary(); analyst.remediation_narrative("plan-item-id")
```

## Security notes

* `/mcp` and `/v1/*` require `Authorization: Bearer <token>`. With no admin token and no
  `ai.mcp_tokens` configured, they reject every request.
* Write tools are off by default and annotated as destructive in MCP, so clients ask before running them.
* Tool results are size-capped (lists truncated with a note) to keep context windows and costs bounded.
* Treat the analyst's output as advice: commands are suggestions for a human to review, never auto-executed.
