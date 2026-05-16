# GitExpose Detection Coverage

Last updated: v0.2

GitExpose detects credential exposure across **23 providers** in 5 categories, plus supply-chain risk indicators specific to AI infrastructure. Each finding carries OWASP LLM Top 10 (`attack_class`) and MITRE ATLAS technique (`atlas_technique`) metadata.

## Credential providers

### LLM and AI providers

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| OpenAI | `sk-…`, `sk-proj-…`, `sk-svcacct-…` | CRITICAL | v0.1 + v0.2 |
| Anthropic | `sk-ant-…` | CRITICAL | v0.2 |
| Google AI / Firebase | `AIzaSy…` | CRITICAL | v0.1 |
| Groq | `gsk_…` | CRITICAL | v0.2 |
| OpenRouter | `sk-or-…` | CRITICAL | v0.2 |
| xAI (Grok) | `xai-…` | CRITICAL | v0.2 |
| Cerebras | `csk-…` | CRITICAL | v0.2 |
| Hugging Face | `hf_…` | CRITICAL | v0.2 |
| Replicate | `r8_…` | CRITICAL | v0.2 |
| Perplexity | `pplx-…` | CRITICAL | v0.2 |
| ElevenLabs | 32-hex (context-bound) | CRITICAL | v0.2 |

### RAG / Vector DB

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Pinecone | `pcsk_…` | CRITICAL | v0.2 |

### LLM observability

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| LangSmith | `lsv2_pt_…` and `ls__…` | CRITICAL | v0.2 |

### Code, cloud, payment

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| AWS | `AKIA…` + secret-key context | CRITICAL | v0.1 |
| GitHub PAT | `ghp_…`, `ghs_…` | CRITICAL | v0.1 |
| GitLab PAT | `glpat-…` | CRITICAL | v0.2 |
| Docker Hub | `dckr_pat_…` | CRITICAL | v0.2 |
| Stripe | `sk_live_…`, `rk_live_…`, `sk_test_…` | CRITICAL/HIGH | v0.1 + v0.2 |

### Communication

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Discord (bot) | `M…\..\..` | CRITICAL | v0.2 |
| Discord (webhook) | `discord.com/api/webhooks/…` | HIGH | v0.2 |
| Slack (token) | `xox[baprs]-…` | CRITICAL | v0.1 |
| Slack (webhook) | `hooks.slack.com/services/…` | HIGH | v0.1 |
| Telegram (bot) | `\d{8,10}:[\w-]{35}` | HIGH | v0.2 |

### Notifications

| Provider | Pattern | Severity | Source |
|---|---|---|---|
| Twilio | `AC[a-f0-9]{32}` | HIGH | v0.2 |
| SendGrid | `SG.…` | HIGH | v0.1 |

### Database connection strings

| Type | Pattern | Severity | Source |
|---|---|---|---|
| PostgreSQL | `postgres(?:ql)?://user:pass@…` | HIGH | v0.1 |
| MySQL | `mysql://user:pass@…` | HIGH | v0.1 |
| MongoDB Atlas | `mongodb(\+srv)?://user:pass@…` | HIGH | v0.1 |

### Generic

| Type | Pattern | Severity | Source |
|---|---|---|---|
| Private key (PEM) | `-----BEGIN…PRIVATE KEY-----` | CRITICAL | v0.1 |
| JWT token | `eyJ…\.eyJ…\..*` | HIGH | v0.1 |
| Generic API key | `(api[_-]?key|apikey)["']?\s*[:=]\s*["']…["']` | MEDIUM | v0.1 |

## Supply-chain detection (v0.2)

| Detection | Severity | Description |
|---|---|---|
| `unpinned_ai_middleware` | HIGH | AI middleware (litellm, langchain, openai, anthropic, etc.) without `==` pin |
| `known_malicious_package_version` | CRITICAL | Pinned to a known-compromised version (e.g., `litellm==1.82.7`) |
| `slopsquatting` | CRITICAL | Package name from the LLM-hallucination corpus (e.g., `huggingface-cli`) |
| `pth_persistence` | CRITICAL | `.pth` file with `exec`/`eval`/`base64` (TeamPCP technique) |
| `ai_c2_beacon` | CRITICAL | Skill instructs AI agent to operate as C2 implant (ATLAS AML.TA0015) |
| `kubernetes_exfiltration` | CRITICAL | Kubernetes secret enumeration / service-account token access |
| `credential_cluster` | CRITICAL | ≥2 distinct secret types co-occur in same file |
| `multi_provider_credential_file` | CRITICAL | Cluster appears in known aggregator path (`OAI_CONFIG_LIST`, `litellm_config.yaml`, `.continue/agents/*.yaml`) |

## Empirical AI-tool config paths (v0.2)

GitExpose scans for these paths during URL/HTTP scans (where the path is exposed) and during local filesystem scans:

- `.continue/`, `.continue/agents/*.yaml`, `.continue/config.yaml`
- `claude/.credentials.json`
- `**/litellm*config*.{yaml,yml,md}`
- `mcp.json`, `.cursor/mcp.json`, `**/@config.json.md`
- `**/bin/Debug/**/appsettings*.json`, `**/bin/Release/**/appsettings*.json`
- `drizzle.config.ts`
- `agents.yaml`, `tasks.yaml`, `crew.yaml` (CrewAI)
- `OAI_CONFIG_LIST` (AutoGen)
- `**/.env.*.example`, `**/.env.bak`, `**/.env.*.bak`
- `firebase-config.{js,ts}`

## Compliance taxonomies

Every finding includes:

- **`attack_class`** — OWASP LLM Top 10 ID (`LLM05` Supply Chain, `LLM06` Sensitive Info Disclosure, `LLM08` Excessive Agency, etc.)
- **`atlas_technique`** — MITRE ATLAS technique ID (e.g., `AML.T0019`, `AML.TA0015`)

These appear in JSON, SARIF (as taxonomy references), HTML (badges), CSV (columns), and console output.

The basis for new patterns and paths is public threat intelligence and real-world leak observations. No external service is queried at scan time.
