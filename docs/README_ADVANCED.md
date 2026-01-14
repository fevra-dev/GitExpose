# GitExpose Advanced Features v3.0

<div align="center">

**🔬 Next-Generation Security Scanner for the 2025 Threat Landscape**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CVE](https://img.shields.io/badge/CVE--2025--55182-React2Shell-red.svg)](#react2shell-detection)

*Addressing cutting-edge attack vectors: React2Shell, ML Supply Chain Poisoning, LLM Infrastructure Exposure, and Invisible Unicode Attacks*

</div>

---

## 🎯 Executive Summary

GitExpose v3.0 extends beyond traditional sensitive file detection to address the **2025-2026 threat landscape**, incorporating detection capabilities for:

| Module | Threat Addressed | Research Basis |
|--------|------------------|----------------|
| **React2Shell Detector** | CVE-2025-55182 (CVSS 10.0) | Framework RCE via Flight protocol |
| **ML Model Scanner** | Pickle/PyTorch deserialization RCE | nullifAI, HuggingFace poisoning |
| **LLM Exposure Scanner** | AI infrastructure compromise | RAG poisoning, prompt leakage |
| **Unicode Detector** | GlassWorm-style supply chain | Invisible code injection |
| **MCP Server** | AI agent orchestration | HexStrike AI patterns |

---

## 🚀 Quick Start

```bash
# Full security audit
gitexpose scan example.com --full-audit

# Specific scans
gitexpose react2shell https://nextjs-app.com
gitexpose ml-scan https://api.example.com
gitexpose llm-scan https://ai-app.com
gitexpose unicode-scan --file suspicious.js

# Start MCP server for AI agents
gitexpose mcp
```

---

## 📦 New Modules

### 1. React2Shell Detector (`react2shell_detector.py`)

Detects the **CVE-2025-55182** vulnerability - a critical pre-authentication RCE affecting React Server Components, Next.js, and the Flight protocol.

**What it detects:**
- Exposed RSC (React Server Components) endpoints
- Flight protocol serialization endpoints
- Vulnerable Next.js configurations (13.x-15.x)
- Server action exports
- Build manifest exposure

**Technical Details:**
```python
from gitexpose.react2shell_detector import React2ShellDetector

detector = React2ShellDetector(deep_scan=True)
finding = await detector.scan("https://nextjs-app.com")

print(f"Status: {finding.status.value}")  # vulnerable/potentially_vulnerable/likely_safe
print(f"Framework: {finding.framework.value}")  # nextjs/remix/gatsby
print(f"Risk Score: {finding.risk_score}/10.0")
```

**CLI Usage:**
```bash
gitexpose react2shell https://target.com --deep-scan
gitexpose react2shell https://target.com -o json
```

---

### 2. ML Model Supply Chain Scanner (`ml_model_scanner.py`)

Scans for exposed machine learning model files that could execute arbitrary code when loaded.

**Threat Model:**
- **Pickle deserialization**: Arbitrary Python code execution via `__reduce__`
- **PyTorch `torch.load()`**: Uses pickle internally
- **TensorFlow SavedModel**: Custom ops can execute code
- **nullifAI attacks**: 7z-compressed pickles evading scanners

**Detected Formats:**
| Extension | Format | Risk Level |
|-----------|--------|------------|
| `.pkl`, `.pickle` | Python Pickle | 🔴 Critical |
| `.pt`, `.pth`, `.bin` | PyTorch | 🔴 Critical |
| `.joblib` | Joblib | 🔴 Critical |
| `.h5`, `.hdf5`, `.keras` | Keras/TF | 🟠 High |
| `.onnx` | ONNX | 🟡 Medium |
| `.safetensors` | SafeTensors | 🟢 Low |

**Deep Analysis Features:**
- Dangerous pickle opcode detection (`GLOBAL`, `REDUCE`, etc.)
- Nested pickle stream identification
- Base64-encoded payload detection
- 7z compression evasion technique detection

```python
from gitexpose.ml_model_scanner import MLModelScanner

scanner = MLModelScanner(deep_analysis=True)
result = await scanner.scan("https://ml-api.com")

for model in result.exposed_models:
    print(f"[{model.risk_level.value}] {model.path}")
    for indicator in model.indicators:
        print(f"  ⚠ {indicator.description}")
```

---

### 3. LLM/RAG Exposure Scanner (`llm_exposure_scanner.py`)

Detects exposed AI/LLM infrastructure as organizations rapidly deploy AI without security controls.

**Detection Targets:**

| Category | What's Detected |
|----------|-----------------|
| **Vector Databases** | ChromaDB, Pinecone, Weaviate, Milvus, Qdrant |
| **System Prompts** | Exposed prompt templates, system instructions |
| **RAG Configs** | Knowledge base locations, chunking strategies |
| **LangChain/LlamaIndex** | Chain configs, agent definitions |
| **API Keys** | OpenAI, Anthropic, Cohere, HuggingFace tokens |
| **Agent Configs** | MCP servers, tool definitions |

**Why This Matters:**
- System prompts often contain business logic and internal API docs
- Vector databases store sensitive knowledge bases
- Exposed API keys enable model abuse and billing fraud
- Agent configs reveal tool permissions and attack surface

```python
from gitexpose.llm_exposure_scanner import LLMExposureScanner

scanner = LLMExposureScanner()
result = await scanner.scan("https://ai-app.com")

for exposure in result.exposures:
    print(f"[{exposure.severity.value}] {exposure.exposure_type.value}")
    print(f"  URL: {exposure.url}")
    print(f"  {exposure.description}")
```

---

### 4. Invisible Unicode Detector (`invisible_unicode_detector.py`)

Detects invisible Unicode characters used in supply chain attacks like **GlassWorm**.

**Attack Vectors Detected:**

| Category | Characters | Threat Level |
|----------|------------|--------------|
| **Zero-Width** | ZWSP, ZWNJ, ZWJ | 🟡 Medium |
| **Variation Selectors** | VS1-VS256 | 🔴 High |
| **Bidirectional** | RLO, LRO (Trojan Source) | 🔴 Critical |
| **Tag Characters** | U+E0000-E007F | 🔴 High |
| **Homoglyphs** | Cyrillic, Greek lookalikes | 🟡 Medium |
| **PUA** | Private Use Area | 🟡 Medium |

**GlassWorm Pattern Detection:**
```python
from gitexpose.invisible_unicode_detector import InvisibleUnicodeAnalyzer

analyzer = InvisibleUnicodeAnalyzer(strict_mode=True)
anomalies = analyzer.analyze(suspicious_code)

for anomaly in anomalies:
    print(f"[{anomaly.threat_level.value}] Line {anomaly.line_number}")
    print(f"  {anomaly.codepoint}: {anomaly.description}")

# Decode hidden messages from tag characters
hidden = analyzer.decode_hidden_message(suspicious_code)
if hidden:
    print(f"Hidden message: {hidden}")
```

**CLI Usage:**
```bash
# Scan URL for infected JavaScript
gitexpose unicode-scan https://cdn.example.com/bundle.js

# Analyze local file
gitexpose unicode-scan --file suspicious-extension/index.js
```

---

### 5. MCP Server (`mcp_server.py`)

Implements the **Model Context Protocol** to expose GitExpose as tools for AI agents.

**Why MCP?**
- Enables autonomous security scanning by Claude, GPT, and other AI agents
- Integrates with AI-powered security workflows (HexStrike AI pattern)
- Allows chaining GitExpose with other security tools

**Available MCP Tools:**

| Tool | Description |
|------|-------------|
| `gitexpose_scan` | Comprehensive sensitive file scan |
| `gitexpose_git_dump` | Git repository reconstruction |
| `gitexpose_extract_secrets` | Credential extraction |
| `gitexpose_react2shell_detect` | React2Shell vulnerability check |
| `gitexpose_ml_model_scan` | ML model poisoning scan |
| `gitexpose_llm_exposure_scan` | AI infrastructure exposure |
| `gitexpose_unicode_detect` | Invisible Unicode detection |
| `gitexpose_sourcemap_scan` | Source map recovery |
| `gitexpose_cicd_scan` | CI/CD configuration exposure |
| `gitexpose_api_discovery` | API endpoint enumeration |

**Configuration for Claude/Cursor:**
```json
{
  "mcpServers": {
    "gitexpose": {
      "command": "python",
      "args": ["-m", "gitexpose.mcp_server"]
    }
  }
}
```

**Starting the Server:**
```bash
gitexpose mcp
```

---

## 📊 Architecture

```
gitexpose/
├── NEW ADDITIONS/
│   ├── react2shell_detector.py    # CVE-2025-55182 detection
│   ├── ml_model_scanner.py        # ML supply chain scanning
│   ├── llm_exposure_scanner.py    # AI infrastructure exposure
│   ├── invisible_unicode_detector.py  # GlassWorm pattern detection
│   ├── mcp_server.py              # Model Context Protocol server
│   ├── cli_advanced.py            # Unified advanced CLI
│   │
│   ├── # Previously created modules
│   ├── cloud_scanner.py           # Multi-cloud asset scanning
│   ├── sourcemap_analyzer.py      # Source map recovery
│   ├── cicd_scanner.py            # CI/CD exposure
│   ├── iac_scanner.py             # Infrastructure as Code
│   ├── api_discovery.py           # API enumeration
│   ├── stealth_scanner.py         # WAF evasion
│   └── paths_extended.py          # 100+ detection signatures
```

---

## 🔬 Research Basis

These modules are built on current threat intelligence:

### React2Shell (CVE-2025-55182)
- **Source**: Microsoft Security Blog, Darktrace, Trend Micro
- **Impact**: Unauthenticated RCE via single HTTP request
- **Affected**: Next.js 13.x-15.x, React Server Components
- **Weaponization**: Within hours of disclosure (28% of exploits in 2025)

### ML Model Poisoning
- **Source**: ReversingLabs "nullifAI" research
- **Technique**: Broken pickle format evades PickleScan
- **Platform**: HuggingFace, PyPI, npm
- **Risk**: Arbitrary code execution on `torch.load()` or `pickle.load()`

### GlassWorm
- **Source**: Truesec, Snyk, Dark Reading
- **Technique**: Invisible Unicode variation selectors
- **Target**: VS Code extensions, npm packages
- **C2**: Solana blockchain (unkillable infrastructure)

### LLM Security
- **Source**: OWASP LLM Top 10 2025, Lakera, Prompt Security
- **Threats**: RAG poisoning, indirect prompt injection, API key leakage
- **Impact**: 99% of organizations experienced API security issues in 2025

---

## 🛠️ Installation

```bash
# Install with all dependencies
pip install gitexpose[advanced]

# Or install from source
git clone https://github.com/yourusername/gitexpose.git
cd gitexpose
pip install -e ".[advanced]"
```

**Requirements:**
```
aiohttp>=3.9.0
aiofiles>=23.2.0
click>=8.1.0
rich>=13.0.0  # Optional but recommended
```

---

## 🎯 Use Cases

### Security Audit
```bash
# Full audit with all modules
gitexpose scan target.com --full-audit -o html --out-file audit.html
```

### Bug Bounty
```bash
# Quick reconnaissance
gitexpose scan target.com --react2shell --source-maps --git-dump
```

### AI Security Assessment
```bash
# Audit AI/ML deployments
gitexpose llm-scan https://ai-app.com
gitexpose ml-scan https://ml-api.com --deep-analysis
```

### Supply Chain Defense
```bash
# Check for compromised code
gitexpose unicode-scan --file node_modules/suspicious-package/index.js
```

### AI Agent Integration
```bash
# Start MCP server for autonomous scanning
gitexpose mcp
```

---

## 📈 Portfolio Talking Points

> *"I built GitExpose to address the 2025 threat landscape where exploits are weaponized within hours. It detects React2Shell (CVE-2025-55182), scans for ML model supply chain attacks, identifies exposed AI infrastructure, and catches invisible Unicode used in GlassWorm-style attacks. The tool includes MCP integration for AI agent orchestration, positioning it for the autonomous security future."*

**Key Differentiators:**
1. **React2Shell Detection** - No other open-source tool specifically targets this
2. **ML Supply Chain** - Goes beyond file detection to analyze pickle opcodes
3. **LLM Infrastructure** - Bleeding-edge; most tools don't cover AI attack surface
4. **Invisible Unicode** - Critical for VS Code extension and npm supply chain defense
5. **MCP Compatibility** - Future-proofs for AI agent security workflows

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional framework detection (Remix, Astro, SvelteKit)
- New ML model format analysis
- Additional vector database signatures
- Unicode attack pattern research

---

<div align="center">

**Built for the security researchers defending against 2025's $10.5 trillion cybercrime economy**

[Report Bug](https://github.com/yourusername/gitexpose/issues) · [Request Feature](https://github.com/yourusername/gitexpose/issues)

</div>
