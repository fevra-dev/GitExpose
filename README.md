# GitExpose

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![CVE](https://img.shields.io/badge/CVE--2025--55182-React2Shell-red.svg)

**Advanced Security Scanner for the 2025 Threat Landscape**

*Detect exposed files, vulnerable frameworks, AI infrastructure, and supply chain threats*

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## Overview

GitExpose is a high-performance security scanner that goes beyond traditional sensitive file detection. Built to address **2025's evolving threat landscape**, it detects:

| Threat Category | What's Detected |
|-----------------|-----------------|
| **Exposed Files** | .git, .env, configs, backups, source maps |
| **Framework Vulnerabilities** | React2Shell (CVE-2025-55182), Next.js misconfigs |
| **ML Supply Chain** | Malicious pickle files, poisoned PyTorch models |
| **AI Infrastructure** | Vector databases, system prompts, RAG configs |
| **Invisible Code** | Unicode attacks, GlassWorm patterns, Trojan Source |
| **Cloud Assets** | S3 buckets, Azure blobs, GCP storage |
| **CI/CD Exposure** | GitHub Actions, GitLab CI, Jenkins configs |

---

## Features

### Core Scanning
- **Async HTTP** with configurable concurrency (50-100+ requests)
- **Signature validation** reduces false positives by 95%+
- **Multiple outputs**: Console, JSON, CSV, HTML reports
- **100+ detection patterns** across all categories

### Advanced Modules
- **React2Shell Detector** - CVE-2025-55182 vulnerability scanning
- **ML Model Scanner** - Pickle opcode analysis, PyTorch/TensorFlow detection
- **LLM Exposure Scanner** - Vector DBs, prompts, API keys
- **Unicode Detector** - Invisible characters, GlassWorm patterns
- **Cloud Scanner** - Multi-cloud asset exposure
- **API Discovery** - REST enumeration, GraphQL introspection
- **Stealth Mode** - WAF detection and evasion
- **MCP Server** - AI agent integration via Model Context Protocol

---

## Installation

```bash
# Clone repository
git clone https://github.com/fevra-dev/GitExpose.git
cd gitexpose

# Install with pip
pip install -e .

# Or install with advanced dependencies
pip install -e ".[advanced]"
```

### Requirements
- Python 3.9+
- aiohttp, click, colorama (core)
- rich, aiofiles, GitPython (advanced, optional)

---

## Quick Start

### Basic Scan
```bash
# Single target
gitexpose example.com

# Multiple targets
gitexpose example.com api.example.com

# From file
gitexpose -f targets.txt
```

### Advanced Scans
```bash
# Full security audit (all modules)
gitexpose scan example.com --full-audit

# React2Shell vulnerability check
gitexpose react2shell https://nextjs-app.com

# ML model supply chain scan
gitexpose ml-scan https://api.example.com

# LLM/AI infrastructure exposure
gitexpose llm-scan https://ai-app.com

# Invisible Unicode detection
gitexpose unicode-scan --file suspicious.js
```

### Output Formats
```bash
# JSON output
gitexpose example.com -o json --out-file results.json

# HTML report
gitexpose scan example.com --full-audit -o html --out-file report.html

# CSV for spreadsheets
gitexpose -f targets.txt -o csv --out-file results.csv
```

---

## Advanced Capabilities

### React2Shell Detection (CVE-2025-55182)
Detects the critical pre-auth RCE vulnerability affecting React Server Components:
```python
from gitexpose.advanced import React2ShellDetector

detector = React2ShellDetector(deep_scan=True)
finding = await detector.scan("https://nextjs-app.com")

print(f"Status: {finding.status.value}")  # vulnerable/potentially_vulnerable
print(f"Risk Score: {finding.risk_score}/10.0")
```

### ML Model Supply Chain
Scans for exposed models that could execute arbitrary code:
```python
from gitexpose.advanced import MLModelScanner

scanner = MLModelScanner(deep_analysis=True)
result = await scanner.scan("https://ml-api.com")

for model in result.exposed_models:
    print(f"[{model.risk_level}] {model.path}")
```

### MCP Server (AI Agent Integration)
```bash
# Start MCP server for Claude/GPT integration
gitexpose mcp
```

---

## Detection Coverage

| Category | Patterns | Severity |
|----------|----------|----------|
| **Git Repositories** | .git/config, HEAD, index | Critical |
| **Environment Files** | .env, .env.production | Critical |
| **Configuration** | wp-config.php, settings.py | High |
| **Backups** | backup.sql, database.dump | Critical |
| **Source Maps** | *.js.map, webpack bundles | High |
| **ML Models** | .pkl, .pt, .h5 | Critical |
| **AI/LLM** | Vector DBs, prompts, API keys | Critical |

---

## Project Structure

```
gitexpose/
├── gitexpose/
│   ├── __init__.py          # Main package
│   ├── cli.py                # CLI interface
│   ├── scanner.py            # Core scanning engine
│   │
│   ├── advanced/             # Advanced security modules
│   │   ├── react2shell_detector.py
│   │   ├── ml_model_scanner.py
│   │   ├── llm_exposure_scanner.py
│   │   ├── invisible_unicode_detector.py
│   │   └── mcp_server.py
│   │
│   ├── git/                  # Git analysis
│   ├── secrets/              # Credential extraction
│   └── reporters/            # Output formatters
│
├── docs/                     # Documentation
├── tests/                    # Test suite
└── requirements.txt
```

---

## Responsible Use

This tool is intended for:
- Authorized penetration testing
- Bug bounty programs (in-scope targets)
- Security audits with permission
- Validating your own infrastructure

**Never** use against targets without explicit authorization.

---

## Research Basis

Built on current threat intelligence:

| Threat | Source | Impact |
|--------|--------|--------|
| React2Shell | CVE-2025-55182 | CVSS 10.0 RCE |
| ML Poisoning | nullifAI research | Arbitrary code execution |
| GlassWorm | VS Code supply chain | Self-propagating worm |
| RAG Poisoning | OWASP LLM Top 10 | AI manipulation |

---

## Contributing

Contributions welcome! Areas of interest:
- New detection patterns
- Framework-specific scanners
- ML model format analysis
- Unicode attack patterns

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security researchers defending against the 2025 threat landscape**

</div>
