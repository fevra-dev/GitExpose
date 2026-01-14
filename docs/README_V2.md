# GitExpose v2.0 - Cutting-Edge Security Scanner

## 🚀 New Features Overview

GitExpose v2.0 transforms the tool from a simple sensitive file scanner into a **comprehensive attack surface discovery platform**. These enhancements address critical gaps in existing security tools and provide capabilities found in premium commercial products.

---

## 📦 New Modules

### 1. Cloud Asset Exposure Scanner (`cloud_scanner.py`)
**Gap Addressed:** Many organizations accidentally expose cloud storage buckets, but existing tools don't comprehensively detect and validate these exposures.

**Features:**
- **Multi-Cloud Support:** AWS S3, Azure Blob Storage, GCP Cloud Storage, DigitalOcean Spaces, Alibaba OSS, Oracle OCI
- **Container Registries:** ECR, GCR, ACR exposure detection
- **Smart Enumeration:** Automatic bucket name enumeration based on domain
- **Permission Checking:** Detects public read, write, and listing permissions
- **File Discovery:** Lists exposed files in public buckets
- **CDN Origin Detection:** Identifies CloudFront, Azure CDN origins

**Usage:**
```bash
gitexpose example.com --cloud-scan --cloud-enumerate
```

---

### 2. Source Map Analyzer (`sourcemap_analyzer.py`)
**Gap Addressed:** Source maps are one of the most overlooked attack vectors - they expose full original source code including hardcoded secrets.

**Features:**
- **Automatic Discovery:** Finds source maps via URLs, headers, and inline references
- **Full Extraction:** Recovers complete original TypeScript/React/Vue/Angular source
- **Secret Detection:** 15+ secret patterns scanned in recovered code
- **Framework Detection:** Identifies React, Vue, Angular, Next.js, Nuxt, Svelte
- **Build System Identification:** Webpack, Vite, Rollup detection
- **Source Recovery:** Saves recovered source code to disk

**Usage:**
```bash
gitexpose example.com --source-maps --extract-sources --sources-dir ./recovered
```

**Why This Matters:**
- 40%+ of production sites accidentally expose source maps
- Exposes entire application logic and business rules
- Reveals API endpoints, admin routes, internal services
- Often contains hardcoded API keys and credentials

---

### 3. CI/CD Pipeline Scanner (`cicd_scanner.py`)
**Gap Addressed:** CI/CD configurations reveal deployment infrastructure, secret patterns, and attack vectors but aren't systematically scanned.

**Features:**
- **Multi-Platform Support:** 
  - GitHub Actions
  - GitLab CI
  - Jenkins
  - CircleCI
  - Travis CI
  - Azure DevOps
  - Bitbucket Pipelines
  - Drone CI
  - BuildKite
  - ArgoCD
  - Tekton
- **Secret Pattern Detection:** Identifies referenced secrets and environment variables
- **Cloud Provider Detection:** AWS, GCP, Azure, Kubernetes, Docker
- **Attack Vector Identification:** Command injection, privilege escalation, network exposure
- **Service Discovery:** Internal endpoints, database connections

**Usage:**
```bash
gitexpose example.com --cicd-scan
```

---

### 4. Infrastructure as Code Scanner (`iac_scanner.py`)
**Gap Addressed:** IaC files often contain security misconfigurations and hardcoded credentials but are rarely scanned as part of web security assessments.

**Features:**
- **Terraform:** State files, variable files, provider configs
- **Kubernetes:** Deployments, services, configmaps, secrets, ingress
- **Docker Compose:** Production and development configs
- **Dockerfiles:** Security misconfiguration detection
- **Ansible:** Playbooks with credential exposure
- **CloudFormation:** AWS infrastructure templates
- **Helm Charts:** Kubernetes package configs

**Security Analysis:**
- Hardcoded secrets detection
- Privileged container detection
- Public access misconfigurations
- Missing encryption
- Root user configurations
- Resource limit validation

**Usage:**
```bash
gitexpose example.com --iac-scan
```

---

### 5. API Endpoint Discovery (`api_discovery.py`)
**Gap Addressed:** API endpoints are major attack surfaces but discovering and analyzing them requires manual work.

**Features:**
- **GraphQL Analysis:**
  - Introspection query execution
  - Type and field enumeration
  - Mutation discovery
  - Sensitive operation detection
- **OpenAPI/Swagger:**
  - Specification parsing
  - Endpoint enumeration
  - Authentication analysis
- **REST API:**
  - CORS misconfiguration detection
  - Rate limiting absence detection
  - Debug mode detection
- **WebSocket:** Endpoint discovery

**Usage:**
```bash
gitexpose example.com --api-discovery --graphql-introspection
```

---

### 6. Advanced Stealth Module (`stealth_scanner.py`)
**Gap Addressed:** Security scanners are easily detected and blocked by WAFs, but evasion capabilities are typically only in commercial tools.

**Features:**
- **WAF Detection:**
  - Cloudflare, Akamai, AWS WAF, Imperva
  - Sucuri, F5 BIG-IP, ModSecurity
  - Barracuda, Fortinet
  - Bypass technique recommendations
- **Adaptive Rate Limiting:**
  - Automatic backoff on rate limits
  - Recovery when successful
  - Per-host rate management
- **Fingerprint Randomization:**
  - User-Agent rotation (modern 2025 browsers)
  - Header randomization
  - Client hints spoofing
  - Referer chain building
- **Stealth Levels:**
  - Normal: Maximum speed
  - Low: UA rotation only
  - Medium: +Random delays
  - High: +Full header randomization
  - Paranoid: Maximum stealth

**Usage:**
```bash
gitexpose example.com --stealth high --detect-waf
```

---

### 7. Extended Paths Database (`paths_extended.py`)
**Gap Addressed:** Detection coverage for modern frameworks and cloud configurations.

**New Detection Categories:**
- **Modern Frameworks:** Next.js, Nuxt.js, Vite, Remix, SvelteKit
- **Source Maps:** Various build output patterns
- **Cloud Configs:** AWS, GCP, Azure, Firebase, Amplify
- **Containers:** Kubernetes, Docker, Helm, Skaffold
- **Debug Endpoints:** Spring Boot Actuator, ELMAH, ASP.NET Trace
- **Package Managers:** NPM, Yarn, pnpm, Composer, Poetry, Bundler, Cargo, Go
- **IDE Configs:** IntelliJ database connections, VS Code
- **Credentials:** SSH keys, .netrc, .pgpass, .my.cnf
- **Serverless:** Vercel, Netlify, SAM, Serverless Framework

**Total: 100+ new detection signatures**

---

## 🎯 Integrated CLI (`cli_v2.py`)

The new CLI brings all modules together with a unified interface:

```bash
# Basic scan
gitexpose example.com

# Full security audit
gitexpose example.com --full-audit -o html --out-file report.html

# Cloud-focused scan
gitexpose example.com --cloud-scan --cloud-enumerate

# Source code recovery
gitexpose example.com --source-maps --extract-sources

# Stealth scan
gitexpose example.com --stealth high --detect-waf --full-audit

# Multiple targets with all features
gitexpose -f targets.txt --full-audit --stealth medium -o json --out-file results.json
```

---

## 🏆 Competitive Advantages

### vs. Nuclei
- ✅ Specialized for exposure detection (not just vuln scanning)
- ✅ Built-in source code recovery from source maps
- ✅ Automatic cloud bucket enumeration
- ✅ GraphQL introspection with mutation analysis

### vs. TruffleHog/Gitleaks
- ✅ Web-based scanning (no repo access needed)
- ✅ Source map secret extraction
- ✅ CI/CD config analysis
- ✅ Cloud asset discovery

### vs. Subjack/S3Scanner
- ✅ Multi-cloud support (not just S3)
- ✅ Permission level detection
- ✅ Integrated with full security scanner
- ✅ File listing in exposed buckets

### vs. Commercial Tools (Burp, Nessus)
- ✅ Open source and free
- ✅ Modern framework coverage
- ✅ CI/CD and IaC analysis
- ✅ Python-based and extensible

---

## 📊 Use Cases

### 1. Bug Bounty Hunting
```bash
# Quick recon on new target
gitexpose target.com --full-audit --source-maps -o json

# Check for cloud misconfigs
gitexpose target.com --cloud-scan --cloud-enumerate
```

### 2. Penetration Testing
```bash
# Stealth reconnaissance
gitexpose target.com --stealth paranoid --detect-waf --full-audit

# Gather API intelligence
gitexpose target.com --api-discovery --graphql-introspection
```

### 3. Security Assessments
```bash
# Full audit with report
gitexpose -f client-domains.txt --full-audit -o html --out-file assessment.html
```

### 4. DevSecOps Integration
```bash
# CI/CD pipeline check
gitexpose staging.company.com --cicd-scan --iac-scan -o json
```

---

## 🔧 Installation

### Requirements
```
aiohttp>=3.9.0
aiofiles>=23.2.0
click>=8.1.0
GitPython>=3.1.40 (optional, for git analysis)
rich>=13.7.0 (optional, for beautiful output)
pyyaml>=6.0 (optional, for YAML parsing)
```

### Install
```bash
pip install -e .
# or
pip install aiohttp aiofiles click GitPython rich
```

---

## 🚀 Getting Started

1. **Copy modules to main package:**
```bash
cp gitexpose/NEW\ ADDITIONS/*.py gitexpose/
```

2. **Update `__init__.py`:**
```python
from .cloud_scanner import CloudAssetScanner
from .sourcemap_analyzer import SourceMapAnalyzer
from .cicd_scanner import CICDScanner
from .iac_scanner import IaCScanner
from .api_discovery import APIDiscovery
from .stealth_scanner import StealthScanner, WAFDetector
```

3. **Update entry point in `setup.py`:**
```python
entry_points={
    'console_scripts': [
        'gitexpose=gitexpose.cli_v2:main',
    ],
}
```

4. **Run:**
```bash
gitexpose example.com --full-audit
```

---

## 📈 Roadmap

### v2.1 (Planned)
- [ ] YAML template system (Nuclei-compatible)
- [ ] Shodan integration for target discovery
- [ ] Subdomain enumeration
- [ ] Real-time web dashboard

### v2.2 (Future)
- [ ] Container image scanning
- [ ] Kubernetes cluster reconnaissance
- [ ] GraphQL mutation fuzzing
- [ ] AI-powered finding prioritization

---

## 💡 Portfolio Highlights

This project demonstrates expertise in:

1. **Async Python** - High-performance concurrent scanning
2. **Security Research** - Novel attack surface identification
3. **Cloud Security** - Multi-cloud exposure detection
4. **Modern Web** - Framework-specific detection
5. **Infrastructure** - IaC security analysis
6. **API Security** - GraphQL/REST analysis
7. **Evasion Techniques** - WAF bypass and stealth

---

## 📄 License

MIT License - Free for personal and commercial use.

---

**Made with ❤️ for the security community**
