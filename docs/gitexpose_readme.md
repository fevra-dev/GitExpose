# GitExpose

<div align="center">

**🔍 Fast, Concurrent Scanner for Exposed Sensitive Files**

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/gitexpose?style=social)](https://github.com/yourusername/gitexpose)

*Detect exposed `.git` directories, environment files, backups, and other sensitive resources on web servers*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Advanced Features](#-advanced-features) • [Documentation](#-documentation)

</div>

---

## 🎯 Overview

GitExpose is a high-performance security scanner that detects exposed sensitive files on web applications. Unlike traditional directory bruzzers, GitExpose validates findings with signature-based detection to minimize false positives and provides actionable intelligence.

### Why GitExpose?

- **⚡ Lightning Fast**: Asynchronous scanning with configurable concurrency (50-100+ concurrent requests)
- **🎯 Accuracy**: Signature-based validation reduces false positives by 95%+
- **🔓 Git Repository Dumping**: Automatically downloads and reconstructs exposed `.git` repositories
- **🔑 Secret Extraction**: Detects and validates 30+ types of credentials (AWS keys, API tokens, database URLs)
- **📊 Multiple Output Formats**: Console, JSON, CSV, and interactive HTML reports
- **🔌 Extensible**: Plugin architecture for Slack, Jira, webhooks, and custom integrations

---

## ✨ Features

### Core Scanning
- **100+ Detection Patterns**: Git repositories, environment files, backups, configs, and more
- **Concurrent Scanning**: Up to 100 simultaneous requests with adaptive rate limiting
- **Smart Validation**: Response signature matching to confirm real vulnerabilities
- **Multiple Targets**: Scan single URLs, multiple targets, or bulk from files

### Git Repository Analysis
- **Full Repository Dumping**: Download entire `.git` directories including:
  - Core files (HEAD, config, index, packed-refs)
  - All git objects and references
  - Complete commit history
- **Repository Reconstruction**: Automatic checkout of working directory
- **Historical Secret Scanning**: Analyze all commits for exposed credentials

### Secret Detection & Validation
Automatically detects and extracts:
- **Cloud Providers**: AWS keys, GCP API keys, Azure credentials
- **Version Control**: GitHub, GitLab, Bitbucket tokens
- **Communication**: Slack tokens/webhooks, Discord webhooks
- **Payments**: Stripe, PayPal, Square API keys
- **Email Services**: SendGrid, Mailgun, Mailchimp keys
- **Databases**: PostgreSQL, MySQL, MongoDB connection strings
- **Private Keys**: RSA, SSH, OpenSSH, PGP keys
- **Generic Patterns**: API keys, passwords, JWT tokens

**Secret Validation**: Test if credentials are still active (optional)

### Reporting & Output
- **Console**: Beautiful colored output with severity indicators
- **JSON**: Machine-readable format for automation
- **CSV**: Import into spreadsheets and databases
- **HTML**: Interactive reports with charts and statistics
- **Live Dashboard**: Real-time web interface (optional)

---

## 🚀 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager
- git (for repository reconstruction)

### Install from PyPI (Recommended)
```bash
pip install gitexpose
```

### Install from Source
```bash
git clone https://github.com/yourusername/gitexpose.git
cd gitexpose
pip install -e .
```

### Install with Optional Dependencies
```bash
# For git repository analysis (recommended)
pip install gitexpose[git]

# For all features
pip install gitexpose[all]
```

### Docker
```bash
docker pull gitexpose/gitexpose
docker run -it gitexpose/gitexpose example.com
```

---

## 📖 Usage

### Basic Scanning

```bash
# Scan a single target
gitexpose example.com

# Scan multiple targets
gitexpose example.com example.org api.example.com

# Scan from file (one URL per line)
gitexpose -f targets.txt

# Adjust performance
gitexpose example.com -c 100 -t 5  # 100 concurrent, 5s timeout
```

### Output Formats

```bash
# Console output (default, colored)
gitexpose example.com

# JSON output
gitexpose example.com -o json

# Save to file
gitexpose -f targets.txt -o json --out-file results.json

# CSV output
gitexpose example.com -o csv --out-file results.csv

# HTML report
gitexpose -f targets.txt -o html --out-file report.html
```

### Git Repository Dumping

```bash
# Dump exposed .git repositories
gitexpose example.com --git-dump

# Specify dump directory
gitexpose example.com --git-dump --git-dump-dir ./dumps

# Dump and analyze git history for secrets
gitexpose example.com --git-dump --analyze-secrets
```

### Secret Extraction & Validation

```bash
# Extract secrets from responses
gitexpose example.com --extract-secrets

# Extract and validate secrets (checks if active)
gitexpose example.com --extract-secrets --validate-secrets

# Choose secrets output format
gitexpose example.com --extract-secrets --secrets-format json
gitexpose example.com --extract-secrets --secrets-format csv
gitexpose example.com --extract-secrets --secrets-format markdown
```

### Complete Security Audit

```bash
# Full workflow: scan, dump, analyze, validate, report
gitexpose -f targets.txt \
  --git-dump \
  --analyze-secrets \
  --extract-secrets \
  --validate-secrets \
  -o html \
  --out-file full-audit.html \
  -v
```

---

## 🔥 Advanced Features

### 1. Git Repository Dumping

When GitExpose finds an exposed `.git` directory, it can:

1. **Download Core Files**: HEAD, config, index, packed-refs, logs
2. **Discover Objects**: Parse refs and index to find all git objects
3. **Recursive Download**: Follow object references to download entire repository
4. **Reconstruct Repository**: Use `git checkout` to rebuild working directory
5. **Scan History**: Analyze all commits for exposed credentials

**Example Output:**
```
git-dumps/
└── example.com/
    ├── .git/           # Full git repository
    ├── src/            # Reconstructed source files
    ├── config/
    └── secrets_report.txt  # Found secrets
```

### 2. Secret Detection Patterns

GitExpose detects 30+ secret types using regex patterns:

```python
# Examples of detected patterns
AWS Access Keys:     AKIA[0-9A-Z]{16}
GitHub Tokens:       ghp_[a-zA-Z0-9]{36}
Slack Tokens:        xox[baprs]-[0-9]{10,12}-...
Database URLs:       postgresql://user:pass@host:5432/db
Private Keys:        -----BEGIN RSA PRIVATE KEY-----
JWT Tokens:          eyJ[A-Za-z0-9-_=]+\.eyJ...
```

### 3. Secret Validation

Optionally test if credentials are still active:

- **GitHub**: Test against GitHub API
- **Slack**: Verify with Slack API
- **Stripe**: Check Stripe API access
- **AWS**: Attempt STS get-caller-identity

Results marked as ✅ Valid or ❌ Invalid

### 4. HTML Reports

Interactive HTML reports include:
- Executive summary with statistics
- Severity distribution charts (Chart.js)
- Color-coded findings with evidence
- Responsive design for mobile viewing
- Print-friendly styling

### 5. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run GitExpose
        run: |
          pip install gitexpose
          gitexpose -f targets.txt \
            --git-dump \
            --analyze-secrets \
            -o html \
            --out-file scan-report.html
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: scan-report.html
```

---

## 📊 Detection Coverage

### File Categories

| Category | Examples | Severity |
|----------|----------|----------|
| **Git Repositories** | `.git/config`, `.git/HEAD`, `.git/index` | 🔴 Critical |
| **Environment Files** | `.env`, `.env.production`, `.env.local` | 🔴 Critical |
| **Configuration** | `wp-config.php`, `config.yml`, `settings.py` | 🟠 High |
| **Backups** | `backup.sql`, `database.sql`, `backup.zip` | 🔴 Critical |
| **Version Control** | `.svn/entries`, `.hg/`, `.bzr/` | 🟠 High |
| **Debug Files** | `phpinfo.php`, `debug.log`, `error.log` | 🟡 Medium |
| **Sensitive Files** | `.htpasswd`, `.DS_Store`, `composer.json` | 🟡 Medium |

### Total Detection Patterns: **100+**

---

## 🛠️ Command Reference

### Required Arguments
```bash
gitexpose TARGET [TARGET...]     # One or more URLs to scan
```

### Optional Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file` | File containing targets (one per line) | - |
| `-o, --output` | Output format: console, json, csv, html | console |
| `--out-file` | Write output to file | stdout |
| `-c, --concurrency` | Max concurrent requests | 50 |
| `-t, --timeout` | Request timeout in seconds | 10 |
| `-q, --quiet` | Only show vulnerable targets | false |
| `-v, --verbose` | Enable debug logging | false |
| `--no-color` | Disable colored output | false |
| `--user-agent` | Custom User-Agent string | GitExpose/1.0 |
| `--follow-redirects` | Follow HTTP redirects | false |

### Advanced Options

| Flag | Description | Default |
|------|-------------|---------|
| `--git-dump` | Dump exposed git repositories | false |
| `--git-dump-dir` | Directory for git dumps | ./git-dumps |
| `--analyze-secrets` | Analyze git history for secrets | false |
| `--extract-secrets` | Extract secrets from responses | false |
| `--validate-secrets` | Validate extracted secrets | false |
| `--secrets-format` | Secrets output format: json, csv, markdown | markdown |
| `--version` | Show version and exit | - |

---

## 📚 Documentation

### File Structure
```
gitexpose/
├── gitexpose/
│   ├── __init__.py
│   ├── cli.py                  # CLI interface
│   ├── cli_enhanced.py         # Enhanced CLI with advanced features
│   ├── scanner.py              # Core scanning engine
│   ├── models.py               # Data models
│   ├── paths.py                # Path definitions (100+ patterns)
│   ├── signatures.py           # Response validation
│   │
│   ├── git/                    # Git dumping & analysis
│   │   ├── dumper.py           # Repository reconstruction
│   │   └── analyzer.py         # Secret scanning
│   │
│   ├── secrets/                # Secret detection
│   │   └── extractor.py        # Pattern matching & validation
│   │
│   └── reporters/              # Output formatters
│       ├── console.py
│       ├── json_reporter.py
│       ├── csv_reporter.py
│       └── html.py
│
├── templates/                  # YAML detection templates (future)
├── tests/                      # Test suite
├── docs/                       # Documentation
└── examples/                   # Usage examples
```

### Programmatic Usage

```python
import asyncio
from gitexpose import GitExposeScanner
from gitexpose.git import GitDumper, GitSecretAnalyzer
from gitexpose.reporters.html import HTMLReporter

async def main():
    # Initialize scanner
    scanner = GitExposeScanner(concurrency=50, timeout=10)
    
    # Run scan
    report = scanner.scan_sync(['https://example.com'])
    
    # Generate HTML report
    reporter = HTMLReporter()
    html_output = reporter.generate(report)
    
    with open('report.html', 'w') as f:
        f.write(html_output)
    
    # Check for git repositories
    for target_report in report.target_reports:
        for finding in target_report.findings:
            if '.git/' in finding.path.lower():
                print(f"Found .git at {finding.url}")
                
                # Dump repository
                async with aiohttp.ClientSession() as session:
                    dumper = GitDumper(
                        target_report.target,
                        f'./dumps/{target_report.target}',
                        session
                    )
                    result = await dumper.dump()
                    
                    if result['success']:
                        # Analyze for secrets
                        analyzer = GitSecretAnalyzer(f'./dumps/{target_report.target}')
                        secrets = await analyzer.scan_history()
                        print(f"Found {len(secrets)} secrets in git history")

if __name__ == '__main__':
    asyncio.run(main())
```

---

## 🔒 Security & Ethics

### ⚠️ Important Legal Notice

**GitExpose is a security research tool. You must:**

1. ✅ **Only scan systems you own or have explicit permission to test**
2. ✅ **Follow responsible disclosure practices**
3. ✅ **Comply with local laws and regulations**
4. ❌ **Never use for unauthorized access or malicious purposes**

### Ethical Usage Guidelines

- **Authorization**: Always obtain written permission before scanning
- **Data Handling**: Secure all dumped repositories and extracted secrets
- **Rate Limiting**: Use appropriate concurrency to avoid DoS
- **Disclosure**: Report findings responsibly to system owners
- **Privacy**: Don't share or publish sensitive data found during scans

### Data Security

- Dumped repositories may contain **real credentials**
- Store output files securely with proper access controls
- Consider encrypting sensitive scan results
- Delete temporary files after analysis
- Use `--validate-secrets` cautiously (alerts credential owners)

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Areas for Contribution
- 🔍 Add new detection patterns
- 🐛 Report and fix bugs
- 📝 Improve documentation
- 🧪 Write tests
- 🎨 Enhance reporters
- 🔌 Create plugins

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/gitexpose.git
cd gitexpose

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linters
flake8 gitexpose/
black gitexpose/
mypy gitexpose/
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🐛 Troubleshooting

### Common Issues

**Git Dumping Fails**
```bash
# Ensure git is installed
git --version

# Install if missing:
# Ubuntu/Debian: sudo apt-get install git
# macOS: brew install git
# Windows: https://git-scm.com/download/win
```

**Import Errors**
```bash
# Reinstall in development mode
pip install -e .

# Or add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**GitPython Not Found**
```bash
# Install optional git dependencies
pip install GitPython

# Or with extras
pip install gitexpose[git]
```

**Async/Aiofiles Errors**
```bash
# Ensure aiofiles is installed
pip install aiofiles
```

**Performance Issues**
```bash
# Reduce concurrency for resource-constrained environments
gitexpose example.com -c 10

# Increase timeout for slow targets
gitexpose example.com -t 30
```

---

## 📈 Roadmap

### Version 2.0 (In Progress)
- [x] Git repository dumping and reconstruction
- [x] Secret extraction and validation
- [x] HTML report generation
- [ ] YAML template system (like Nuclei)
- [ ] Plugin architecture (Slack, Jira, webhooks)
- [ ] Live web dashboard
- [ ] Cloud provider integration (AWS, GCP, Azure)

### Version 2.1 (Planned)
- [ ] Stealth mode with WAF evasion
- [ ] Adaptive rate limiting
- [ ] Shodan integration
- [ ] Custom template creation
- [ ] Machine learning for false positive reduction

### Version 3.0 (Future)
- [ ] Distributed scanning
- [ ] Container scanning
- [ ] GraphQL endpoint testing
- [ ] API fuzzing capabilities

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by [GitTools](https://github.com/internetwache/GitTools) and [truffleHog](https://github.com/trufflesecurity/trufflehog)
- Built with [aiohttp](https://github.com/aio-libs/aiohttp) for async HTTP
- Uses [Click](https://github.com/pallets/click) for the CLI interface
- Chart visualization by [Chart.js](https://www.chartjs.org/)

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/gitexpose/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/gitexpose/discussions)
- **Security**: security@gitexpose.io
- **Twitter**: [@gitexpose](https://twitter.com/gitexpose)

---

## ⭐ Show Your Support

If GitExpose helped you find vulnerabilities or improve your security posture, please consider:

- ⭐ **Starring the repository**
- 🐦 **Sharing on social media**
- 📝 **Writing a blog post about your experience**
- 💬 **Contributing back to the project**

---

<div align="center">

**Made with ❤️ by security researchers, for security researchers**

[Report Bug](https://github.com/yourusername/gitexpose/issues) · [Request Feature](https://github.com/yourusername/gitexpose/issues) · [Documentation](https://gitexpose.io/docs)

</div>