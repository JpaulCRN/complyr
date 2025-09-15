# Complyr - NIST RMF/ATO Compliance Scanner

<p align="center">
  <img src="https://img.shields.io/badge/NIST-800--53-blue" alt="NIST 800-53">
  <img src="https://img.shields.io/badge/OSCAL-Compatible-green" alt="OSCAL Compatible">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

<p align="center">
  <strong>🔒 Automated NIST 800-53 compliance scanning for modern software projects</strong>
</p>

<p align="center">
  Complyr bridges the gap between development and compliance, automatically assessing your codebase against NIST RMF controls based on Technology Readiness Level (TRL).
</p>

---

## 🚀 Features

- **🎯 TRL-Based Assessment**: Dynamically adjusts compliance requirements based on project maturity (TRL 1-9)
- **📋 Official OSCAL Integration**: Uses NIST's official control catalog from [oscal-content](https://github.com/usnistgov/oscal-content)
- **🔍 Smart Control Filtering**: Automatically focuses on ~50 software-relevant controls from 1000+ total
- **⚡ Concurrent Scanning**: 3x faster vulnerability detection with worker pools
- **🛡️ Multi-Language Support**: Works with Node.js, Python, Java, Go, and Rust projects
- **📊 OSCAL Document Export**: Generates standards-compliant assessment results and POAM documents
- **🚫 Banned Technology Detection**: Identifies prohibited frameworks and vulnerable dependencies
- **🔄 CVE Vulnerability Scanning**: Real-time checks against GitHub Security Advisory Database
- **💪 Robust Error Recovery**: Continues operation with warnings instead of failing completely

## 📦 Installation

### Pre-built Binaries

Download the latest release for your platform:

```bash
# macOS/Linux
curl -L https://github.com/yourusername/complyr/releases/latest/download/complyr-$(uname -s)-$(uname -m) -o complyr
chmod +x complyr
sudo mv complyr /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/yourusername/complyr/releases/latest/download/complyr.exe -OutFile complyr.exe
```

### Build from Source

```bash
# Requires Go 1.21+
git clone https://github.com/yourusername/complyr.git
cd complyr
go build -o complyr

# Install globally
sudo mv complyr /usr/local/bin/  # macOS/Linux
# or add to PATH on Windows
```

## 🎯 Quick Start

### 1. Initialize Your Project

```bash
complyr init
```

This creates `.complyr.yaml` with your project configuration:

```yaml
project:
  trl: 3              # Technology Readiness Level (1-9)
  contract_type: "Phase I SBIR"  # Contract type
  customer: "Navy"    # Optional customer specification
```

### 2. Run Compliance Scan

```bash
# Scan current directory
complyr scan

# Scan specific path
complyr scan /path/to/project

# Export OSCAL document
complyr scan --oscal assessment-results.json

# Verbose output with remediation guidance
complyr scan --verbose
```

## 📊 Understanding TRL Levels

| TRL | Stage | Description | NIST Baseline | Required Controls |
|-----|-------|-------------|---------------|-------------------|
| **1-2** | Basic Research | Concept development | None | SI-2 (vulnerability scanning) |
| **3** | Proof of Concept | Early prototype | Low | SI-2, SI-3, CM-2 |
| **4-6** | System Validation | Testing & refinement | Moderate | +AU-2, AC-3, IA-2, SC-13 |
| **7-8** | Prototype Testing | Pre-production | High | +SC-8, SI-4, IA-5, CM-4 |
| **9** | Production Ready | Operational system | High+ | All software controls |

## 🔍 What Gets Scanned

### Supported Project Types

- **Node.js**: `package.json`, `package-lock.json`
- **Python**: `requirements.txt`, `Pipfile`
- **Java**: `pom.xml`
- **Go**: `go.mod`
- **Rust**: `Cargo.toml`

### Security Checks Performed

1. **Dependency Analysis**
   - Extracts all project dependencies
   - Maps to security-relevant libraries
   - Identifies authentication, crypto, logging frameworks

2. **Banned Technology Detection**
   - Prohibited AI models (deepseek, qwen)
   - Vulnerable frameworks (jQuery < 3.5)
   - Deprecated security libraries

3. **CVE Vulnerability Scanning**
   - Real-time GitHub Security Advisory checks
   - CVSS scoring and severity mapping
   - Automatic POAM generation for critical issues

4. **NIST Control Assessment**
   - ~50 software-relevant controls evaluated
   - Maps findings to specific control violations
   - Provides remediation recommendations

## 📋 NIST 800-53 Controls Assessed

### Core Security Families

| Family | Controls | Focus Area |
|--------|----------|------------|
| **AC** (Access Control) | AC-2, AC-3, AC-6, AC-17 | Authentication & authorization |
| **AU** (Audit) | AU-2, AU-3, AU-8, AU-9 | Logging & monitoring |
| **CM** (Configuration) | CM-2, CM-4, CM-6, CM-7 | Baseline & change management |
| **IA** (Identity) | IA-2, IA-5, IA-8, IA-9 | User authentication |
| **SC** (System Protection) | SC-8, SC-13, SC-23, SC-28 | Cryptography & transmission |
| **SI** (System Integrity) | SI-2, SI-3, SI-4, SI-7, SI-10 | Vulnerabilities & monitoring |
| **SA** (Acquisition) | SA-11, SA-15, SA-22 | Secure development |
| **SR** (Supply Chain) | SR-3, SR-4, SR-5 | Third-party risk |

## 🔄 OSCAL Integration

Complyr generates OSCAL-compliant documents following the [NIST OSCAL standard](https://pages.nist.gov/OSCAL/):

```bash
# Generate OSCAL assessment results
complyr scan --oscal assessment.json

# Output includes:
# - Assessment Results (control evaluations)
# - Findings (vulnerabilities and violations)
# - Plan of Action & Milestones (remediation tasks)
```

### OSCAL Document Structure

```json
{
  "assessment-results": {
    "uuid": "complyr-generated-uuid",
    "metadata": {
      "title": "Complyr Assessment Results",
      "oscal-version": "1.0.4"
    },
    "results": [...],     // Control assessments
    "findings": [...],    // Issues discovered
    "poam-items": [...]   // Remediation plan
  }
}
```

## 🛠️ Configuration

### Project Configuration (`.complyr.yaml`)

```yaml
project:
  trl: 5                    # Technology Readiness Level
  contract_type: "Phase II SBIR"  # Contract type
  customer: "DISA"          # Customer/sponsor
```

### Environment Variables

```bash
# GitHub token for increased API rate limits
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Custom OSCAL catalog location (optional)
export OSCAL_CATALOG_URL=https://your-oscal-catalog.json
```

## 📈 Example Output

```
 ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗  ██╗   ██╗██████╗
██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║  ╚██╗ ██╔╝██╔══██╗
██║     ██║   ██║██╔████╔██║██████╔╝██║   ╚████╔╝ ██████╔╝
                    by Colvin Run
                    NIST RMF Compliance Scanner

📁 Project: Node.js (JavaScript) | TRL 5 | Phase II SBIR
📍 Path: /Users/demo/my-app
📦 Dependencies analyzed: 142

📊 COMPLIANCE STATUS
   Stage: TRL 5 - System Validation
   Required Controls: 8 of 12 satisfied
   🎯 Current TRL Compliance: 66.7%
   [████████████████████░░░░░░░░░]

🚨 ISSUES FOUND
   🔴 Critical: 2 (Banned technology: deepseek)
   🟠 High: 3 (CVE-2024-1234 in lodash@4.17.19)
   🟡 Medium: 5

📋 TRL 5 REQUIREMENTS (12 controls)
   ❌ NOT SATISFIED (4 controls)
   ❌ AU-2: Event Logging
      📝 No logging libraries detected
      💡 Quick fix: npm install winston or pino

   ✅ SATISFIED (8 controls)
   ✅ SI-2: Flaw Remediation
   ✅ CM-2: Baseline Configuration
   ✅ IA-2: User Authentication
```

## 🔧 Advanced Usage

### Custom Control Baselines

```go
// Add to internal/core/controls.go
var CustomBaseline = map[string][]string{
    "fedramp-low": {"AC-2", "AC-3", "AU-2", "CM-2", "IA-2"},
    "dod-il4": {"AC-2", "AC-3", "AC-6", "AU-2", "AU-3", "CM-4"},
}
```

### Integrating with CI/CD

```yaml
# GitHub Actions example
name: Compliance Scan
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Complyr
        run: |
          curl -L https://github.com/yourusername/complyr/releases/latest/download/complyr-linux-amd64 -o complyr
          chmod +x complyr

      - name: Run Compliance Scan
        run: |
          ./complyr scan --oscal results.json

      - name: Upload OSCAL Results
        uses: actions/upload-artifact@v3
        with:
          name: oscal-assessment
          path: results.json

      - name: Check Compliance
        run: |
          # Fail if critical issues found
          ./complyr scan --json | jq -e '.Summary.CriticalIssues == 0'
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/complyr.git
cd complyr

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o complyr

# Run locally
./complyr scan .
```

## 📊 Performance

- **Concurrent Scanning**: 3 worker pools for parallel CVE checks
- **Efficient I/O**: Buffered file reading for large dependency files
- **Smart Caching**: 7-day cache for OSCAL catalog (2.7MB)
- **Typical Scan Time**: 2-5 seconds for 100+ dependencies

## 🔒 Security

Complyr is designed with security in mind:

- Never stores credentials or tokens
- Read-only file system access
- Validates all inputs and package names
- Uses official NIST control definitions
- Rate-limited API calls with exponential backoff

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [NIST](https://www.nist.gov/) for the OSCAL standard and control catalog
- [GitHub Security Advisory Database](https://github.com/advisories) for vulnerability data
- [Colvin Run Networks](https://colvinrun.com) for sponsoring development

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/complyr/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/complyr/discussions)
- **Email**: support@colvinrun.com

## 🗺️ Roadmap

- [ ] FedRAMP baseline support
- [ ] SBOM (Software Bill of Materials) generation
- [ ] Container image scanning
- [ ] Infrastructure as Code (Terraform/CloudFormation) scanning
- [ ] Auto-remediation suggestions with code fixes
- [ ] Web UI dashboard
- [ ] Integration with GRC platforms

---

<p align="center">
  Made with ❤️ by <a href="https://colvinrun.com">Colvin Run Networks</a>
</p>

<p align="center">
  <strong>Simplifying compliance for modern software teams</strong>
</p>