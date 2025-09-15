# Complyr - NIST RMF/ATO Compliance Scanner

## Project Overview

Complyr is a Go-based command-line tool that performs automated compliance scanning for code repositories against NIST RMF (Risk Management Framework) controls. It helps prepare projects for ATO (Authority to Operate) certification by assessing technical implementation of NIST 800-53 controls based on the project's Technology Readiness Level (TRL).

## Key Features

- **TRL-Based Assessment**: Adjusts compliance requirements based on project maturity (TRL 1-9)
- **Official OSCAL Integration**: Loads controls from NIST's official OSCAL catalog (oscal-content repository)
- **Software-Focused Controls**: Automatically filters to only assess software-relevant controls (~50 out of 1000+ total)
- **NIST 800-53B Baselines**: Maps TRL levels to appropriate impact baselines (Low/Moderate/High)
- **Dependency Scanning**: Analyzes project dependencies across multiple languages (JavaScript, Python, Java, Go, Rust)
- **Concurrent Vulnerability Detection**: Uses worker pools to check CVEs via GitHub Security Advisory API
- **Banned Technology Detection**: Identifies prohibited technologies and frameworks
- **OSCAL Document Export**: Generates compliant assessment-results, findings, and POAM documents
- **Multi-Language Support**: Works with Node.js, Python, Java, Go, and Rust projects
- **Error Recovery**: Continues operation with warnings instead of failing on partial errors

## Architecture

### Directory Structure
```
complyr/
├── cmd/                    # CLI commands
│   ├── root.go            # Base command setup
│   ├── init.go            # Project initialization command
│   └── scan.go            # Scanning command
├── internal/              # Internal packages
│   ├── core/              # Core business logic
│   │   ├── types.go       # Type definitions
│   │   ├── controls.go    # NIST control definitions (legacy + TRL mapping)
│   │   ├── oscal.go       # OSCAL document generation
│   │   ├── oscal_catalog.go # Official NIST catalog integration
│   │   ├── errors.go      # Enhanced error handling and recovery
│   │   └── assessment.go  # Compliance assessment logic
│   └── scanners/          # Scanning implementations
│       ├── scanner.go     # Main scanning orchestration with concurrency
│       ├── dependencies.go # Dependency parsing (buffered I/O)
│       └── vulnerabilities.go # CVE scanning (worker pools)
├── pkg/                   # Public packages
│   └── output/            # Output formatting
│       └── display.go     # Result display logic
├── main.go                # Entry point
├── go.mod                 # Go module definition
└── .complyr.yaml         # Project configuration
```

### Core Components

1. **TRL (Technology Readiness Level) System**
   - TRL 1-2: Basic Research
   - TRL 3-4: Proof of Concept
   - TRL 5-6: System Validation
   - TRL 7-8: Prototype Testing
   - TRL 9: Production Ready

2. **Official OSCAL Catalog Integration**
   - **Source**: https://github.com/usnistgov/oscal-content/blob/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
   - **Caching**: Downloads and caches catalog locally (.oscal-cache.json, 7-day refresh)
   - **Software Filter**: Automatically filters to ~50 software-relevant controls from 1000+ total
   - **Baseline Mapping**: Maps TRL levels to NIST 800-53B baselines (Low/Moderate/High impact)

3. **Software-Relevant Controls Assessed**
   - **Access Control (AC)**: AC-2, AC-3, AC-6, AC-17, AC-25
   - **Audit (AU)**: AU-2, AU-3, AU-4, AU-8, AU-9, AU-10
   - **Configuration Management (CM)**: CM-2, CM-4, CM-6, CM-7, CM-8, CM-11
   - **Identity & Authentication (IA)**: IA-2, IA-5, IA-7, IA-8, IA-9
   - **Risk Assessment (RA)**: RA-5
   - **System Acquisition (SA)**: SA-10, SA-11, SA-15, SA-22
   - **System Protection (SC)**: SC-8, SC-12, SC-13, SC-23, SC-28
   - **System Integrity (SI)**: SI-2, SI-3, SI-4, SI-7, SI-10, SI-11, SI-16
   - **Supply Chain (SR)**: SR-3, SR-4, SR-5

4. **Supported Project Types**
   - Node.js (package.json)
   - Python (requirements.txt, Pipfile)
   - Java (pom.xml)
   - Go (go.mod)
   - Rust (Cargo.toml)

## Key Commands

### Initialize Project
```bash
complyr init
```
Creates `.complyr.yaml` with TRL, contract type, and customer configuration.

### Run Compliance Scan
```bash
complyr scan [path]
# or just
complyr
```
Options:
- `-j, --json`: Output results in JSON format
- `-v, --verbose`: Enable verbose output
- `--oscal <file>`: Export OSCAL assessment-results document to specified file

## Configuration

The `.complyr.yaml` file stores project-specific compliance settings:
```yaml
project:
  trl: 3              # Technology Readiness Level (1-9)
  contract_type: "Phase I SBIR"  # Contract type
  customer: "Navy"    # Optional customer specification
```

## Scanning Process

1. **Project Detection**: Identifies project type and language, reads `.complyr.yaml` configuration
2. **OSCAL Catalog Loading**: Downloads/caches official NIST 800-53 catalog, filters to software-relevant controls
3. **Dependency Parsing**: Extracts all project dependencies with buffered I/O and error recovery
4. **Concurrent Security Scanning**:
   - **Banned Technology Detection**: Runs in parallel to check prohibited libraries (e.g., deepseek, qwen)
   - **CVE Vulnerability Scanning**: Uses 3-worker pool to query GitHub Security Advisory API
5. **TRL-Aware Control Assessment**:
   - Maps TRL to appropriate NIST 800-53B baseline (Low/Moderate/High impact)
   - Evaluates ~50 software-relevant controls based on detected libraries and frameworks
6. **OSCAL Document Generation**: Creates standards-compliant assessment-results, findings, and POAM
7. **Report Generation**: Produces TRL-specific compliance report with next-step recommendations

## Security Features

- **Banned Technologies**: Maintains list of prohibited AI models and vulnerable frameworks
- **Library Detection**: Identifies security-relevant libraries (auth, crypto, logging, monitoring)
- **TRL-Aware Controls**: Applies appropriate controls based on project maturity
- **Vulnerability Scoring**: Uses CVSS scores for vulnerability prioritization

## Development Guidelines

### Adding New Languages
1. Add detection logic in `detectProjectType()` (scanner.go:99)
2. Implement dependency parser in `dependencies.go`
3. Map to ecosystem in `getEcosystem()` (vulnerabilities.go:68)

### Adding New Controls
1. Define control in `GetNISTControls()` (controls.go:28)
2. Add assessment logic in `assessControl()` (assessment.go:78)
3. Update TRL mappings in `TRLControls` (controls.go:146)

### Adding Banned Technologies
Update `GetBannedTechnologies()` in controls.go:229 with new entries.

## Testing

Run the scanner on test projects:
```bash
# Test on current directory
complyr scan

# Test with verbose output
complyr scan -v

# Test with JSON output
complyr scan -j
```

## Build Instructions

```bash
# Build for current platform
go build -o complyr

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o complyr.exe

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o complyr

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o complyr
```

## Dependencies

- **cobra**: CLI framework
- **survey/v2**: Interactive prompts
- **yaml.v3**: YAML parsing

## Environment Variables

- `GITHUB_TOKEN`: Optional GitHub token for increased API rate limits

## Exit Codes

- `0`: Success, no issues found
- `1`: High severity issues found
- `2`: Critical severity issues found

## Common Issues & Solutions

1. **CVE Scanning Rate Limits**: Set `GITHUB_TOKEN` environment variable
2. **Unknown Project Type**: Ensure proper config files (package.json, go.mod, etc.) exist
3. **No Dependencies Found**: Check that dependency files are properly formatted

## Future Enhancements

- [ ] Support for more languages (C#, Ruby, PHP)
- [ ] Integration with CI/CD pipelines
- [ ] Custom control definitions
- [ ] SBOM (Software Bill of Materials) generation
- [ ] Integration with vulnerability databases beyond GitHub
- [ ] Remediation suggestions and auto-fix capabilities