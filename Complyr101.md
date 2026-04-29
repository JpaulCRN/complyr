# Complyr 101: Automated ATO/RMF Compliance for Software Projects

## What is Complyr?

Complyr is a command-line tool that automates compliance assessment for software projects against NIST Risk Management Framework (RMF) requirements. It bridges the gap between software development and the Authority to Operate (ATO) certification process by providing immediate, actionable feedback on your project's security posture.

## The Problem Complyr Solves

Obtaining an ATO is one of the most challenging aspects of deploying software in federal environments. The traditional process involves:

- **Manual documentation** of hundreds of NIST 800-53 controls
- **Lengthy review cycles** that can take months or years
- **Expensive consultants** to interpret requirements
- **Late-stage surprises** when security gaps are discovered during assessment
- **Repeated rework** when compliance issues surface after development is complete

For SBIR/STTR contractors and commercial software vendors entering the federal space, this process is often opaque, expensive, and frustrating.

---

## How Scanning Works

Complyr performs a multi-phase scan of your codebase:

### Phase 1: Project Detection & Dependency Discovery

1. **Reads `.complyr.yaml`** to determine TRL level and contract context
2. **Detects project type** by looking for manifest files (package.json, go.mod, requirements.txt, etc.)
3. **Identifies monorepo/workspace structures** (Turborepo, npm/pnpm/yarn workspaces, Go workspaces, Cargo workspaces)
4. **Recursively walks the directory tree** to find all dependency manifest files, skipping common non-source directories (node_modules, vendor, .git, dist, build, etc.)

### Phase 2: Dependency Parsing

Complyr parses dependencies from multiple file formats:

| Language | Manifest Files |
|----------|----------------|
| JavaScript/Node.js | package.json |
| Python | requirements.txt, pyproject.toml, Pipfile |
| Go | go.mod |
| Java | pom.xml |
| Rust | Cargo.toml |

Dependencies are extracted with version information and tagged by subproject location for monorepo support.

### Phase 3: Concurrent Security Scanning

Two scans run in parallel using Go's concurrency:

**Banned Technology Detection**: Checks all dependencies against a maintained list of prohibited technologies (e.g., certain AI models, vulnerable frameworks).

**CVE Vulnerability Scanning**: Uses a 3-worker pool to batch-query the GitHub Security Advisory API for known vulnerabilities.

### Phase 4: TRL-Aware Control Assessment

Based on your declared TRL, Complyr maps to the appropriate NIST 800-53B baseline (Low/Moderate/High impact) and evaluates ~50 software-relevant controls based on detected libraries and frameworks.

---

## CVE Detection

Complyr uses the **GitHub Security Advisory REST API** to identify known vulnerabilities in your dependencies.

### How It Works

1. **Ecosystem Mapping**: Your project's language is mapped to a GitHub ecosystem (npm, pip, maven, go, crates.io, etc.)

2. **Batched Queries**: Dependencies are grouped into batches of 5 and processed by a pool of 3 concurrent workers with 200ms rate limiting between requests

3. **API Request**: For each dependency, Complyr queries:
   ```
   GET https://api.github.com/advisories?ecosystem={eco}&affects={package}&per_page=5
   ```

4. **Relevance Filtering**: Results are filtered to focus on actionable vulnerabilities:
   - CVEs from 2020 or newer (filters out very old CVEs unlikely to affect current versions)
   - HIGH and CRITICAL severity always included
   - MEDIUM severity from 2023+ included
   - LOW severity only if from 2024+
   - All GHSA (GitHub Security Advisory) IDs included

5. **Control Mapping**: Each CVE is mapped to NIST control **SI-2 (Flaw Remediation)** with severity, description, and remediation guidance

### Authentication

Set `GITHUB_TOKEN` environment variable for higher API rate limits. Unauthenticated requests are limited to 60/hour; authenticated requests get 5,000/hour.

---

## OSCAL Integration

Complyr generates documents in **OSCAL (Open Security Controls Assessment Language)** format, the NIST standard for machine-readable security assessments.

### Official NIST Catalog Integration

Complyr downloads and caches the official NIST 800-53 Rev 5 catalog directly from the OSCAL-content repository:

```
https://github.com/usnistgov/oscal-content/.../NIST_SP-800-53_rev5_catalog.json
```

- **Local caching**: Stored in `.oscal-cache.json` with a 7-day refresh cycle
- **Software filtering**: Automatically filters 1000+ total controls down to ~50 software-relevant ones
- **Fallback**: If the fetch fails, falls back to embedded control definitions

### Generated Documents

When you run `complyr scan --oscal output.json`, Complyr generates:

**Assessment Results**
- UUID-identified assessment with OSCAL 1.0.4 compliance
- Control-by-control assessment status (satisfied, not-satisfied, pending, not-applicable)
- Evidence collection with finding counts
- Timestamp and party metadata

**Findings**
- Each banned technology and CVE becomes a formal finding
- Mapped to related NIST controls
- Includes severity, description, and remediation tracking

**Plan of Action and Milestones (POA&M)**
- Auto-generated for HIGH and CRITICAL severity issues
- 30-day default due date
- Assigned to "development-team" as responsible party
- Linked to specific control IDs

### TRL to Impact Level Mapping

| TRL | Impact Level | Control Count |
|-----|--------------|---------------|
| 1-3 | Low | ~10 controls |
| 4-6 | Moderate | ~23 controls |
| 7-9 | High | ~38 controls |

---

## Technology Stack

Complyr is built with a minimal, focused set of dependencies:

### Core Language
- **Go 1.21** - Compiled binary, no runtime dependencies, cross-platform

### Direct Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework for commands and flags |
| `github.com/AlecAivazis/survey/v2` | Interactive terminal prompts for `complyr init` |
| `gopkg.in/yaml.v3` | YAML parsing for `.complyr.yaml` config |

### Standard Library Usage
- `encoding/json` - JSON parsing for package.json, OSCAL catalogs, API responses
- `encoding/xml` - XML parsing for Maven pom.xml files
- `net/http` - HTTP client for GitHub API and OSCAL catalog fetching
- `sync` - WaitGroups and concurrency primitives for parallel scanning
- `context` - Request cancellation and timeouts
- `path/filepath` - Cross-platform file path handling
- `bufio` - Buffered I/O for efficient file reading

### External APIs
- **GitHub Security Advisory API** - CVE/vulnerability data (REST API, no auth required but rate-limited)
- **NIST OSCAL Content Repository** - Official control catalog (raw GitHub content)

### Build Output
Single static binary, no external dependencies at runtime. Cross-compiles to Windows, Linux, and macOS.

---

## Getting Started

```bash
# Initialize your project with TRL and contract information
complyr init

# Run a compliance scan
complyr scan

# Generate OSCAL documentation
complyr scan --oscal assessment-results.json

# Verbose output for detailed findings
complyr scan -v
```

## Who Benefits from Complyr

- **SBIR/STTR Contractors** preparing for Phase II or Phase III transitions
- **Defense Contractors** building software for DoD systems
- **Federal Software Vendors** seeking FedRAMP or agency ATOs
- **System Integrators** managing compliance across multiple components
- **Security Teams** looking to automate compliance monitoring

## The Bottom Line

Complyr transforms ATO preparation from a documentation exercise into a technical practice. By automating the assessment of software-relevant controls and generating standards-compliant documentation, it helps development teams:

- **Understand their compliance posture** at any point in development
- **Address gaps proactively** before formal assessment
- **Generate required documentation** automatically
- **Maintain compliance** as the project evolves

The result: faster ATOs, lower costs, and more secure software.
