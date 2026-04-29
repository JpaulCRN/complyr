package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JpaulCRN/complyr/internal/core"
)

// semverPart represents a parsed semantic version
type semverPart struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Valid      bool
}

// parseSemver parses a version string into components
// Handles formats like: 1.2.3, ^1.2.3, ~1.2.3, >=1.2.3, 1.2.3-beta.1
func parseSemver(version string) semverPart {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimSpace(version)

	if version == "" || version == "*" {
		return semverPart{Valid: false}
	}

	// Split prerelease suffix
	prerelease := ""
	if idx := strings.Index(version, "-"); idx != -1 {
		prerelease = version[idx+1:]
		version = version[:idx]
	}

	// Also handle + for build metadata
	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}

	parts := strings.Split(version, ".")
	if len(parts) < 1 {
		return semverPart{Valid: false}
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semverPart{Valid: false}
	}

	minor := 0
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}

	patch := 0
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}

	return semverPart{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Valid:      true,
	}
}

// compareSemver compares two versions
// Returns: -1 if a < b, 0 if a == b, 1 if a > b
func compareSemver(a, b semverPart) int {
	if !a.Valid || !b.Valid {
		return 0
	}

	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}

	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}

	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}

	// Prerelease versions have lower precedence than normal versions
	if a.Prerelease != "" && b.Prerelease == "" {
		return -1
	}
	if a.Prerelease == "" && b.Prerelease != "" {
		return 1
	}

	return 0
}

// isVersionInRange checks if a version falls within a vulnerable range
// Range format examples: ">= 5.2.6, <= 5.4.20", "< 4.17.21", ">= 1.0.0, < 2.0.0"
//
// Returns false when the installed version can't be parsed (callers are
// expected to detect unparseable versions up-front via parseSemver and
// surface them to the user via recordUnparseableVersion — flagging every
// advisory as a hit produces noise on git-pinned and tag-pinned deps).
func isVersionInRange(installedVersion string, vulnerableRange string) bool {
	installed := parseSemver(installedVersion)
	if !installed.Valid {
		return false
	}

	// Handle empty range
	if vulnerableRange == "" {
		return false
	}

	// Split on comma for compound ranges like ">= 5.2.6, <= 5.4.20"
	conditions := strings.Split(vulnerableRange, ",")

	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}

		if !checkCondition(installed, cond) {
			return false
		}
	}

	return true
}

// checkCondition checks a single version condition
func checkCondition(installed semverPart, condition string) bool {
	condition = strings.TrimSpace(condition)

	// Parse the operator and version from the condition
	var operator string
	var versionStr string

	if strings.HasPrefix(condition, ">=") {
		operator = ">="
		versionStr = strings.TrimPrefix(condition, ">=")
	} else if strings.HasPrefix(condition, "<=") {
		operator = "<="
		versionStr = strings.TrimPrefix(condition, "<=")
	} else if strings.HasPrefix(condition, ">") {
		operator = ">"
		versionStr = strings.TrimPrefix(condition, ">")
	} else if strings.HasPrefix(condition, "<") {
		operator = "<"
		versionStr = strings.TrimPrefix(condition, "<")
	} else if strings.HasPrefix(condition, "=") {
		operator = "="
		versionStr = strings.TrimPrefix(condition, "=")
	} else {
		// No operator, treat as exact match
		operator = "="
		versionStr = condition
	}

	target := parseSemver(versionStr)
	if !target.Valid {
		// Unparseable advisory boundary — don't claim a match (false positive).
		return false
	}

	cmp := compareSemver(installed, target)

	switch operator {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "=":
		return cmp == 0
	default:
		return true
	}
}

// extractVulnerableRanges extracts version ranges from advisory vulnerabilities array
func extractVulnerableRanges(advisory map[string]interface{}, packageName string, ecosystem string) []string {
	var ranges []string

	vulnerabilities, ok := advisory["vulnerabilities"].([]interface{})
	if !ok {
		return ranges
	}

	ecosystemLower := strings.ToLower(ecosystem)

	for _, vuln := range vulnerabilities {
		vulnMap, ok := vuln.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this vulnerability entry is for our package and ecosystem
		pkg, ok := vulnMap["package"].(map[string]interface{})
		if !ok {
			continue
		}

		pkgEcosystem, _ := pkg["ecosystem"].(string)
		pkgName, _ := pkg["name"].(string)

		if strings.ToLower(pkgEcosystem) != ecosystemLower {
			continue
		}

		if !strings.EqualFold(pkgName, packageName) {
			continue
		}

		// Extract the vulnerable version range
		if rangeStr, ok := vulnMap["vulnerable_version_range"].(string); ok && rangeStr != "" {
			ranges = append(ranges, rangeStr)
		}
	}

	return ranges
}

// isVersionVulnerable checks if the installed version is within any vulnerable range
func isVersionVulnerable(installedVersion string, vulnerableRanges []string) bool {
	if len(vulnerableRanges) == 0 {
		// No specific ranges found, can't determine - be conservative
		return false
	}

	for _, rangeStr := range vulnerableRanges {
		if isVersionInRange(installedVersion, rangeStr) {
			return true
		}
	}

	return false
}

// normalizeVersionForCVE removes common prefixes and normalizes version strings for CVE comparison
func normalizeVersionForCVE(version string) string {
	// Remove npm-style prefixes
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")

	// Handle version ranges like "1.2.3 - 2.0.0" - take the first part
	if idx := strings.Index(version, " - "); idx != -1 {
		version = version[:idx]
	}

	// Handle || ranges - take the first part
	if idx := strings.Index(version, "||"); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	return strings.TrimSpace(version)
}

// extractPatchedVersion extracts the first patched version from advisory
func extractPatchedVersion(advisory map[string]interface{}, packageName string, ecosystem string) string {
	vulnerabilities, ok := advisory["vulnerabilities"].([]interface{})
	if !ok {
		return ""
	}

	ecosystemLower := strings.ToLower(ecosystem)

	for _, vuln := range vulnerabilities {
		vulnMap, ok := vuln.(map[string]interface{})
		if !ok {
			continue
		}

		pkg, ok := vulnMap["package"].(map[string]interface{})
		if !ok {
			continue
		}

		pkgEcosystem, _ := pkg["ecosystem"].(string)
		pkgName, _ := pkg["name"].(string)

		if strings.ToLower(pkgEcosystem) != ecosystemLower {
			continue
		}

		if !strings.EqualFold(pkgName, packageName) {
			continue
		}

		if patched, ok := vulnMap["first_patched_version"].(string); ok && patched != "" {
			return patched
		}
	}

	return ""
}

// HTTP client for CVE requests
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// Tracks dependencies whose versions couldn't be parsed during a CVE scan, so
// we can surface a single summary at the end instead of either silently
// skipping them or false-positive flagging every advisory hit.
var (
	unparseableMu       sync.Mutex
	unparseableVersions map[string]string
)

func resetUnparseableVersions() {
	unparseableMu.Lock()
	defer unparseableMu.Unlock()
	unparseableVersions = make(map[string]string)
}

func recordUnparseableVersion(name, version string) {
	unparseableMu.Lock()
	defer unparseableMu.Unlock()
	if unparseableVersions == nil {
		unparseableVersions = make(map[string]string)
	}
	unparseableVersions[name] = version
}

func reportUnparseableVersions() {
	unparseableMu.Lock()
	defer unparseableMu.Unlock()
	if len(unparseableVersions) == 0 {
		return
	}
	samples := make([]string, 0, 5)
	for name, ver := range unparseableVersions {
		samples = append(samples, fmt.Sprintf("%s@%s", name, ver))
		if len(samples) >= 5 {
			break
		}
	}
	extra := ""
	if len(unparseableVersions) > len(samples) {
		extra = fmt.Sprintf(" (+%d more)", len(unparseableVersions)-len(samples))
	}
	fmt.Fprintf(os.Stderr, "⚠️  %d dependencies skipped CVE checks (version not in semver form): %s%s\n",
		len(unparseableVersions), strings.Join(samples, ", "), extra)
}

// scanCVEs performs concurrent CVE scanning on dependencies with improved error handling
func scanCVEs(dependencies []core.Dependency, language string) ([]core.CVE, error) {
	if len(dependencies) == 0 {
		return []core.CVE{}, nil
	}

	resetUnparseableVersions()
	defer reportUnparseableVersions()

	ecosystem := getEcosystem(language)
	if ecosystem == "" {
		return []core.CVE{}, fmt.Errorf("unsupported ecosystem for language: %s", language)
	}

	// Use context with timeout for better control
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Concurrent processing with worker pool
	const numWorkers = 3
	const batchSize = 5

	type batchResult struct {
		findings []core.CVE
		err      error
		batchID  int
	}

	batches := make([][]core.Dependency, 0)
	for i := 0; i < len(dependencies); i += batchSize {
		end := i + batchSize
		if end > len(dependencies) {
			end = len(dependencies)
		}
		batches = append(batches, dependencies[i:end])
	}

	resultsChan := make(chan batchResult, len(batches))
	batchChan := make(chan int, len(batches))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batchID := range batchChan {
				select {
				case <-ctx.Done():
					return
				default:
					findings, err := queryGitHubAdvisoriesWithContext(ctx, batches[batchID], ecosystem)
					resultsChan <- batchResult{
						findings: findings,
						err:      err,
						batchID:  batchID,
					}

					// Rate limiting between requests
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()
	}

	// Send batch IDs to workers
	go func() {
		defer close(batchChan)
		for i := range batches {
			select {
			case <-ctx.Done():
				return
			case batchChan <- i:
			}
		}
	}()

	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var findings []core.CVE
	for result := range resultsChan {
		if result.err != nil {
			continue
		}
		findings = append(findings, result.findings...)
	}

	return findings, nil
}

// getEcosystem maps programming languages to GitHub ecosystems
func getEcosystem(language string) string {
	ecosystemMap := map[string]string{
		"JavaScript": "npm",
		"Python":     "pip",
		"Java":       "maven",
		"Go":         "go",
		"Ruby":       "rubygems",
		"PHP":        "composer",
		"Rust":       "crates.io",
	}
	return ecosystemMap[language]
}

// queryGitHubAdvisoriesWithContext queries the GitHub Security Advisory API with context
func queryGitHubAdvisoriesWithContext(ctx context.Context, dependencies []core.Dependency, ecosystem string) ([]core.CVE, error) {
	var findings []core.CVE

	for _, dep := range dependencies {
		if len(findings) >= 15 { // Limit total findings per batch
			break
		}

		cves, err := queryPackageVulnerabilities(ctx, dep, ecosystem)
		if err != nil {
			// Continue with other packages if one fails
			continue
		}
		findings = append(findings, cves...)
	}

	return findings, nil
}

// queryPackageVulnerabilities queries vulnerabilities for a single package using REST API
func queryPackageVulnerabilities(ctx context.Context, dep core.Dependency, ecosystem string) ([]core.CVE, error) {
	var findings []core.CVE

	// Use GitHub's REST API for security advisories
	ecosystemParam := getRestAPIEcosystem(ecosystem)
	url := fmt.Sprintf("https://api.github.com/advisories?ecosystem=%s&affects=%s&per_page=5", ecosystemParam, dep.Name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return findings, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Complyr-CLI/1.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Make request
	resp, err := httpClient.Do(req)
	if err != nil {
		return findings, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 401 {
			return findings, fmt.Errorf("GitHub API authentication failed (401): %s", string(body))
		} else if resp.StatusCode == 403 {
			return findings, fmt.Errorf("GitHub API rate limit exceeded (403): %s", string(body))
		}
		return findings, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings, fmt.Errorf("failed to read response body: %w", err)
	}

	var advisories []map[string]interface{}
	if err := json.Unmarshal(body, &advisories); err != nil {
		return findings, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Convert advisories to CVEs
	for _, advisory := range advisories {
		cve := parseRestAdvisory(advisory, dep, ecosystem)
		if cve.CVE != "" && len(cve.Violations) > 0 {
			findings = append(findings, cve)
		}
	}

	return findings, nil
}

// getRestAPIEcosystem maps internal ecosystem names to GitHub REST API ecosystem names
func getRestAPIEcosystem(ecosystem string) string {
	// GitHub REST API uses lowercase ecosystem names
	ecosystemMap := map[string]string{
		"NPM":       "npm",
		"PIP":       "pip",
		"MAVEN":     "maven",
		"GO":        "go",
		"RUBYGEMS":  "rubygems",
		"COMPOSER":  "composer",
		"CRATES.IO": "crates.io",
	}
	if mapped, exists := ecosystemMap[strings.ToUpper(ecosystem)]; exists {
		return mapped
	}
	return strings.ToLower(ecosystem)
}

// parseRestAdvisory converts REST API advisory data to CVE
func parseRestAdvisory(advisory map[string]interface{}, dep core.Dependency, ecosystem string) core.CVE {
	var cve core.CVE

	// Extract CVE ID from identifiers
	if identifiers, ok := advisory["identifiers"].([]interface{}); ok {
		for _, id := range identifiers {
			if idMap, ok := id.(map[string]interface{}); ok {
				if idType, ok := idMap["type"].(string); ok && idType == "CVE" {
					if value, ok := idMap["value"].(string); ok {
						cve.CVE = value
						break
					}
				}
			}
		}
	}

	// If no CVE, use GHSA ID
	if cve.CVE == "" {
		if ghsaId, ok := advisory["ghsa_id"].(string); ok {
			cve.CVE = ghsaId
		}
	}

	// Extract other fields
	cve.Package = dep.Name
	cve.Version = dep.Version

	if summary, ok := advisory["summary"].(string); ok {
		cve.Description = summary
	}

	if severity, ok := advisory["severity"].(string); ok {
		cve.Severity = strings.ToUpper(severity)
	}

	// Extract CVSS score
	if cvss, ok := advisory["cvss"].(map[string]interface{}); ok {
		if score, ok := cvss["score"].(float64); ok {
			cve.Score = score
		}
	}

	// Extract vulnerable version ranges and check if installed version is affected
	vulnerableRanges := extractVulnerableRanges(advisory, dep.Name, ecosystem)
	installedVersion := normalizeVersionForCVE(dep.Version)

	if len(vulnerableRanges) > 0 {
		// If the installed version isn't valid semver (git SHA, "latest", Maven
		// qualifier, etc.), we can't make a defensible vulnerability claim.
		// Record it so the user knows it was skipped, then move on.
		if !parseSemver(installedVersion).Valid {
			recordUnparseableVersion(dep.Name, dep.Version)
			return core.CVE{}
		}
		if !isVersionVulnerable(installedVersion, vulnerableRanges) {
			return core.CVE{} // Installed version is not in vulnerable range
		}
	}

	// Extract patched version for better remediation advice
	patchedVersion := extractPatchedVersion(advisory, dep.Name, ecosystem)
	remediationMsg := "Update to patched version or find secure alternative"
	if patchedVersion != "" {
		remediationMsg = fmt.Sprintf("Update to version %s or later", patchedVersion)
	}

	// Create control violations only for relevant vulnerabilities
	cve.Violations = []core.ControlViolation{
		{
			ControlID:   "SI-2",
			Framework:   core.FrameworkNIST800_53,
			Title:       "Flaw Remediation",
			Severity:    cve.Severity,
			Finding:     "Known vulnerability in dependency",
			Rationale:   fmt.Sprintf("Package %s@%s has known security vulnerability", dep.Name, dep.Version),
			Remediation: remediationMsg,
		},
	}

	return cve
}

