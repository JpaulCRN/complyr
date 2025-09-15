package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/JpaulCRN/complyr/internal/core"
)

// HTTP client for CVE requests
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// scanCVEs performs concurrent CVE scanning on dependencies with improved error handling
func scanCVEs(dependencies []core.Dependency, language string) ([]core.CVE, error) {
	if len(dependencies) == 0 {
		return []core.CVE{}, nil
	}

	ecosystem := getEcosystem(language)
	if ecosystem == "" {
		return []core.CVE{}, fmt.Errorf("unsupported ecosystem for language: %s", language)
	}

	fmt.Printf("   📦 Analyzing %d dependencies for vulnerabilities...\n", len(dependencies))

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

	// Collect results
	var findings []core.CVE
	var errors []error

	for result := range resultsChan {
		if result.err != nil {
			errors = append(errors, fmt.Errorf("batch %d: %w", result.batchID, result.err))
			continue
		}
		findings = append(findings, result.findings...)
	}

	// Report warnings for failed batches, but don't fail the entire scan
	if len(errors) > 0 {
		fmt.Printf("   ⚠️  Warning: %d batches failed CVE lookup\n", len(errors))
	}

	if len(findings) > 0 {
		fmt.Printf("   🚨 Found %d vulnerabilities\n", len(findings))
	} else {
		fmt.Printf("   ✅ No known vulnerabilities found\n")
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

	url := "https://api.github.com/graphql"

	// Build GraphQL query for multiple packages
	var packageQueries []string
	for i, dep := range dependencies {
		if i >= 5 { // Limit batch size
			break
		}

		sanitizedName := sanitizePackageName(dep.Name)
		query := fmt.Sprintf(`
			advisory%d: securityAdvisories(
				first: 3,
				ecosystem: %s,
				package: "%s"
			) {
				nodes {
					ghsaId
					identifiers {
						type
						value
					}
					summary
					severity
					cvss {
						score
					}
				}
			}`, i, strings.ToUpper(ecosystem), sanitizedName)
		packageQueries = append(packageQueries, query)
	}

	graphqlQuery := fmt.Sprintf(`{ %s }`, strings.Join(packageQueries, "\n"))

	// Create request
	requestBody := map[string]string{
		"query": graphqlQuery,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return findings, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonBody)))
	if err != nil {
		return findings, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v4+json")
	req.Header.Set("User-Agent", "Complyr-CLI/1.0")

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	// Make request
	resp, err := httpClient.Do(req)
	if err != nil {
		return findings, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return findings, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings, fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return findings, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Extract advisories from response
	if data, ok := result["data"].(map[string]interface{}); ok {
		for i, dep := range dependencies {
			if i >= 5 {
				break
			}

			advisoryKey := fmt.Sprintf("advisory%d", i)
			if advisory, exists := data[advisoryKey].(map[string]interface{}); exists {
				if securityAdvisories, ok := advisory["securityAdvisories"].(map[string]interface{}); ok {
					if nodes, ok := securityAdvisories["nodes"].([]interface{}); ok {
						for _, node := range nodes {
							if advisoryNode, ok := node.(map[string]interface{}); ok {
								cve := parseGitHubAdvisory(advisoryNode, dep)
								if cve.CVE != "" {
									findings = append(findings, cve)
								}
							}
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// parseGitHubAdvisory converts GitHub advisory data to CVE
func parseGitHubAdvisory(advisory map[string]interface{}, dep core.Dependency) core.CVE {
	var cve core.CVE

	// Extract CVE ID
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
		if ghsaId, ok := advisory["ghsaId"].(string); ok {
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

	if cvss, ok := advisory["cvss"].(map[string]interface{}); ok {
		if score, ok := cvss["score"].(float64); ok {
			cve.Score = score
		}
	}

	// Create control violations
	cve.Violations = []core.ControlViolation{
		{
			ControlID:   "SI-2",
			Framework:   core.FrameworkNIST800_53,
			Title:       "Flaw Remediation",
			Severity:    cve.Severity,
			Finding:     "Known vulnerability in dependency",
			Rationale:   fmt.Sprintf("Package %s@%s has known security vulnerability", dep.Name, dep.Version),
			Remediation: "Update to patched version or find secure alternative",
		},
	}

	return cve
}

// sanitizePackageName prevents GraphQL injection
func sanitizePackageName(name string) string {
	name = strings.ReplaceAll(name, `"`, `\"`)
	name = strings.ReplaceAll(name, `\`, `\\`)
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
