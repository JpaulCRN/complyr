package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JpaulCRN/complyr/internal/core"
)

// PrintBanner displays the complyr banner to stdout
func PrintBanner() {
	PrintBannerTo(os.Stdout)
}

// PrintBannerTo displays the complyr banner to specified writer
func PrintBannerTo(w io.Writer) {
	banner := `
 ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗  ██╗   ██╗██████╗
██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║  ╚██╗ ██╔╝██╔══██╗
██║     ██║   ██║██╔████╔██║██████╔╝██║   ╚████╔╝ ██████╔╝
██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║    ╚██╔╝  ██╔══██╗
╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██║   ██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝   ╚═╝  ╚═╝
                    by Colvin Run
                    NIST RMF Compliance Scanner
`
	fmt.Fprintln(w, banner)
}

// DisplayResults shows scan results in human-readable format
func DisplayResults(result *core.ScanResult, verbose bool) {
	displayHeader(result)

	// Show TRL-aware summary if TRL is configured
	if result.ProjectContext.TRL > 0 {
		displayTRLSummary(result)
	} else {
		displaySummary(result)
	}

	displayFindings(result, verbose)

	// Show TRL-aware controls if TRL is configured
	if result.ProjectContext.TRL > 0 {
		displayTRLControls(result, verbose)
	} else {
		displayControls(result.ControlsAssessed, verbose)
	}

	displayTRLConclusion(result)
}

// DisplayJSON outputs results in JSON format
func DisplayJSON(result *core.ScanResult) error {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayHeader(result *core.ScanResult) {
	// Check if this is a monorepo
	if result.ProjectType.IsMonorepo {
		fmt.Printf("PROJECT: %s\n", result.ProjectType.Name)
		fmt.Printf("  Languages: %s\n", result.ProjectType.Language)

		// Show subprojects
		if len(result.ProjectType.Subprojects) > 0 {
			fmt.Printf("  Subprojects: %d\n", len(result.ProjectType.Subprojects))
			for _, sub := range result.ProjectType.Subprojects {
				fmt.Printf("  - %s (%s)\n", sub.Path, sub.Language)
			}
		}
	} else {
		fmt.Printf("PROJECT: %s (%s)", result.ProjectType.Name, result.ProjectType.Language)
	}

	// Add TRL context if available
	if result.ProjectContext.TRL > 0 {
		fmt.Printf(" | TRL %d", result.ProjectContext.TRL)
		if result.ProjectContext.ContractType != "" {
			fmt.Printf(" | %s", result.ProjectContext.ContractType)
		}
	}
	fmt.Println()

	fmt.Printf("PATH: %s\n", result.ProjectPath)
	fmt.Printf("DEPENDENCIES: %d\n", len(result.Dependencies))

	// Show dependency breakdown by subproject for monorepos
	if result.ProjectType.IsMonorepo {
		displayDependencyBreakdown(result.Dependencies)
	}

	fmt.Println(strings.Repeat("-", 70))
}

// displayDependencyBreakdown shows dependencies grouped by subproject
func displayDependencyBreakdown(dependencies []core.Dependency) {
	// Group dependencies by subproject
	bySubproject := make(map[string]int)
	for _, dep := range dependencies {
		key := dep.Subproject
		if key == "" {
			key = "(root)"
		}
		bySubproject[key]++
	}

	if len(bySubproject) > 1 {
		fmt.Println("  Dependencies by location:")
		for subproject, count := range bySubproject {
			fmt.Printf("  - %s: %d\n", subproject, count)
		}
	}
}

func displayTRLSummary(result *core.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("COMPLIANCE STATUS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Stage: TRL %d - %s\n",
		result.ProjectContext.TRL,
		core.TRLDescriptions[result.ProjectContext.TRL])

	// Show controls for current TRL only
	requiredCount := len(result.TRLAssessment.RequiredControls)
	fmt.Printf("Required Controls: %d of %d satisfied\n",
		result.Summary.SatisfiedControls,
		requiredCount)

	// Show TRL-specific compliance
	readiness := result.TRLAssessment.TRLCompliance
	var color string
	switch {
	case readiness >= 80:
		color = "\033[32m" // Green
	case readiness >= 60:
		color = "\033[33m" // Yellow
	default:
		color = "\033[31m" // Red
	}

	fmt.Printf("Current TRL Compliance: %s%.1f%%\033[0m\n", color, readiness)

	// Show progress bar
	printProgressBar(readiness)

	// Show next TRL readiness if applicable
	if result.ProjectContext.TRL < 9 && result.TRLAssessment.NextTRLReadiness > 0 {
		fmt.Printf("Progress to TRL %d: %.1f%%\n",
			result.ProjectContext.TRL+1,
			result.TRLAssessment.NextTRLReadiness)
	}

	// Show issues if any
	displayIssuesSummary(result.Summary)

	fmt.Println(strings.Repeat("=", 70))
}

func displaySummary(result *core.ScanResult) {
	summary := result.Summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("COMPLIANCE SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Controls Assessed: %d\n", summary.TotalControls)
	fmt.Printf("Satisfied Controls: %d\n", summary.SatisfiedControls)

	// Color-coded ATO readiness
	readiness := summary.ATOReadiness
	var color string
	switch {
	case readiness >= 80:
		color = "\033[32m" // Green
	case readiness >= 60:
		color = "\033[33m" // Yellow
	default:
		color = "\033[31m" // Red
	}

	fmt.Printf("ATO Readiness: %s%.1f%%\033[0m\n", color, readiness)

	displayIssuesSummary(summary)
	fmt.Println(strings.Repeat("=", 70))
}

func displayIssuesSummary(summary core.ScanSummary) {
	totalIssues := summary.CriticalIssues + summary.HighIssues + summary.MediumIssues + summary.LowIssues
	if totalIssues > 0 {
		fmt.Println("\nISSUES FOUND:")
		if summary.CriticalIssues > 0 {
			fmt.Printf("  [CRITICAL] %d\n", summary.CriticalIssues)
		}
		if summary.HighIssues > 0 {
			fmt.Printf("  [HIGH]     %d\n", summary.HighIssues)
		}
		if summary.MediumIssues > 0 {
			fmt.Printf("  [MEDIUM]   %d\n", summary.MediumIssues)
		}
		if summary.LowIssues > 0 {
			fmt.Printf("  [LOW]      %d\n", summary.LowIssues)
		}
	}
}

func printProgressBar(percentage float64) {
	barWidth := 50
	filled := int(percentage / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)
	fmt.Printf("[%s]\n", bar)
}

func displayFindings(result *core.ScanResult, verbose bool) {
	// For monorepos, group findings by subproject
	if result.ProjectType.IsMonorepo && verbose {
		displayMonorepoFindings(result)
		return
	}

	// Display banned technologies
	if len(result.BannedTechFound) > 0 {
		fmt.Printf("\nBANNED TECHNOLOGIES (%d found):\n", len(result.BannedTechFound))
		for _, banned := range result.BannedTechFound {
			severityLabel := getSeverityLabel(banned.Severity)
			fmt.Printf("  [%s] %s@%s\n", severityLabel, banned.Name, banned.Version)
			if verbose {
				fmt.Printf("    File: %s\n", banned.File)
				fmt.Printf("    Reason: %s\n", banned.Reason)
			}
		}
	} else {
		fmt.Println("\n[PASS] No banned technologies found")
	}

	// Display CVEs
	if len(result.CVEsFound) > 0 {
		fmt.Printf("\nVULNERABILITIES (%d found):\n", len(result.CVEsFound))
		for _, cve := range result.CVEsFound {
			severityLabel := getSeverityLabel(cve.Severity)
			fmt.Printf("  [%s] %s in %s@%s\n", severityLabel, cve.CVE, cve.Package, cve.Version)
			if verbose && cve.Description != "" {
				fmt.Printf("    Description: %s\n", cve.Description)
			}
			if verbose && cve.Score > 0 {
				fmt.Printf("    CVSS Score: %.1f\n", cve.Score)
			}
		}
	} else {
		fmt.Println("\n[PASS] No known vulnerabilities found")
	}
}

// displayMonorepoFindings shows findings grouped by subproject
func displayMonorepoFindings(result *core.ScanResult) {
	// Group banned tech by subproject (using the dependency's subproject)
	bannedBySubproject := make(map[string][]core.BannedTech)
	for _, banned := range result.BannedTechFound {
		// Find which subproject this dependency belongs to
		subproject := findDependencySubproject(result.Dependencies, banned.Name)
		bannedBySubproject[subproject] = append(bannedBySubproject[subproject], banned)
	}

	// Group CVEs by subproject
	cvesBySubproject := make(map[string][]core.CVE)
	for _, cve := range result.CVEsFound {
		subproject := findDependencySubproject(result.Dependencies, cve.Package)
		cvesBySubproject[subproject] = append(cvesBySubproject[subproject], cve)
	}

	// Collect all subprojects with findings
	allSubprojects := make(map[string]bool)
	for sub := range bannedBySubproject {
		allSubprojects[sub] = true
	}
	for sub := range cvesBySubproject {
		allSubprojects[sub] = true
	}

	if len(allSubprojects) == 0 {
		fmt.Println("\n[PASS] No banned technologies found")
		fmt.Println("\n[PASS] No known vulnerabilities found")
		return
	}

	// Display findings by subproject
	for subproject := range allSubprojects {
		displayName := subproject
		if displayName == "" {
			displayName = "(root)"
		}
		fmt.Printf("\nSUBPROJECT: %s\n", displayName)

		// Banned tech for this subproject
		if banned, ok := bannedBySubproject[subproject]; ok && len(banned) > 0 {
			fmt.Printf("  Banned Technologies: %d\n", len(banned))
			for _, b := range banned {
				severityLabel := getSeverityLabel(b.Severity)
				fmt.Printf("    [%s] %s@%s - %s\n", severityLabel, b.Name, b.Version, b.Reason)
			}
		}

		// CVEs for this subproject
		if cves, ok := cvesBySubproject[subproject]; ok && len(cves) > 0 {
			fmt.Printf("  Vulnerabilities: %d\n", len(cves))
			for _, cve := range cves {
				severityLabel := getSeverityLabel(cve.Severity)
				fmt.Printf("    [%s] %s in %s@%s\n", severityLabel, cve.CVE, cve.Package, cve.Version)
			}
		}
	}

	// Summary
	totalBanned := len(result.BannedTechFound)
	totalCVEs := len(result.CVEsFound)
	if totalBanned == 0 {
		fmt.Println("\n[PASS] No banned technologies found")
	}
	if totalCVEs == 0 {
		fmt.Println("\n[PASS] No known vulnerabilities found")
	}
}

// findDependencySubproject finds which subproject a dependency belongs to
func findDependencySubproject(dependencies []core.Dependency, packageName string) string {
	for _, dep := range dependencies {
		if dep.Name == packageName {
			return dep.Subproject
		}
	}
	return ""
}

func displayTRLControls(result *core.ScanResult, verbose bool) {
	if len(result.ControlsAssessed) == 0 {
		return
	}

	// Separate required and optional controls
	var requiredControls []core.ControlResult
	var optionalControls []core.ControlResult

	for _, control := range result.ControlsAssessed {
		if control.IsOptional {
			optionalControls = append(optionalControls, control)
		} else {
			requiredControls = append(requiredControls, control)
		}
	}

	// Display required controls for current TRL
	if len(requiredControls) > 0 {
		fmt.Printf("\nTRL %d REQUIREMENTS (%d controls):\n",
			result.ProjectContext.TRL, len(requiredControls))

		// Group by status
		statusGroups := make(map[string][]core.ControlResult)
		for _, control := range requiredControls {
			statusGroups[control.Status] = append(statusGroups[control.Status], control)
		}

		// Display by status
		displayControlsByStatus(statusGroups, verbose)
	}

	// Display controls needed for next TRL (IMPROVED - showing only what's needed)
	if len(optionalControls) > 0 && result.ProjectContext.TRL < 9 {
		displayNextTRLPreparation(result, optionalControls, verbose)
	}

	// Show deferred controls briefly
	if len(result.TRLAssessment.DeferredControls) > 0 && verbose {
		fmt.Printf("\nFUTURE REQUIREMENTS (TRL 7+):\n")
		fmt.Printf("  Controls not needed until operational testing: %s\n",
			strings.Join(result.TRLAssessment.DeferredControls, ", "))
	}
}

// displayNextTRLPreparation shows what's needed for the next TRL level
func displayNextTRLPreparation(result *core.ScanResult, optionalControls []core.ControlResult, verbose bool) {
	nextTRL := result.ProjectContext.TRL + 1

	// Get the control set for next TRL
	nextTRLSet := core.GetTRLControls(nextTRL)
	nextTRLRequired := make(map[string]bool)
	for _, controlID := range nextTRLSet.Required {
		nextTRLRequired[controlID] = true
	}

	// Filter optional controls to only those required for next TRL
	var neededForNextTRL []core.ControlResult
	var alreadySatisfiedForNextTRL []core.ControlResult

	for _, control := range optionalControls {
		if nextTRLRequired[control.ControlID] {
			if control.Status == core.StatusSatisfied {
				alreadySatisfiedForNextTRL = append(alreadySatisfiedForNextTRL, control)
			} else {
				neededForNextTRL = append(neededForNextTRL, control)
			}
		}
	}

	totalNeeded := len(neededForNextTRL) + len(alreadySatisfiedForNextTRL)
	if totalNeeded == 0 {
		return
	}

	fmt.Printf("\nPREPARING FOR TRL %d (%d additional controls required):\n", nextTRL, totalNeeded)

	if len(neededForNextTRL) > 0 {
		fmt.Printf("\n  NEEDS IMPLEMENTATION (%d controls):\n", len(neededForNextTRL))
		for _, control := range neededForNextTRL {
			fmt.Printf("  - %s: %s\n", control.ControlID, control.Title)
			if verbose {
				fmt.Printf("      Status: %s\n", control.Evidence)
			}
		}
	}

	if len(alreadySatisfiedForNextTRL) > 0 {
		fmt.Printf("\n  ALREADY SATISFIED (%d controls):\n", len(alreadySatisfiedForNextTRL))
		for _, control := range alreadySatisfiedForNextTRL {
			fmt.Printf("  [PASS] %s: %s\n", control.ControlID, control.Title)
		}
	}
}

func displayControls(controls []core.ControlResult, verbose bool) {
	if len(controls) == 0 {
		return
	}

	fmt.Printf("\nCONTROL ASSESSMENT (%d controls):\n", len(controls))

	// Group by status
	statusGroups := make(map[string][]core.ControlResult)
	for _, control := range controls {
		statusGroups[control.Status] = append(statusGroups[control.Status], control)
	}

	displayControlsByStatus(statusGroups, verbose)
}

func displayControlsByStatus(statusGroups map[string][]core.ControlResult, verbose bool) {
	// Display by status priority
	statusOrder := []string{
		core.StatusNotSatisfied,
		core.StatusManualReview,
		core.StatusSatisfied,
		core.StatusNotApplicable,
	}

	for _, status := range statusOrder {
		if controls, exists := statusGroups[status]; exists && len(controls) > 0 {
			fmt.Printf("\n  %s (%d controls):\n", getStatusDisplay(status), len(controls))

			for _, control := range controls {
				label := getStatusLabel(control.Status)
				fmt.Printf("  [%s] %s: %s\n", label, control.ControlID, control.Title)

				if verbose || status == core.StatusNotSatisfied {
					fmt.Printf("      %s\n", control.Evidence)
					if control.Findings > 0 {
						fmt.Printf("      Findings: %d\n", control.Findings)
					}
				}
			}
		}
	}
}

func displayTRLConclusion(result *core.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 70))

	// TRL-specific conclusion
	if result.ProjectContext.TRL > 0 {
		compliance := result.TRLAssessment.TRLCompliance

		if compliance >= 100 {
			fmt.Printf("RESULT: All TRL %d requirements satisfied\n",
				result.ProjectContext.TRL)
			if result.ProjectContext.TRL < 9 {
				fmt.Printf("NEXT STEPS: Review requirements for TRL %d advancement\n",
					result.ProjectContext.TRL+1)
			} else {
				fmt.Println("STATUS: Production-ready from compliance perspective")
			}
		} else if compliance >= 80 {
			fmt.Printf("RESULT: %.0f%% compliant with TRL %d requirements\n",
				compliance, result.ProjectContext.TRL)
			fmt.Println("NEXT STEPS: Address remaining controls for full compliance")
		} else {
			fmt.Printf("RESULT: %.0f%% compliant with TRL %d requirements\n",
				compliance, result.ProjectContext.TRL)
			fmt.Println("NEXT STEPS: Prioritize required controls for current stage")
		}

		// Show appropriate next steps
		if result.Summary.CriticalIssues > 0 || result.Summary.HighIssues > 0 {
			fmt.Println("\nWARNING: Address critical and high severity issues immediately")
		}

		fmt.Printf("\nTRL %d Compliance: %.1f%%\n",
			result.ProjectContext.TRL, compliance)

	} else {
		// Fall back to original conclusion for non-TRL scans
		displayConclusion(result)
	}

	fmt.Println("\nFor TRL-based assessment: complyr init")
	fmt.Println("For detailed findings: complyr scan --verbose")
	fmt.Println(strings.Repeat("=", 70))
}

func displayConclusion(result *core.ScanResult) {
	readiness := result.Summary.ATOReadiness

	if readiness >= 80 {
		fmt.Println("RESULT: Project well-positioned for ATO")
		fmt.Println("NEXT STEPS: Conduct final manual reviews for remaining controls")
	} else if readiness >= 60 {
		fmt.Println("WARNING: Some issues need attention before ATO")
		fmt.Println("NEXT STEPS: Address critical and high-severity findings first")
	} else {
		fmt.Println("ATTENTION: Significant compliance gaps detected")
		fmt.Println("NEXT STEPS: Resolve critical issues before ATO process")
	}

	fmt.Printf("\nOverall ATO Readiness: %.1f%%\n", readiness)
}

func getSeverityLabel(severity string) string {
	switch severity {
	case core.SeverityCritical:
		return "CRITICAL"
	case core.SeverityHigh:
		return "HIGH"
	case core.SeverityMedium:
		return "MEDIUM"
	case core.SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func getStatusLabel(status string) string {
	switch status {
	case core.StatusSatisfied:
		return "PASS"
	case core.StatusNotSatisfied:
		return "FAIL"
	case core.StatusManualReview:
		return "REVIEW"
	case core.StatusNotApplicable:
		return "N/A"
	default:
		return "UNKNOWN"
	}
}

func getStatusDisplay(status string) string {
	switch status {
	case core.StatusSatisfied:
		return "SATISFIED"
	case core.StatusNotSatisfied:
		return "NOT SATISFIED"
	case core.StatusManualReview:
		return "MANUAL REVIEW REQUIRED"
	case core.StatusNotApplicable:
		return "NOT APPLICABLE"
	default:
		return "UNKNOWN"
	}
}
