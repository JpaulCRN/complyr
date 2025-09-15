package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JpaulCRN/complyr/internal/core"
)

// PrintBanner displays the complyr banner
func PrintBanner() {
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
	fmt.Println(banner)
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
	fmt.Printf("📁 Project: %s (%s)", result.ProjectType.Name, result.ProjectType.Language)

	// Add TRL context if available
	if result.ProjectContext.TRL > 0 {
		fmt.Printf(" | TRL %d", result.ProjectContext.TRL)
		if result.ProjectContext.ContractType != "" {
			fmt.Printf(" | %s", result.ProjectContext.ContractType)
		}
	}
	fmt.Println()

	fmt.Printf("📍 Path: %s\n", result.ProjectPath)
	fmt.Printf("📦 Dependencies analyzed: %d\n", len(result.Dependencies))
	fmt.Println(strings.Repeat("─", 50))
}

func displayTRLSummary(result *core.ScanResult) {
	fmt.Println("\n📊 COMPLIANCE STATUS")
	fmt.Printf("   Stage: TRL %d - %s\n",
		result.ProjectContext.TRL,
		core.TRLDescriptions[result.ProjectContext.TRL])

	// Show controls for current TRL only
	requiredCount := len(result.TRLAssessment.RequiredControls)
	fmt.Printf("   Required Controls: %d of %d satisfied\n",
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

	fmt.Printf("   🎯 Current TRL Compliance: %s%.1f%%\033[0m\n", color, readiness)

	// Show progress bar
	printProgressBar(readiness)

	// Show next TRL readiness if applicable
	if result.ProjectContext.TRL < 9 && result.TRLAssessment.NextTRLReadiness > 0 {
		fmt.Printf("   📈 Progress to TRL %d: %.1f%%\n",
			result.ProjectContext.TRL+1,
			result.TRLAssessment.NextTRLReadiness)
	}

	// Show issues if any
	displayIssuesSummary(result.Summary)

	fmt.Println(strings.Repeat("─", 50))
}

func displaySummary(result *core.ScanResult) {
	summary := result.Summary
	fmt.Println("\n📋 COMPLIANCE SUMMARY")
	fmt.Printf("   Controls Assessed: %d\n", summary.TotalControls)
	fmt.Printf("   Satisfied Controls: %d\n", summary.SatisfiedControls)

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

	fmt.Printf("   🎯 ATO Readiness: %s%.1f%%\033[0m\n", color, readiness)

	displayIssuesSummary(summary)
	fmt.Println(strings.Repeat("─", 50))
}

func displayIssuesSummary(summary core.ScanSummary) {
	totalIssues := summary.CriticalIssues + summary.HighIssues + summary.MediumIssues + summary.LowIssues
	if totalIssues > 0 {
		fmt.Println("\n🚨 ISSUES FOUND")
		if summary.CriticalIssues > 0 {
			fmt.Printf("   🔴 Critical: %d\n", summary.CriticalIssues)
		}
		if summary.HighIssues > 0 {
			fmt.Printf("   🟠 High: %d\n", summary.HighIssues)
		}
		if summary.MediumIssues > 0 {
			fmt.Printf("   🟡 Medium: %d\n", summary.MediumIssues)
		}
		if summary.LowIssues > 0 {
			fmt.Printf("   🟢 Low: %d\n", summary.LowIssues)
		}
	}
}

func printProgressBar(percentage float64) {
	barWidth := 30
	filled := int(percentage / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("   [%s]\n", bar)
}

func displayFindings(result *core.ScanResult, verbose bool) {
	// Display banned technologies
	if len(result.BannedTechFound) > 0 {
		fmt.Printf("\n🚫 BANNED TECHNOLOGIES (%d found)\n", len(result.BannedTechFound))
		for _, banned := range result.BannedTechFound {
			severityIcon := getSeverityIcon(banned.Severity)
			fmt.Printf("   %s %s@%s\n", severityIcon, banned.Name, banned.Version)
			if verbose {
				fmt.Printf("      📄 File: %s\n", banned.File)
				fmt.Printf("      📝 Reason: %s\n", banned.Reason)
			}
		}
	} else {
		fmt.Println("\n✅ No banned technologies found")
	}

	// Display CVEs
	if len(result.CVEsFound) > 0 {
		fmt.Printf("\n🔍 VULNERABILITIES (%d found)\n", len(result.CVEsFound))
		for _, cve := range result.CVEsFound {
			severityIcon := getSeverityIcon(cve.Severity)
			fmt.Printf("   %s %s in %s@%s\n", severityIcon, cve.CVE, cve.Package, cve.Version)
			if verbose && cve.Description != "" {
				fmt.Printf("      📝 %s\n", cve.Description)
			}
			if verbose && cve.Score > 0 {
				fmt.Printf("      📊 CVSS Score: %.1f\n", cve.Score)
			}
		}
	} else {
		fmt.Println("\n✅ No known vulnerabilities found")
	}
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
		fmt.Printf("\n📋 TRL %d REQUIREMENTS (%d controls)\n",
			result.ProjectContext.TRL, len(requiredControls))

		// Group by status
		statusGroups := make(map[string][]core.ControlResult)
		for _, control := range requiredControls {
			statusGroups[control.Status] = append(statusGroups[control.Status], control)
		}

		// Display by status
		displayControlsByStatus(statusGroups, verbose)
	}

	// Display optional controls (preparing for next TRL)
	if len(optionalControls) > 0 && result.ProjectContext.TRL < 9 {
		fmt.Printf("\n📈 PREPARING FOR TRL %d\n", result.ProjectContext.TRL+1)
		fmt.Println("   When ready to advance, you'll need:")

		for _, control := range optionalControls {
			status := ""
			if control.Status == core.StatusSatisfied {
				status = " ✅"
			}
			fmt.Printf("   • %s: %s%s\n", control.ControlID, control.Title, status)

			if verbose && control.Status != core.StatusSatisfied {
				fmt.Printf("      💡 Quick fix: %s\n", getQuickFix(control))
			}
		}
	}

	// Show deferred controls briefly
	if len(result.TRLAssessment.DeferredControls) > 0 && verbose {
		fmt.Printf("\n🔮 FUTURE REQUIREMENTS (TRL 7+)\n")
		fmt.Printf("   Controls not needed until operational testing: %s\n",
			strings.Join(result.TRLAssessment.DeferredControls, ", "))
	}
}

func displayControls(controls []core.ControlResult, verbose bool) {
	if len(controls) == 0 {
		return
	}

	fmt.Printf("\n📋 CONTROL ASSESSMENT (%d controls)\n", len(controls))

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
			fmt.Printf("\n   %s (%d controls)\n", getStatusDisplay(status), len(controls))

			for _, control := range controls {
				icon := getStatusIcon(control.Status)
				fmt.Printf("   %s %s: %s\n", icon, control.ControlID, control.Title)

				if verbose || status == core.StatusNotSatisfied {
					fmt.Printf("      📝 %s\n", control.Evidence)
					if control.Findings > 0 {
						fmt.Printf("      🔍 Findings: %d\n", control.Findings)
					}
					// Add quick fix suggestions for unsatisfied controls
					if status == core.StatusNotSatisfied {
						fmt.Printf("      💡 Quick fix: %s\n", getQuickFix(control))
					}
				}
			}
		}
	}
}

func getQuickFix(control core.ControlResult) string {
	// Provide quick fix suggestions based on control family
	switch control.Family {
	case "AU":
		return "npm install winston or pino for logging"
	case "AC", "IA":
		return "npm install passport or @fastify/jwt for authentication"
	case "SC":
		return "npm install bcrypt for cryptography"
	case "SI":
		if control.ControlID == "SI-4" {
			return "npm install @sentry/node for monitoring"
		}
		return "Enable automated scanning in CI/CD"
	default:
		return "Review control requirements and implement appropriate measures"
	}
}

func displayTRLConclusion(result *core.ScanResult) {
	fmt.Println(strings.Repeat("─", 50))

	// TRL-specific conclusion
	if result.ProjectContext.TRL > 0 {
		compliance := result.TRLAssessment.TRLCompliance

		if compliance >= 100 {
			fmt.Printf("\n🎉 EXCELLENT: All TRL %d requirements satisfied!\n",
				result.ProjectContext.TRL)
			if result.ProjectContext.TRL < 9 {
				fmt.Printf("   You're ready to advance to TRL %d when the project is ready.\n",
					result.ProjectContext.TRL+1)
			} else {
				fmt.Println("   Your system is production-ready from a compliance perspective!")
			}
		} else if compliance >= 80 {
			fmt.Printf("\n👍 GOOD PROGRESS: You're %.0f%% compliant with TRL %d requirements.\n",
				compliance, result.ProjectContext.TRL)
			fmt.Println("   Address the remaining controls to achieve full compliance.")
		} else {
			fmt.Printf("\n📋 FOCUS NEEDED: Currently %.0f%% compliant with TRL %d requirements.\n",
				compliance, result.ProjectContext.TRL)
			fmt.Println("   Prioritize satisfying the required controls for your current stage.")
		}

		// Show appropriate next steps
		if result.Summary.CriticalIssues > 0 || result.Summary.HighIssues > 0 {
			fmt.Println("\n⚠️  Address critical and high severity issues immediately.")
		}

		fmt.Printf("\n📊 TRL %d Compliance: %.1f%%\n",
			result.ProjectContext.TRL, compliance)

	} else {
		// Fall back to original conclusion for non-TRL scans
		displayConclusion(result)
	}

	fmt.Println("💡 Run 'complyr init' to configure TRL-based assessment")
	fmt.Println("🔗 For detailed remediation guidance, run with --verbose flag")
}

func displayConclusion(result *core.ScanResult) {
	readiness := result.Summary.ATOReadiness

	if readiness >= 80 {
		fmt.Println("\n🎉 EXCELLENT: Your project is well-positioned for ATO!")
		fmt.Println("   Consider conducting final manual reviews for remaining controls.")
	} else if readiness >= 60 {
		fmt.Println("\n⚠️  MODERATE: Some issues need attention before ATO.")
		fmt.Println("   Address critical and high-severity findings first.")
	} else {
		fmt.Println("\n🚨 ATTENTION REQUIRED: Significant compliance gaps detected.")
		fmt.Println("   Resolve critical issues before proceeding with ATO process.")
	}

	fmt.Printf("\n📊 Overall ATO Readiness: %.1f%%\n", readiness)
}

func getSeverityIcon(severity string) string {
	switch severity {
	case core.SeverityCritical:
		return "🔴"
	case core.SeverityHigh:
		return "🟠"
	case core.SeverityMedium:
		return "🟡"
	case core.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func getStatusIcon(status string) string {
	switch status {
	case core.StatusSatisfied:
		return "✅"
	case core.StatusNotSatisfied:
		return "❌"
	case core.StatusManualReview:
		return "📋"
	case core.StatusNotApplicable:
		return "⚪"
	default:
		return "❓"
	}
}

func getStatusDisplay(status string) string {
	switch status {
	case core.StatusSatisfied:
		return "✅ SATISFIED"
	case core.StatusNotSatisfied:
		return "❌ NOT SATISFIED"
	case core.StatusManualReview:
		return "📋 MANUAL REVIEW REQUIRED"
	case core.StatusNotApplicable:
		return "⚪ NOT APPLICABLE"
	default:
		return "❓ UNKNOWN"
	}
}
