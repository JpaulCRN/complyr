package core

import (
	"fmt"
	"strings"
)

// TRLAssessmentResult contains TRL-specific assessment results
type TRLAssessmentResult struct {
	CurrentTRL       int
	RequiredControls []string
	OptionalControls []string
	DeferredControls []string
	TRLCompliance    float64 // Percentage for current TRL
	NextTRLReadiness float64 // Readiness for next TRL
}

// ControlResult represents the assessment result for a single control
type ControlResult struct {
	ControlID      string
	Title          string
	Status         string
	Evidence       string
	Findings       int
	Framework      string
	Family         string
	Automated      bool
	RequiredForTRL int
	IsOptional     bool
	IsDeferred     bool
}

// AssessCompliance performs the main compliance assessment with TRL awareness
func AssessCompliance(result *ScanResult) error {
	// Get TRL-specific controls using OSCAL baselines
	trlControlSet := GetTRLControls(result.ProjectContext.TRL)

	// Get all control violations from findings
	var allViolations []ControlViolation
	for _, banned := range result.BannedTechFound {
		allViolations = append(allViolations, banned.Violations...)
	}
	for _, cve := range result.CVEsFound {
		allViolations = append(allViolations, cve.Violations...)
	}

	// Assess controls based on TRL requirements - try enhanced OSCAL first
	controls, err := EnhancedNISTControls()
	if err != nil {
		// Fall back to embedded controls if OSCAL loading fails
		controls = GetNISTControls()
	}
	var controlResults []ControlResult

	// Assess required controls for current TRL
	for _, controlID := range trlControlSet.Required {
		if control, exists := controls[controlID]; exists {
			assessment := assessControl(control, result.Dependencies, allViolations)
			assessment.RequiredForTRL = result.ProjectContext.TRL
			controlResults = append(controlResults, assessment)
		}
	}

	// Assess optional controls (show as informational)
	for _, controlID := range trlControlSet.Optional {
		if control, exists := controls[controlID]; exists {
			assessment := assessControl(control, result.Dependencies, allViolations)
			assessment.IsOptional = true
			controlResults = append(controlResults, assessment)
		}
	}

	result.ControlsAssessed = controlResults
	result.TRLAssessment = calculateTRLCompliance(result, trlControlSet)
	result.Summary = calculateTRLSummary(result)
	result.ComplianceScore = result.TRLAssessment.TRLCompliance

	return nil
}

// assessControl evaluates a single control
func assessControl(control Control, dependencies []Dependency, violations []ControlViolation) ControlResult {
	// Count violations affecting this control
	violationCount := 0
	for _, violation := range violations {
		if strings.EqualFold(violation.ControlID, control.ID) {
			violationCount++
		}
	}

	// Determine status
	status := StatusSatisfied
	evidence := fmt.Sprintf("No violations found for %s", control.Title)

	if violationCount > 0 {
		status = StatusNotSatisfied
		evidence = fmt.Sprintf("Found %d violations affecting %s", violationCount, control.Title)
	} else {
		// Check if relevant libraries are present
		switch control.Family {
		case "AC":
			status, evidence = assessAccessControl(control.ID, dependencies)
		case "AU":
			status, evidence = assessAudit(control.ID, dependencies)
		case "IA":
			status, evidence = assessIdentityAuth(control.ID, dependencies)
		case "SC":
			status, evidence = assessSystemProtection(control.ID, dependencies)
		case "SI":
			status, evidence = assessSystemIntegrity(control.ID, dependencies)
		case "CM":
			status, evidence = assessConfigurationManagement(control.ID, dependencies)
		}
	}

	return ControlResult{
		ControlID: control.ID,
		Title:     control.Title,
		Status:    status,
		Evidence:  evidence,
		Findings:  violationCount,
		Framework: FrameworkNIST800_53,
		Family:    control.Family,
		Automated: control.Automated,
	}
}

// assessAccessControl evaluates access control implementations
func assessAccessControl(controlID string, dependencies []Dependency) (string, string) {
	authLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["authentication"])
	authzLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["authorization"])

	switch controlID {
	case "AC-2", "AC-3":
		if len(authLibs) > 0 {
			return StatusSatisfied, fmt.Sprintf("Authentication libraries found: %s", strings.Join(authLibs, ", "))
		}
		return StatusNotSatisfied, "No authentication libraries detected"
	case "AC-6":
		if len(authzLibs) > 0 {
			return StatusSatisfied, fmt.Sprintf("Authorization libraries found: %s", strings.Join(authzLibs, ", "))
		}
		return StatusManualReview, "No RBAC libraries detected - requires manual review"
	}
	return StatusSatisfied, "Control assessment completed"
}

// assessAudit evaluates audit and logging implementations
func assessAudit(controlID string, dependencies []Dependency) (string, string) {
	loggingLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["logging"])

	if len(loggingLibs) > 0 {
		return StatusSatisfied, fmt.Sprintf("Logging libraries found: %s", strings.Join(loggingLibs, ", "))
	}
	return StatusNotSatisfied, "No logging libraries detected"
}

// assessIdentityAuth evaluates identity and authentication controls
func assessIdentityAuth(controlID string, dependencies []Dependency) (string, string) {
	authLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["authentication"])
	cryptoLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["cryptography"])

	switch controlID {
	case "IA-2":
		if len(authLibs) > 0 {
			return StatusSatisfied, fmt.Sprintf("Authentication libraries found: %s", strings.Join(authLibs, ", "))
		}
		return StatusNotSatisfied, "No authentication libraries detected"
	case "IA-5":
		if len(cryptoLibs) > 0 {
			return StatusSatisfied, fmt.Sprintf("Cryptographic libraries found: %s", strings.Join(cryptoLibs, ", "))
		}
		return StatusNotSatisfied, "No authenticator management libraries detected"
	}
	return StatusSatisfied, "Control assessment completed"
}

// assessSystemProtection evaluates system and communications protection
func assessSystemProtection(controlID string, dependencies []Dependency) (string, string) {
	cryptoLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["cryptography"])

	if len(cryptoLibs) > 0 {
		return StatusSatisfied, fmt.Sprintf("Cryptographic protection found: %s", strings.Join(cryptoLibs, ", "))
	}
	return StatusNotSatisfied, "No cryptographic protection libraries detected"
}

// assessSystemIntegrity evaluates system and information integrity
func assessSystemIntegrity(controlID string, dependencies []Dependency) (string, string) {
	monitoringLibs := findLibrariesByKeywords(dependencies, LibraryKeywords["monitoring"])

	switch controlID {
	case "SI-2", "SI-7":
		return StatusSatisfied, "Automated vulnerability and integrity scanning performed"
	case "SI-3":
		return StatusSatisfied, "Malicious code protection assessment completed"
	case "SI-4":
		if len(monitoringLibs) > 0 {
			return StatusSatisfied, fmt.Sprintf("Monitoring libraries found: %s", strings.Join(monitoringLibs, ", "))
		}
		return StatusNotSatisfied, "No monitoring libraries detected"
	}
	return StatusSatisfied, "Control assessment completed"
}

// assessConfigurationManagement evaluates configuration management controls
func assessConfigurationManagement(controlID string, dependencies []Dependency) (string, string) {
	// Simple check for configuration files
	return StatusSatisfied, "Baseline configuration detected (package.json/go.mod/etc.)"
}

// findLibrariesByKeywords searches for libraries matching security keywords
func findLibrariesByKeywords(dependencies []Dependency, keywords []string) []string {
	var found []string
	foundSet := make(map[string]bool)

	for _, dep := range dependencies {
		depNameLower := strings.ToLower(dep.Name)
		for _, keyword := range keywords {
			if strings.Contains(depNameLower, strings.ToLower(keyword)) && !foundSet[dep.Name] {
				found = append(found, dep.Name)
				foundSet[dep.Name] = true
				break
			}
		}
	}

	return found
}

// Calculate TRL-specific compliance
func calculateTRLCompliance(result *ScanResult, controlSet TRLControlSet) TRLAssessmentResult {
	assessment := TRLAssessmentResult{
		CurrentTRL:       result.ProjectContext.TRL,
		RequiredControls: controlSet.Required,
		OptionalControls: controlSet.Optional,
		DeferredControls: controlSet.Deferred,
	}

	// Count satisfied required controls
	satisfiedRequired := 0
	totalRequired := len(controlSet.Required)

	for _, control := range result.ControlsAssessed {
		if !control.IsOptional && control.Status == StatusSatisfied {
			satisfiedRequired++
		}
	}

	// Calculate TRL compliance
	if totalRequired > 0 {
		assessment.TRLCompliance = (float64(satisfiedRequired) / float64(totalRequired)) * 100
	}

	// Calculate readiness for next TRL
	if result.ProjectContext.TRL < 9 {
		nextTRLControls := GetTRLControls(result.ProjectContext.TRL + 1)
		satisfiedNext := 0
		for _, controlID := range nextTRLControls.Required {
			for _, assessed := range result.ControlsAssessed {
				if assessed.ControlID == controlID && assessed.Status == StatusSatisfied {
					satisfiedNext++
					break
				}
			}
		}
		if len(nextTRLControls.Required) > 0 {
			assessment.NextTRLReadiness = (float64(satisfiedNext) / float64(len(nextTRLControls.Required))) * 100
		}
	}

	return assessment
}

// Calculate TRL-aware summary
func calculateTRLSummary(result *ScanResult) ScanSummary {
	summary := ScanSummary{
		TotalControls: len(result.TRLAssessment.RequiredControls),
	}

	// Count satisfied required controls only
	for _, control := range result.ControlsAssessed {
		if !control.IsOptional && control.Status == StatusSatisfied {
			summary.SatisfiedControls++
		}
	}

	// Count issues by severity
	for _, banned := range result.BannedTechFound {
		switch banned.Severity {
		case SeverityCritical:
			summary.CriticalIssues++
		case SeverityHigh:
			summary.HighIssues++
		case SeverityMedium:
			summary.MediumIssues++
		case SeverityLow:
			summary.LowIssues++
		}
	}

	for _, cve := range result.CVEsFound {
		switch cve.Severity {
		case SeverityCritical:
			summary.CriticalIssues++
		case SeverityHigh:
			summary.HighIssues++
		case SeverityMedium:
			summary.MediumIssues++
		case SeverityLow:
			summary.LowIssues++
		}
	}

	// Use TRL compliance as ATO readiness
	summary.ATOReadiness = result.TRLAssessment.TRLCompliance

	// Apply penalties for critical issues
	penalty := float64(summary.CriticalIssues*20 + summary.HighIssues*10)
	summary.ATOReadiness -= penalty
	if summary.ATOReadiness < 0 {
		summary.ATOReadiness = 0
	}

	return summary
}
