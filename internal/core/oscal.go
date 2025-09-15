package core

import (
	"encoding/json"
	"fmt"
	"time"
)

// OSCAL structures for compliance data exchange
type OSCALDocument struct {
	SystemSecurityPlan *SystemSecurityPlan `json:"system-security-plan,omitempty"`
	AssessmentResults  *AssessmentResults  `json:"assessment-results,omitempty"`
	PlanOfAction       *PlanOfAction       `json:"plan-of-action-and-milestones,omitempty"`
}

type SystemSecurityPlan struct {
	UUID      string            `json:"uuid"`
	Metadata  OSCALMetadata     `json:"metadata"`
	SystemID  string            `json:"system-id"`
	Controls  []OSCALControl    `json:"controls"`
	SystemInfo SystemCharacteristics `json:"system-characteristics"`
}

type AssessmentResults struct {
	UUID      string            `json:"uuid"`
	Metadata  OSCALMetadata     `json:"metadata"`
	Results   []ControlAssessment `json:"results"`
	Findings  []Finding         `json:"findings"`
}

type PlanOfAction struct {
	UUID      string            `json:"uuid"`
	Metadata  OSCALMetadata     `json:"metadata"`
	Actions   []Action          `json:"poam-items"`
}

type OSCALMetadata struct {
	Title          string    `json:"title"`
	Published      time.Time `json:"published"`
	LastModified   time.Time `json:"last-modified"`
	Version        string    `json:"version"`
	OSCALVersion   string    `json:"oscal-version"`
	Parties        []Party   `json:"parties,omitempty"`
}

type Party struct {
	UUID       string `json:"uuid"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	ShortName  string `json:"short-name,omitempty"`
}

type OSCALControl struct {
	ControlID      string                 `json:"control-id"`
	Title          string                 `json:"title"`
	Class          string                 `json:"class,omitempty"`
	Implementation []ControlImplementation `json:"implementations,omitempty"`
	Status         string                 `json:"status"`
}

type ControlImplementation struct {
	UUID           string `json:"uuid"`
	Source         string `json:"source"`
	Description    string `json:"description"`
	ImplementedBy  string `json:"implemented-requirement,omitempty"`
}

type SystemCharacteristics struct {
	SystemType        string              `json:"system-type"`
	Description       string              `json:"description"`
	SecuritySensitivity string            `json:"security-sensitivity-level"`
	SystemName        string              `json:"system-name"`
	SystemInfo        map[string]string   `json:"system-information"`
	OperatingEnvironment string            `json:"operating-environment"`
	Authorization     AuthorizationBoundary `json:"authorization-boundary"`
}

type AuthorizationBoundary struct {
	Description string                `json:"description"`
	Components  []SystemComponent     `json:"components"`
}

type SystemComponent struct {
	UUID        string            `json:"uuid"`
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Purpose     string            `json:"purpose"`
	Status      string            `json:"status"`
	Props       map[string]string `json:"props,omitempty"`
}

type ControlAssessment struct {
	ControlID     string    `json:"control-id"`
	Assessment    string    `json:"assessment"`
	Status        string    `json:"status"`
	Description   string    `json:"description"`
	Evidence      []Evidence `json:"evidence,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

type Evidence struct {
	UUID        string `json:"uuid"`
	Description string `json:"description"`
	Href        string `json:"href,omitempty"`
}

type Finding struct {
	UUID          string    `json:"uuid"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	ControlID     string    `json:"related-control"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	DateIdentified time.Time `json:"date-identified"`
	Remediation   string    `json:"remediation-tracking,omitempty"`
}

type Action struct {
	UUID          string    `json:"uuid"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	ControlID     string    `json:"related-control"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	DueDate       time.Time `json:"due-date"`
	Milestone     string    `json:"milestone-id,omitempty"`
	ResponsibleParty string `json:"responsible-party"`
}

// GenerateOSCALDocument creates an OSCAL-compliant document from scan results
func GenerateOSCALDocument(result *ScanResult) (*OSCALDocument, error) {
	now := time.Now()

	// Generate assessment results
	assessmentResults := &AssessmentResults{
		UUID: generateUUID(),
		Metadata: OSCALMetadata{
			Title:        fmt.Sprintf("Complyr Assessment Results - %s", result.ProjectType.Name),
			Published:    now,
			LastModified: now,
			Version:      "1.0",
			OSCALVersion: "1.0.4",
			Parties: []Party{
				{
					UUID:      generateUUID(),
					Type:      "organization",
					Name:      "Complyr Automated Assessment Tool",
					ShortName: "Complyr",
				},
			},
		},
		Results:  convertControlAssessments(result.ControlsAssessed),
		Findings: convertFindings(result),
	}

	// Generate Plan of Action and Milestones if there are issues
	var poam *PlanOfAction
	if hasIssues(result) {
		poam = &PlanOfAction{
			UUID: generateUUID(),
			Metadata: OSCALMetadata{
				Title:        fmt.Sprintf("Complyr POAM - %s", result.ProjectType.Name),
				Published:    now,
				LastModified: now,
				Version:      "1.0",
				OSCALVersion: "1.0.4",
			},
			Actions: generatePOAMItems(result),
		}
	}

	return &OSCALDocument{
		AssessmentResults: assessmentResults,
		PlanOfAction:     poam,
	}, nil
}

// ExportOSCALJSON exports the OSCAL document as JSON
func ExportOSCALJSON(document *OSCALDocument) ([]byte, error) {
	return json.MarshalIndent(document, "", "  ")
}

// Helper functions

func generateUUID() string {
	// Simple UUID generation for OSCAL compliance
	// In production, use a proper UUID library
	return fmt.Sprintf("complyr-%d", time.Now().UnixNano())
}

func convertControlAssessments(controls []ControlResult) []ControlAssessment {
	var assessments []ControlAssessment

	for _, control := range controls {
		assessment := ControlAssessment{
			ControlID:   control.ControlID,
			Assessment:  fmt.Sprintf("Automated assessment of %s", control.Title),
			Status:      mapStatusToOSCAL(control.Status),
			Description: control.Evidence,
			Timestamp:   time.Now(),
		}

		if control.Findings > 0 {
			assessment.Evidence = []Evidence{
				{
					UUID:        generateUUID(),
					Description: fmt.Sprintf("%d findings identified during automated scan", control.Findings),
				},
			}
		}

		assessments = append(assessments, assessment)
	}

	return assessments
}

func convertFindings(result *ScanResult) []Finding {
	var findings []Finding
	now := time.Now()

	// Convert banned technology findings
	for _, banned := range result.BannedTechFound {
		finding := Finding{
			UUID:           generateUUID(),
			Title:          fmt.Sprintf("Banned Technology: %s", banned.Name),
			Description:    banned.Reason,
			Severity:       mapSeverityToOSCAL(banned.Severity),
			Status:         "open",
			DateIdentified: now,
		}

		// Map to affected controls
		if len(banned.Violations) > 0 {
			finding.ControlID = banned.Violations[0].ControlID
			finding.Remediation = banned.Violations[0].Remediation
		}

		findings = append(findings, finding)
	}

	// Convert CVE findings
	for _, cve := range result.CVEsFound {
		finding := Finding{
			UUID:           generateUUID(),
			Title:          fmt.Sprintf("Vulnerability: %s in %s", cve.CVE, cve.Package),
			Description:    cve.Description,
			Severity:       mapSeverityToOSCAL(cve.Severity),
			Status:         "open",
			DateIdentified: now,
		}

		if len(cve.Violations) > 0 {
			finding.ControlID = cve.Violations[0].ControlID
			finding.Remediation = cve.Violations[0].Remediation
		}

		findings = append(findings, finding)
	}

	return findings
}

func generatePOAMItems(result *ScanResult) []Action {
	var actions []Action
	dueDate := time.Now().AddDate(0, 0, 30) // 30 days from now

	// Create POAM items for critical and high severity issues
	for _, banned := range result.BannedTechFound {
		if banned.Severity == SeverityCritical || banned.Severity == SeverityHigh {
			action := Action{
				UUID:             generateUUID(),
				Title:            fmt.Sprintf("Remove banned technology: %s", banned.Name),
				Description:      fmt.Sprintf("Remediate use of prohibited technology %s@%s", banned.Name, banned.Version),
				Severity:         mapSeverityToOSCAL(banned.Severity),
				Status:           "open",
				DueDate:          dueDate,
				ResponsibleParty: "development-team",
			}

			if len(banned.Violations) > 0 {
				action.ControlID = banned.Violations[0].ControlID
			}

			actions = append(actions, action)
		}
	}

	for _, cve := range result.CVEsFound {
		if cve.Severity == SeverityCritical || cve.Severity == SeverityHigh {
			action := Action{
				UUID:             generateUUID(),
				Title:            fmt.Sprintf("Patch vulnerability: %s", cve.CVE),
				Description:      fmt.Sprintf("Update %s@%s to remediate %s (Score: %.1f)", cve.Package, cve.Version, cve.CVE, cve.Score),
				Severity:         mapSeverityToOSCAL(cve.Severity),
				Status:           "open",
				DueDate:          dueDate,
				ResponsibleParty: "development-team",
			}

			if len(cve.Violations) > 0 {
				action.ControlID = cve.Violations[0].ControlID
			}

			actions = append(actions, action)
		}
	}

	return actions
}

func mapStatusToOSCAL(status string) string {
	switch status {
	case StatusSatisfied:
		return "satisfied"
	case StatusNotSatisfied:
		return "not-satisfied"
	case StatusManualReview:
		return "pending"
	case StatusNotApplicable:
		return "not-applicable"
	default:
		return "pending"
	}
}

func mapSeverityToOSCAL(severity string) string {
	switch severity {
	case SeverityCritical:
		return "high"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "moderate"
	case SeverityLow:
		return "low"
	default:
		return "moderate"
	}
}

func hasIssues(result *ScanResult) bool {
	return len(result.BannedTechFound) > 0 || len(result.CVEsFound) > 0 || result.Summary.CriticalIssues > 0 || result.Summary.HighIssues > 0
}

// MapNISTtoOSCAL provides mapping between NIST controls and OSCAL format
func MapNISTtoOSCAL(controls map[string]Control) []OSCALControl {
	var oscalControls []OSCALControl

	for id, control := range controls {
		oscalControl := OSCALControl{
			ControlID: id,
			Title:     control.Title,
			Class:     control.Family,
			Status:    "planned",
			Implementation: []ControlImplementation{
				{
					UUID:        generateUUID(),
					Source:      "automated-assessment",
					Description: control.Statement,
				},
			},
		}
		oscalControls = append(oscalControls, oscalControl)
	}

	return oscalControls
}