package core

// Add these type definitions to your core package if they don't exist

// ScanResult represents the complete scan results
type ScanResult struct {
	ProjectPath      string
	ProjectType      ProjectType
	ProjectContext   ProjectContext
	Dependencies     []Dependency
	BannedTechFound  []BannedTech
	CVEsFound        []CVE
	ControlsAssessed []ControlResult
	TRLAssessment    TRLAssessmentResult
	Summary          ScanSummary
	ComplianceScore  float64
}

// ProjectType represents the detected project type
type ProjectType struct {
	Name        string
	Language    string
	ConfigFiles []string
}

// Dependency represents a project dependency
type Dependency struct {
	Name    string
	Version string
	File    string
	Type    string //
}

// BannedTech represents a banned technology
type BannedTech struct {
	Name       string
	Reason     string
	Severity   string
	Version    string
	File       string
	Violations []ControlViolation
}

// CVE represents a Common Vulnerabilities and Exposures entry
type CVE struct {
	CVE         string
	Package     string
	Version     string
	Score       float64
	Severity    string
	Description string
	Violations  []ControlViolation
}

// ControlViolation represents a control violation
type ControlViolation struct {
	ControlID   string
	Framework   string
	Title       string
	Severity    string
	Finding     string
	Rationale   string
	Remediation string
}

// ScanSummary contains summary statistics
type ScanSummary struct {
	TotalControls     int
	SatisfiedControls int
	CriticalIssues    int
	HighIssues        int
	MediumIssues      int
	LowIssues         int
	ATOReadiness      float64
}

// Status constants
const (
	StatusSatisfied     = "Satisfied"
	StatusNotSatisfied  = "Not Satisfied"
	StatusManualReview  = "Manual Review Required"
	StatusNotApplicable = "Not Applicable"
)

// Severity constants
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
)

// Framework constants
const (
	FrameworkNIST800_53 = "NIST 800-53"
)
