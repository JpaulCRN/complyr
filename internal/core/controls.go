package core

// Control represents a NIST 800-53 control
type Control struct {
	ID        string
	Title     string
	Family    string
	Statement string
	Guidance  string
	Automated bool
}

// TRLControlSet defines controls for each Technology Readiness Level
type TRLControlSet struct {
	Required []string
	Optional []string
	Deferred []string
}

// ProjectContext holds project-specific information
type ProjectContext struct {
	TRL          int
	ContractType string // "Phase I SBIR", "Phase II SBIR", "Other"
	Customer     string // "DISA", "Army", "Air Force", etc.
}

// GetNISTControls returns the essential NIST 800-53 controls for automated assessment
// This is the fallback version - the enhanced version loads from official OSCAL catalog
func GetNISTControls() map[string]Control {
	return map[string]Control{
		"AC-2": {
			ID:        "AC-2",
			Title:     "Account Management",
			Family:    "AC",
			Statement: "Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
			Guidance:  "Account management includes the identification of account types and assignment of associated authorizations.",
			Automated: true,
		},
		"AC-3": {
			ID:        "AC-3",
			Title:     "Access Enforcement",
			Family:    "AC",
			Statement: "Enforce approved authorizations for logical access to information and system resources.",
			Guidance:  "Access control policies control access between active entities and passive entities.",
			Automated: true,
		},
		"AC-6": {
			ID:        "AC-6",
			Title:     "Least Privilege",
			Family:    "AC",
			Statement: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.",
			Guidance:  "Least privilege incorporates access enforcement and flow enforcement policies.",
			Automated: true,
		},
		"AU-2": {
			ID:        "AU-2",
			Title:     "Audit Events",
			Family:    "AU",
			Statement: "Determine that the information system is capable of auditing defined events.",
			Guidance:  "An event is any observable occurrence in an organizational information system.",
			Automated: true,
		},
		"AU-3": {
			ID:        "AU-3",
			Title:     "Audit Record Content",
			Family:    "AU",
			Statement: "Ensure that audit records contain information that establishes what type of event occurred.",
			Guidance:  "Audit record content includes time stamps, source addresses, user identifiers, and event descriptions.",
			Automated: true,
		},
		"IA-2": {
			ID:        "IA-2",
			Title:     "Identification and Authentication",
			Family:    "IA",
			Statement: "Uniquely identify and authenticate organizational users.",
			Guidance:  "Organizational users include employees or individuals with equivalent status.",
			Automated: true,
		},
		"IA-5": {
			ID:        "IA-5",
			Title:     "Authenticator Management",
			Family:    "IA",
			Statement: "Manage information system authenticators for initial distribution and lost/compromised authenticators.",
			Guidance:  "Individual authenticators include passwords, tokens, biometrics, and PKI certificates.",
			Automated: true,
		},
		"SC-8": {
			ID:        "SC-8",
			Title:     "Transmission Confidentiality and Integrity",
			Family:    "SC",
			Statement: "Protect the confidentiality and integrity of transmitted information.",
			Guidance:  "This control applies to both internal and external networks and all types of system components.",
			Automated: true,
		},
		"SC-13": {
			ID:        "SC-13",
			Title:     "Cryptographic Protection",
			Family:    "SC",
			Statement: "Implement cryptographic mechanisms to prevent unauthorized disclosure of information.",
			Guidance:  "Cryptographic mechanisms include protected distribution systems.",
			Automated: true,
		},
		"SI-2": {
			ID:        "SI-2",
			Title:     "Flaw Remediation",
			Family:    "SI",
			Statement: "Identify, report, and correct information system flaws.",
			Guidance:  "Install security-relevant software and firmware updates within defined time periods.",
			Automated: true,
		},
		"SI-3": {
			ID:        "SI-3",
			Title:     "Malicious Code Protection",
			Family:    "SI",
			Statement: "Implement malicious code protection mechanisms at system entry and exit points.",
			Guidance:  "Malicious code includes viruses, worms, Trojan horses, and spyware.",
			Automated: true,
		},
		"SI-4": {
			ID:        "SI-4",
			Title:     "Information System Monitoring",
			Family:    "SI",
			Statement: "Monitor the information system to detect attacks and indicators of potential attacks.",
			Guidance:  "Information system monitoring includes external and internal monitoring.",
			Automated: true,
		},
		"SI-7": {
			ID:        "SI-7",
			Title:     "Software, Firmware, and Information Integrity",
			Family:    "SI",
			Statement: "Employ integrity verification tools to detect unauthorized changes to software and firmware.",
			Guidance:  "Unauthorized changes can occur due to errors or malicious activity.",
			Automated: true,
		},
		"CM-2": {
			ID:        "CM-2",
			Title:     "Baseline Configuration",
			Family:    "CM",
			Statement: "Develop, document, and maintain a current baseline configuration of the information system.",
			Guidance:  "Baseline configurations include information about system components, network topology, and logical placement.",
			Automated: true,
		},
	}
}

// GetTRLControls maps Technology Readiness Levels to required controls using OSCAL baselines
func GetTRLControls(trl int) TRLControlSet {
	// First try to get OSCAL-based baseline
	impactLevel := MapTRLToImpactLevel(trl)
	baseline := GetSoftwareBaseline(impactLevel)

	if len(baseline) > 0 {
		// Use OSCAL baseline with TRL-specific filtering
		return TRLControlSet{
			Required: filterControlsForTRL(baseline, trl),
			Optional: getOptionalControlsForTRL(baseline, trl),
			Deferred: getDeferredControlsForTRL(baseline, trl),
		}
	}

	// Fall back to hardcoded mappings if OSCAL fails
	return getLegacyTRLControls(trl)
}

// Legacy TRL controls mapping (fallback)
var legacyTRLControls = map[int]TRLControlSet{
	// TRL 1-2: Basic research, concept validation
	1: {
		Required: []string{"SI-2"}, // Just vulnerability scanning
		Optional: []string{"SI-3", "CM-2"},
		Deferred: []string{"AC-2", "AC-3", "AU-2", "IA-2", "SC-8", "SC-13"},
	},
	2: {
		Required: []string{"SI-2"},
		Optional: []string{"SI-3", "CM-2"},
		Deferred: []string{"AC-2", "AC-3", "AU-2", "IA-2", "SC-8", "SC-13"},
	},
	// TRL 3-4: Proof of concept, component validation
	3: {
		Required: []string{"SI-2", "SI-3", "CM-2"},
		Optional: []string{"AU-2", "SC-13"},
		Deferred: []string{"AC-2", "AC-3", "IA-2", "SC-8"},
	},
	4: {
		Required: []string{"SI-2", "SI-3", "CM-2", "AU-2"},
		Optional: []string{"SC-13", "SI-4"},
		Deferred: []string{"AC-2", "AC-3", "IA-2", "SC-8"},
	},
	// TRL 5-6: System validation in relevant environment
	5: {
		Required: []string{"SI-2", "SI-3", "CM-2", "AU-2", "AU-3", "AC-3"},
		Optional: []string{"IA-2", "SC-8", "SC-13", "SI-4"},
		Deferred: []string{"AC-2", "IA-5"},
	},
	6: {
		Required: []string{"SI-2", "SI-3", "CM-2", "AU-2", "AU-3", "AC-3", "SC-13"},
		Optional: []string{"IA-2", "SC-8", "SI-4", "AC-2"},
		Deferred: []string{"IA-5"},
	},
	// TRL 7-8: Prototype demonstration, system complete
	7: {
		Required: []string{
			"SI-2", "SI-3", "SI-4", "CM-2", "AU-2", "AU-3",
			"AC-2", "AC-3", "IA-2", "SC-8", "SC-13",
		},
		Optional: []string{"IA-5", "AC-6", "SI-7"},
		Deferred: []string{},
	},
	8: {
		Required: []string{
			"SI-2", "SI-3", "SI-4", "SI-7", "CM-2", "AU-2", "AU-3",
			"AC-2", "AC-3", "AC-6", "IA-2", "IA-5", "SC-8", "SC-13",
		},
		Optional: []string{},
		Deferred: []string{},
	},
	// TRL 9: Production system
	9: {
		Required: getAllNISTControlIDs(), // All controls
		Optional: []string{},
		Deferred: []string{},
	},
}

// Helper functions for OSCAL-based TRL mapping
func filterControlsForTRL(baseline []string, trl int) []string {
	// TRL 1-3: Start with basic security controls
	if trl <= 3 {
		basic := []string{"SI-2", "SI-3", "CM-2"}
		return intersect(baseline, basic)
	}

	// TRL 4-6: Add authentication and audit
	if trl <= 6 {
		moderate := []string{"SI-2", "SI-3", "CM-2", "AU-2", "AU-3", "AC-3", "IA-2", "SC-13"}
		return intersect(baseline, moderate)
	}

	// TRL 7+: Most or all baseline controls
	return baseline
}

func getOptionalControlsForTRL(baseline []string, trl int) []string {
	// Controls that are recommended but not required at this TRL
	if trl < 9 {
		allControls := GetSoftwareBaseline("high")
		required := filterControlsForTRL(baseline, trl)
		return difference(allControls, required)
	}
	return []string{}
}

func getDeferredControlsForTRL(baseline []string, trl int) []string {
	// Controls that can be deferred until higher TRL
	if trl <= 6 {
		advanced := []string{"AU-4", "AU-9", "SC-28", "SI-11", "SI-16", "SR-3", "SR-4", "SR-5"}
		return intersect(GetSoftwareBaseline("high"), advanced)
	}
	return []string{}
}

func getLegacyTRLControls(trl int) TRLControlSet {
	if controls, exists := legacyTRLControls[trl]; exists {
		return controls
	}
	// Default to TRL 3 if not found
	return legacyTRLControls[3]
}

// Utility functions
func intersect(slice1, slice2 []string) []string {
	result := []string{}
	set := make(map[string]bool)

	for _, item := range slice2 {
		set[item] = true
	}

	for _, item := range slice1 {
		if set[item] {
			result = append(result, item)
		}
	}

	return result
}

func difference(slice1, slice2 []string) []string {
	result := []string{}
	set := make(map[string]bool)

	for _, item := range slice2 {
		set[item] = true
	}

	for _, item := range slice1 {
		if !set[item] {
			result = append(result, item)
		}
	}

	return result
}

// Helper function to get all control IDs
func getAllNISTControlIDs() []string {
	controls := GetNISTControls()
	ids := make([]string, 0, len(controls))
	for id := range controls {
		ids = append(ids, id)
	}
	return ids
}

// TRL descriptions for display
var TRLDescriptions = map[int]string{
	1: "Basic Research",
	2: "Technology Concept",
	3: "Proof of Concept",
	4: "Component Validation",
	5: "System Validation",
	6: "System Demonstration",
	7: "Prototype Testing",
	8: "System Complete",
	9: "Production Ready",
}

// GetBannedTechnologies returns the list of prohibited technologies
func GetBannedTechnologies() map[string]BannedTech {
	return map[string]BannedTech{
		"deepseek": {
			Name:     "deepseek",
			Reason:   "Prohibited AI model - security/policy violation",
			Severity: SeverityCritical,
			Violations: []ControlViolation{
				{
					ControlID:   "SI-7",
					Framework:   FrameworkNIST800_53,
					Title:       "Software, Firmware, and Information Integrity",
					Severity:    SeverityCritical,
					Finding:     "Prohibited software component detected",
					Rationale:   "Use of banned AI service violates organizational security policy",
					Remediation: "Remove dependency immediately and replace with approved alternative",
				},
			},
		},
		"qwen": {
			Name:     "qwen",
			Reason:   "Prohibited AI model - security/policy violation",
			Severity: SeverityCritical,
			Violations: []ControlViolation{
				{
					ControlID:   "SI-7",
					Framework:   FrameworkNIST800_53,
					Title:       "Software, Firmware, and Information Integrity",
					Severity:    SeverityCritical,
					Finding:     "Prohibited software component detected",
					Rationale:   "Use of banned AI service violates organizational security policy",
					Remediation: "Remove dependency immediately and replace with approved alternative",
				},
			},
		},
		"jquery": {
			Name:     "jquery",
			Reason:   "Legacy framework with known security vulnerabilities",
			Severity: SeverityHigh,
			Violations: []ControlViolation{
				{
					ControlID:   "SI-2",
					Framework:   FrameworkNIST800_53,
					Title:       "Flaw Remediation",
					Severity:    SeverityHigh,
					Finding:     "Vulnerable framework version detected",
					Rationale:   "jQuery versions below 3.5.0 have known XSS vulnerabilities",
					Remediation: "Update to jQuery 3.6+ or migrate to modern framework",
				},
			},
		},
	}
}

// LibraryKeywords defines security-relevant library patterns
var LibraryKeywords = map[string][]string{
	"authentication": {"auth", "passport", "oauth", "jwt", "session", "login"},
	"authorization":  {"authz", "rbac", "acl", "permission", "role", "casbin"},
	"logging":        {"log", "winston", "bunyan", "pino", "logrus", "zap"},
	"cryptography":   {"crypto", "bcrypt", "scrypt", "argon2", "tls", "ssl", "aes"},
	"monitoring":     {"monitor", "metrics", "prometheus", "sentry", "datadog"},
}
