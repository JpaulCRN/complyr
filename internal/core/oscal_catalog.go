package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OSCALCatalog represents the official NIST 800-53 catalog structure
type OSCALCatalog struct {
	Catalog struct {
		UUID     string `json:"uuid"`
		Metadata struct {
			Title        string    `json:"title"`
			LastModified time.Time `json:"last-modified"`
			Version      string    `json:"version"`
			OSCALVersion string    `json:"oscal-version"`
		} `json:"metadata"`
		Groups []ControlGroup `json:"groups"`
	} `json:"catalog"`
}

type ControlGroup struct {
	ID       string                 `json:"id"`
	Class    string                 `json:"class"`
	Title    string                 `json:"title"`
	Controls []OSCALControlOfficial `json:"controls"`
}

type OSCALControlOfficial struct {
	ID    string `json:"id"`
	Class string `json:"class"`
	Title string `json:"title"`
	Props []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"props"`
	Parts []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Prose string `json:"prose"`
		Parts []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Prose string `json:"prose"`
		} `json:"parts,omitempty"`
	} `json:"parts"`
	Controls []OSCALControlOfficial `json:"controls,omitempty"` // For control enhancements
}

// SoftwareRelevantControls defines which controls can be assessed through code analysis
var SoftwareRelevantControls = map[string]struct{
	Automatable bool
	Category    string
	Assessor    func(*ScanResult) string // Function to assess this control
}{
	// Access Control
	"ac-2": {true, "authentication", nil},      // Account Management
	"ac-3": {true, "authorization", nil},       // Access Enforcement
	"ac-6": {true, "authorization", nil},       // Least Privilege
	"ac-17": {true, "remote_access", nil},      // Remote Access
	"ac-25": {true, "reference_monitor", nil},  // Reference Monitor

	// Audit and Accountability
	"au-2": {true, "logging", nil},           // Audit Events
	"au-3": {true, "logging", nil},           // Content of Audit Records
	"au-4": {true, "logging", nil},           // Audit Storage Capacity
	"au-8": {true, "logging", nil},           // Time Stamps
	"au-9": {true, "logging", nil},           // Protection of Audit Information
	"au-10": {true, "non_repudiation", nil},  // Non-repudiation

	// Configuration Management
	"cm-2": {true, "baseline", nil},          // Baseline Configuration
	"cm-4": {true, "change_control", nil},    // Security Impact Analysis
	"cm-6": {true, "settings", nil},          // Configuration Settings
	"cm-7": {true, "functionality", nil},     // Least Functionality
	"cm-8": {true, "inventory", nil},         // Information System Component Inventory
	"cm-11": {true, "software_usage", nil},   // User-Installed Software

	// Contingency Planning
	"cp-10": {true, "recovery", nil}, // Information System Recovery

	// Identification and Authentication
	"ia-2": {true, "authentication", nil},     // User Identification and Authentication
	"ia-5": {true, "authenticators", nil},     // Authenticator Management
	"ia-7": {true, "crypto_auth", nil},        // Cryptographic Module Authentication
	"ia-8": {true, "non_repudiation", nil},    // Identification and Authentication (Non-Org Users)
	"ia-9": {true, "service_auth", nil},       // Service Identification and Authentication

	// Risk Assessment
	"ra-5": {true, "vulnerability_scanning", nil}, // Vulnerability Scanning

	// System and Services Acquisition
	"sa-10": {true, "dev_config_mgmt", nil},    // Developer Configuration Management
	"sa-11": {true, "dev_testing", nil},        // Developer Testing and Evaluation
	"sa-15": {true, "dev_processes", nil},      // Development Process, Standards, and Tools
	"sa-22": {true, "unsupported_components", nil}, // Unsupported System Components

	// System and Communications Protection
	"sc-8": {true, "transmission_protection", nil},  // Transmission Confidentiality and Integrity
	"sc-12": {true, "key_management", nil},          // Cryptographic Key Establishment
	"sc-13": {true, "cryptography", nil},            // Cryptographic Protection
	"sc-23": {true, "session_auth", nil},            // Session Authenticity
	"sc-28": {true, "data_at_rest", nil},            // Protection of Information at Rest

	// System and Information Integrity
	"si-2": {true, "flaw_remediation", nil},         // Flaw Remediation
	"si-3": {true, "malicious_code", nil},           // Malicious Code Protection
	"si-4": {true, "monitoring", nil},               // Information System Monitoring
	"si-7": {true, "integrity", nil},                // Software, Firmware, and Information Integrity
	"si-10": {true, "input_validation", nil},        // Information Input Validation
	"si-11": {true, "error_handling", nil},          // Error Handling
	"si-16": {true, "memory_protection", nil},       // Memory Protection

	// Supply Chain Risk Management
	"sr-3": {true, "supply_chain_controls", nil},    // Supply Chain Controls and Processes
	"sr-4": {true, "provenance", nil},               // Provenance
	"sr-5": {true, "acquisition_strategies", nil},   // Acquisition Strategies
}

// LoadOSCALCatalog fetches the official NIST 800-53 catalog
func LoadOSCALCatalog() (*OSCALCatalog, error) {
	url := "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OSCAL catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OSCAL catalog: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSCAL catalog: %w", err)
	}

	var catalog OSCALCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse OSCAL catalog: %w", err)
	}

	return &catalog, nil
}

// LoadOSCALCatalogFromFile loads the catalog from a local file (for offline use)
func LoadOSCALCatalogFromFile(filepath string) (*OSCALCatalog, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSCAL catalog file: %w", err)
	}

	var catalog OSCALCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse OSCAL catalog: %w", err)
	}

	return &catalog, nil
}

// FilterSoftwareControls returns only software-relevant controls from the catalog
func FilterSoftwareControls(catalog *OSCALCatalog) map[string]OSCALControlOfficial {
	filtered := make(map[string]OSCALControlOfficial)

	for _, group := range catalog.Catalog.Groups {
		for _, control := range group.Controls {
			controlID := strings.ToLower(control.ID)
			if _, relevant := SoftwareRelevantControls[controlID]; relevant {
				filtered[controlID] = control

				// Also include control enhancements if parent is relevant
				for _, enhancement := range control.Controls {
					enhancementID := strings.ToLower(enhancement.ID)
					filtered[enhancementID] = enhancement
				}
			}
		}
	}

	return filtered
}

// GetControlStatement extracts the main statement from an OSCAL control
func GetControlStatement(control OSCALControlOfficial) string {
	for _, part := range control.Parts {
		if part.Name == "statement" {
			return part.Prose
		}
	}
	return ""
}

// GetControlGuidance extracts the guidance from an OSCAL control
func GetControlGuidance(control OSCALControlOfficial) string {
	for _, part := range control.Parts {
		if part.Name == "guidance" {
			return part.Prose
		}
	}
	return ""
}

// MapOSCALToComplyr converts official OSCAL controls to Complyr's internal format
func MapOSCALToComplyr(oscalControl OSCALControlOfficial) Control {
	return Control{
		ID:        strings.ToUpper(oscalControl.ID),
		Title:     oscalControl.Title,
		Family:    strings.ToUpper(strings.Split(oscalControl.ID, "-")[0]),
		Statement: GetControlStatement(oscalControl),
		Guidance:  GetControlGuidance(oscalControl),
		Automated: SoftwareRelevantControls[strings.ToLower(oscalControl.ID)].Automatable,
	}
}

// EnhancedNISTControls loads official controls but filters to software-relevant ones
func EnhancedNISTControls() (map[string]Control, error) {
	// Try to load from cache first
	cacheFile := ".oscal-cache.json"
	var catalog *OSCALCatalog
	var err error

	// Check if cache exists and is recent (less than 7 days old)
	if info, err := os.Stat(cacheFile); err == nil {
		if time.Since(info.ModTime()) < 7*24*time.Hour {
			catalog, err = LoadOSCALCatalogFromFile(cacheFile)
			if err == nil {
				goto ProcessCatalog
			}
		}
	}

	// Load from online source
	catalog, err = LoadOSCALCatalog()
	if err != nil {
		// Fall back to embedded minimal set if online fetch fails
		return GetNISTControls(), nil
	}

	// Cache for future use
	if data, err := json.Marshal(catalog); err == nil {
		os.WriteFile(cacheFile, data, 0644)
	}

ProcessCatalog:
	// Filter to software-relevant controls
	softwareControls := FilterSoftwareControls(catalog)

	// Convert to Complyr format
	complyrControls := make(map[string]Control)
	for id, oscalControl := range softwareControls {
		complyrControl := MapOSCALToComplyr(oscalControl)
		complyrControls[strings.ToUpper(id)] = complyrControl
	}

	// If we got fewer controls than our baseline, merge with defaults
	if len(complyrControls) < len(GetNISTControls()) {
		for id, control := range GetNISTControls() {
			if _, exists := complyrControls[id]; !exists {
				complyrControls[id] = control
			}
		}
	}

	return complyrControls, nil
}

// GetSoftwareBaseline returns appropriate controls based on system impact level
func GetSoftwareBaseline(impactLevel string) []string {
	// Based on NIST 800-53B baselines, filtered for software controls
	switch strings.ToLower(impactLevel) {
	case "low":
		return []string{
			"AC-2", "AC-3", "AU-2", "AU-3", "CM-2", "IA-2", "IA-5",
			"SC-13", "SI-2", "SI-3",
		}
	case "moderate":
		return []string{
			"AC-2", "AC-3", "AC-6", "AU-2", "AU-3", "AU-8", "CM-2", "CM-4",
			"CM-6", "CM-7", "IA-2", "IA-5", "IA-8", "RA-5", "SA-11", "SC-8",
			"SC-13", "SC-23", "SI-2", "SI-3", "SI-4", "SI-7", "SI-10",
		}
	case "high":
		return []string{
			"AC-2", "AC-3", "AC-6", "AC-17", "AU-2", "AU-3", "AU-4", "AU-8",
			"AU-9", "CM-2", "CM-4", "CM-6", "CM-7", "CM-8", "IA-2", "IA-5",
			"IA-8", "IA-9", "RA-5", "SA-10", "SA-11", "SA-15", "SA-22",
			"SC-8", "SC-12", "SC-13", "SC-23", "SC-28", "SI-2", "SI-3",
			"SI-4", "SI-7", "SI-10", "SI-11", "SI-16", "SR-3", "SR-4", "SR-5",
		}
	default:
		return []string{}
	}
}

// MapTRLToImpactLevel maps Technology Readiness Levels to NIST impact levels
func MapTRLToImpactLevel(trl int) string {
	switch {
	case trl <= 3:
		return "low"
	case trl <= 6:
		return "moderate"
	case trl >= 7:
		return "high"
	default:
		return "low"
	}
}