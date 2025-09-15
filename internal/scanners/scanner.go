package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/JpaulCRN/complyr/internal/core"
)

// ComplyrConfig represents .complyr.yaml configuration
type ComplyrConfig struct {
	Project struct {
		TRL          int    `yaml:"trl"`
		ContractType string `yaml:"contract_type"`
		Customer     string `yaml:"customer"`
	} `yaml:"project"`
}

// PerformScan executes a complete compliance scan with TRL awareness and improved error handling
func PerformScan(path string) (*core.ScanResult, error) {
	// Validate inputs
	if err := core.ValidateProjectPath(path); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, core.NewScanError("validation", "scan path does not exist", err)
	}

	// Create error collector for non-critical errors
	errorCollector := core.NewErrorCollector("scan")

	// Detect project context (TRL, contract type, etc.)
	context := detectProjectContext(path)

	// Detect project type
	projectType := detectProjectType(path)
	fmt.Printf("📁 Project: %s (%s) | TRL %d", projectType.Name, projectType.Language, context.TRL)
	if context.ContractType != "" {
		fmt.Printf(" | %s", context.ContractType)
	}
	fmt.Println()

	result := &core.ScanResult{
		ProjectPath:    path,
		ProjectType:    projectType,
		ProjectContext: context,
	}

	// Phase 1: Parse dependencies with error recovery
	fmt.Println("🔍 Analyzing dependencies...")
	var dependencies []core.Dependency

	recovery := core.WithRecovery("dependency_parsing", false, func(err error) {
		errorCollector.Add(err)
		fmt.Printf("⚠️  Warning: Dependency parsing issue: %v\n", err)
	})

	parseErr := recovery.Execute(func() error {
		var tmpErr error
		dependencies, tmpErr = parseDependencies(path, projectType.Language)
		return tmpErr
	})

	if parseErr != nil {
		// Try to continue with empty dependencies rather than failing completely
		errorCollector.Add(core.NewScanError("dependency_parsing", "failed to parse dependencies", parseErr))
		fmt.Printf("⚠️  Warning: Continuing with empty dependency list: %v\n", parseErr)
		dependencies = []core.Dependency{}
	}

	result.Dependencies = dependencies

	// Concurrent execution of independent phases 2 and 3
	var wg sync.WaitGroup
	var bannedTech []core.BannedTech
	var cves []core.CVE
	var cveErr error

	wg.Add(2)

	// Phase 2: Check for banned technologies (concurrent)
	go func() {
		defer wg.Done()
		fmt.Println("🚫 Scanning for banned technologies...")
		bannedTech = scanBannedTech(dependencies)
	}()

	// Phase 3: Check for CVEs (concurrent)
	go func() {
		defer wg.Done()
		fmt.Println("🔍 Scanning for vulnerabilities...")
		cves, cveErr = scanCVEs(dependencies, projectType.Language)
		if cveErr != nil {
			errorCollector.Add(core.NewCVEScanError("batch", projectType.Language, "vulnerability scanning failed", cveErr))
			fmt.Printf("⚠️  CVE scan warning: %v\n", cveErr)
		}
	}()

	wg.Wait()

	result.BannedTechFound = bannedTech
	result.CVEsFound = cves

	// Phase 4: Assess compliance controls (now TRL-aware) with validation
	if err := core.ValidateTRL(context.TRL); err != nil {
		return nil, err
	}

	fmt.Printf("📋 Assessing controls for TRL %d (%s)...\n",
		context.TRL, core.TRLDescriptions[context.TRL])

	assessmentRecovery := core.WithRecovery("compliance_assessment", true, func(err error) {
		errorCollector.Add(err)
	})

	assessErr := assessmentRecovery.Execute(func() error {
		return core.AssessCompliance(result)
	})

	if assessErr != nil {
		return nil, core.NewScanError("compliance_assessment", "compliance assessment failed", assessErr)
	}

	// Log non-critical errors for debugging
	if errorCollector.HasErrors() {
		fmt.Printf("⚠️  Scan completed with %d warnings (use --verbose for details)\n", errorCollector.ErrorCount())
	}

	return result, nil
}

// detectProjectContext reads .complyr.yaml or uses defaults
func detectProjectContext(path string) core.ProjectContext {
	context := core.ProjectContext{
		TRL: 3, // Default to TRL 3 (proof of concept)
	}

	// Check for .complyr.yaml
	configPath := filepath.Join(path, ".complyr.yaml")
	if data, err := os.ReadFile(configPath); err == nil {
		var config ComplyrConfig
		if err := yaml.Unmarshal(data, &config); err == nil {
			if config.Project.TRL > 0 && config.Project.TRL <= 9 {
				context.TRL = config.Project.TRL
			}
			context.ContractType = config.Project.ContractType
			context.Customer = config.Project.Customer
		}
	}

	return context
}

// detectProjectType identifies the project type
func detectProjectType(path string) core.ProjectType {
	projectTypes := map[string]core.ProjectType{
		"package.json":     {Name: "Node.js", Language: "JavaScript", ConfigFiles: []string{"package.json"}},
		"requirements.txt": {Name: "Python", Language: "Python", ConfigFiles: []string{"requirements.txt"}},
		"pom.xml":          {Name: "Maven", Language: "Java", ConfigFiles: []string{"pom.xml"}},
		"go.mod":           {Name: "Go", Language: "Go", ConfigFiles: []string{"go.mod"}},
		"Cargo.toml":       {Name: "Rust", Language: "Rust", ConfigFiles: []string{"Cargo.toml"}},
	}

	for configFile, projectType := range projectTypes {
		if _, err := os.Stat(filepath.Join(path, configFile)); err == nil {
			return projectType
		}
	}

	return core.ProjectType{Name: "Unknown", Language: "Unknown"}
}


// scanBannedTech checks dependencies against banned technologies
func scanBannedTech(dependencies []core.Dependency) []core.BannedTech {
	var findings []core.BannedTech
	bannedTech := core.GetBannedTechnologies()

	for _, dep := range dependencies {
		if banned, exists := bannedTech[dep.Name]; exists {
			finding := banned
			finding.File = dep.File
			finding.Version = dep.Version
			findings = append(findings, finding)
		}
	}

	return findings
}

// InitializeProject creates a .complyr.yaml configuration file
func InitializeProject(path string, trl int, contractType string, customer string) error {
	config := ComplyrConfig{}
	config.Project.TRL = trl
	config.Project.ContractType = contractType
	config.Project.Customer = customer // ADD THIS LINE

	data, err := yaml.Marshal(&config)
	if err != nil {
		return err
	}

	configPath := filepath.Join(path, ".complyr.yaml")
	return os.WriteFile(configPath, data, 0644)
}
