package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	result := &core.ScanResult{
		ProjectPath:    path,
		ProjectType:    projectType,
		ProjectContext: context,
	}

	// Phase 1: Parse dependencies with error recovery
	var dependencies []core.Dependency

	recovery := core.WithRecovery("dependency_parsing", false, func(err error) {
		errorCollector.Add(err)
	})

	parseErr := recovery.Execute(func() error {
		var tmpErr error
		dependencies, tmpErr = parseDependencies(path, projectType.Language)
		return tmpErr
	})

	if parseErr != nil {
		// Try to continue with empty dependencies rather than failing completely
		errorCollector.Add(core.NewScanError("dependency_parsing", "failed to parse dependencies", parseErr))
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
		bannedTech = scanBannedTech(dependencies)
	}()

	// Phase 3: Check for CVEs (concurrent)
	go func() {
		defer wg.Done()
		cves, cveErr = scanCVEs(dependencies, projectType.Language)
		if cveErr != nil {
			errorCollector.Add(core.NewCVEScanError("batch", projectType.Language, "vulnerability scanning failed", cveErr))
		}
	}()

	wg.Wait()

	result.BannedTechFound = bannedTech
	result.CVEsFound = cves

	// Phase 4: Assess compliance controls (now TRL-aware) with validation
	if err := core.ValidateTRL(context.TRL); err != nil {
		return nil, err
	}

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

	configPath := filepath.Join(path, ".complyr.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  No .complyr.yaml found at %s — defaulting to TRL 3 (Proof of Concept). Run 'complyr init' to configure your project.\n", path)
		return context
	}

	var config ComplyrConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Could not parse .complyr.yaml (%v) — defaulting to TRL 3.\n", err)
		return context
	}

	if config.Project.TRL > 0 && config.Project.TRL <= 9 {
		context.TRL = config.Project.TRL
	} else {
		fmt.Fprintf(os.Stderr, "⚠️  .complyr.yaml has invalid TRL %d (must be 1-9) — defaulting to TRL 3.\n", config.Project.TRL)
	}
	context.ContractType = config.Project.ContractType
	context.Customer = config.Project.Customer

	return context
}

// detectWorkspace detects if the project is a monorepo/workspace
func detectWorkspace(path string) *core.WorkspaceInfo {
	// Check for Turborepo
	turboPath := filepath.Join(path, "turbo.json")
	if _, err := os.Stat(turboPath); err == nil {
		return parseTurboWorkspace(path)
	}

	// Check for pnpm-workspace.yaml
	pnpmPath := filepath.Join(path, "pnpm-workspace.yaml")
	if _, err := os.Stat(pnpmPath); err == nil {
		return parsePnpmWorkspace(path)
	}

	// Check for npm/yarn workspaces in package.json
	pkgPath := filepath.Join(path, "package.json")
	if pkgData, err := os.ReadFile(pkgPath); err == nil {
		var pkg map[string]any
		if err := json.Unmarshal(pkgData, &pkg); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Could not parse %s for workspace detection: %v\n", pkgPath, err)
		} else if _, hasWorkspaces := pkg["workspaces"]; hasWorkspaces {
			return parseNpmWorkspaces(path, pkg)
		}
	}

	// Check for Go workspace (go.work)
	goWorkPath := filepath.Join(path, "go.work")
	if _, err := os.Stat(goWorkPath); err == nil {
		return parseGoWorkspace(path)
	}

	// Check for Cargo workspace
	cargoPath := filepath.Join(path, "Cargo.toml")
	if cargoData, err := os.ReadFile(cargoPath); err == nil {
		if strings.Contains(string(cargoData), "[workspace]") {
			return parseCargoWorkspace(path)
		}
	}

	return nil // Not a workspace
}

// parseTurboWorkspace parses a Turborepo configuration
func parseTurboWorkspace(path string) *core.WorkspaceInfo {
	info := &core.WorkspaceInfo{
		Type:       "turborepo",
		Root:       path,
		ConfigFile: "turbo.json",
	}

	// Turborepo uses package.json workspaces, so parse that
	pkgPath := filepath.Join(path, "package.json")
	if pkgData, err := os.ReadFile(pkgPath); err == nil {
		var pkg map[string]any
		if json.Unmarshal(pkgData, &pkg) == nil {
			info.Packages = extractWorkspacePackages(path, pkg)
		}
	}

	return info
}

// parsePnpmWorkspace parses a pnpm workspace configuration
func parsePnpmWorkspace(path string) *core.WorkspaceInfo {
	info := &core.WorkspaceInfo{
		Type:       "pnpm",
		Root:       path,
		ConfigFile: "pnpm-workspace.yaml",
	}

	// Parse pnpm-workspace.yaml
	pnpmPath := filepath.Join(path, "pnpm-workspace.yaml")
	if data, err := os.ReadFile(pnpmPath); err == nil {
		var pnpmConfig struct {
			Packages []string `yaml:"packages"`
		}
		if yaml.Unmarshal(data, &pnpmConfig) == nil {
			info.Packages = expandWorkspaceGlobs(path, pnpmConfig.Packages)
		}
	}

	return info
}

// parseNpmWorkspaces parses npm/yarn workspaces from package.json
func parseNpmWorkspaces(path string, pkg map[string]any) *core.WorkspaceInfo {
	info := &core.WorkspaceInfo{
		Type:       "npm-workspaces",
		Root:       path,
		ConfigFile: "package.json",
		Packages:   extractWorkspacePackages(path, pkg),
	}

	return info
}

// parseGoWorkspace parses a Go workspace (go.work)
func parseGoWorkspace(path string) *core.WorkspaceInfo {
	info := &core.WorkspaceInfo{
		Type:       "go-workspace",
		Root:       path,
		ConfigFile: "go.work",
	}

	goWorkPath := filepath.Join(path, "go.work")
	if data, err := os.ReadFile(goWorkPath); err == nil {
		lines := strings.Split(string(data), "\n")
		inUseBlock := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "use") {
				if strings.Contains(line, "(") {
					inUseBlock = true
					continue
				}
				// Single use directive
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info.Packages = append(info.Packages, filepath.Join(path, parts[1]))
				}
			}
			if inUseBlock {
				if strings.Contains(line, ")") {
					inUseBlock = false
					continue
				}
				if line != "" && !strings.HasPrefix(line, "//") {
					info.Packages = append(info.Packages, filepath.Join(path, line))
				}
			}
		}
	}

	return info
}

// parseCargoWorkspace parses a Cargo workspace
func parseCargoWorkspace(path string) *core.WorkspaceInfo {
	info := &core.WorkspaceInfo{
		Type:       "cargo-workspace",
		Root:       path,
		ConfigFile: "Cargo.toml",
	}

	cargoPath := filepath.Join(path, "Cargo.toml")
	if data, err := os.ReadFile(cargoPath); err == nil {
		lines := strings.Split(string(data), "\n")
		inMembers := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "members") && strings.Contains(line, "[") {
				inMembers = true
				// Check if it's a single-line members definition
				if strings.Contains(line, "]") {
					// Parse inline: members = ["pkg1", "pkg2"]
					start := strings.Index(line, "[")
					end := strings.Index(line, "]")
					if start != -1 && end != -1 {
						content := line[start+1 : end]
						for _, member := range strings.Split(content, ",") {
							member = strings.Trim(strings.TrimSpace(member), "\"'")
							if member != "" {
								info.Packages = append(info.Packages, filepath.Join(path, member))
							}
						}
					}
					inMembers = false
				}
				continue
			}
			if inMembers {
				if strings.Contains(line, "]") {
					inMembers = false
					continue
				}
				member := strings.Trim(strings.TrimSpace(line), "\"',")
				if member != "" {
					info.Packages = append(info.Packages, filepath.Join(path, member))
				}
			}
		}
	}

	return info
}

// extractWorkspacePackages extracts package paths from npm/yarn workspaces config
func extractWorkspacePackages(rootPath string, pkg map[string]any) []string {
	var globs []string

	switch w := pkg["workspaces"].(type) {
	case []any:
		// Simple array format: "workspaces": ["packages/*", "apps/*"]
		for _, item := range w {
			if s, ok := item.(string); ok {
				globs = append(globs, s)
			}
		}
	case map[string]any:
		// Object format: "workspaces": { "packages": ["packages/*"] }
		if packages, ok := w["packages"].([]any); ok {
			for _, item := range packages {
				if s, ok := item.(string); ok {
					globs = append(globs, s)
				}
			}
		}
	}

	return expandWorkspaceGlobs(rootPath, globs)
}

// expandWorkspaceGlobs expands workspace glob patterns to actual directories
func expandWorkspaceGlobs(rootPath string, globs []string) []string {
	var packages []string
	seen := make(map[string]bool)

	for _, glob := range globs {
		// Handle simple patterns like "packages/*" or "apps/*"
		pattern := filepath.Join(rootPath, glob)

		// Use filepath.Glob to expand the pattern
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, match := range matches {
			// Only include directories
			if info, err := os.Stat(match); err == nil && info.IsDir() {
				if !seen[match] {
					seen[match] = true
					packages = append(packages, match)
				}
			}
		}
	}

	return packages
}

// analyzeSubprojects analyzes workspace packages and returns subproject info
func analyzeSubprojects(rootPath string, workspace *core.WorkspaceInfo) []core.SubprojectInfo {
	var subprojects []core.SubprojectInfo

	for _, pkgPath := range workspace.Packages {
		relPath, _ := filepath.Rel(rootPath, pkgPath)
		name := filepath.Base(pkgPath)
		language := detectSubprojectLanguage(pkgPath)

		subprojects = append(subprojects, core.SubprojectInfo{
			Path:     relPath,
			Name:     name,
			Language: language,
		})
	}

	return subprojects
}

// detectSubprojectLanguage detects the primary language of a subproject
func detectSubprojectLanguage(path string) string {
	langFiles := []struct {
		file     string
		language string
	}{
		{"Cargo.toml", "Rust"},
		{"go.mod", "Go"},
		{"pyproject.toml", "Python"},
		{"requirements.txt", "Python"},
		{"pom.xml", "Java"},
		{"package.json", "JavaScript"},
	}

	for _, lf := range langFiles {
		if _, err := os.Stat(filepath.Join(path, lf.file)); err == nil {
			return lf.language
		}
	}

	return "Unknown"
}

// collectLanguages returns unique languages from subprojects
func collectLanguages(subprojects []core.SubprojectInfo) []string {
	seen := make(map[string]bool)
	var languages []string

	for _, sub := range subprojects {
		if sub.Language != "Unknown" && !seen[sub.Language] {
			seen[sub.Language] = true
			languages = append(languages, sub.Language)
		}
	}

	return languages
}

// detectProjectType identifies the project type (now with monorepo support)
func detectProjectType(path string) core.ProjectType {
	// First check for workspace/monorepo
	workspace := detectWorkspace(path)
	if workspace != nil {
		subprojects := analyzeSubprojects(path, workspace)
		languages := collectLanguages(subprojects)

		languageStr := "Multi-language"
		if len(languages) == 1 {
			languageStr = languages[0]
		} else if len(languages) > 1 {
			languageStr = strings.Join(languages, ", ")
		}

		return core.ProjectType{
			Name:        fmt.Sprintf("Monorepo (%s)", workspace.Type),
			Language:    languageStr,
			ConfigFiles: []string{workspace.ConfigFile},
			IsMonorepo:  true,
			Subprojects: subprojects,
		}
	}

	// Check in priority order - pyproject.toml takes precedence over package.json
	projectTypes := []struct {
		configFile  string
		projectType core.ProjectType
	}{
		{"pyproject.toml", core.ProjectType{Name: "Python", Language: "Python", ConfigFiles: []string{"pyproject.toml"}}},
		{"go.mod", core.ProjectType{Name: "Go", Language: "Go", ConfigFiles: []string{"go.mod"}}},
		{"Cargo.toml", core.ProjectType{Name: "Rust", Language: "Rust", ConfigFiles: []string{"Cargo.toml"}}},
		{"pom.xml", core.ProjectType{Name: "Maven", Language: "Java", ConfigFiles: []string{"pom.xml"}}},
		{"requirements.txt", core.ProjectType{Name: "Python", Language: "Python", ConfigFiles: []string{"requirements.txt"}}},
		{"package.json", core.ProjectType{Name: "Node.js", Language: "JavaScript", ConfigFiles: []string{"package.json"}}},
	}

	for _, pt := range projectTypes {
		if _, err := os.Stat(filepath.Join(path, pt.configFile)); err == nil {
			return pt.projectType
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
