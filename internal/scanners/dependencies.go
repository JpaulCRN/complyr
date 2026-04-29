package scanners

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JpaulCRN/complyr/internal/core"
)

// Directories to skip during recursive scanning
var skipDirs = map[string]bool{
	"node_modules":   true,
	"vendor":         true,
	".git":           true,
	"dist":           true,
	"build":          true,
	"__pycache__":    true,
	"target":         true,
	".venv":          true,
	"venv":           true,
	".tox":           true,
	"coverage":       true,
	".next":          true,
	".nuxt":          true,
	"out":            true,
	".turbo":         true,
	".cache":         true,
}

// Manifest file names we look for
var manifestFiles = map[string]string{
	"package.json":     "JavaScript",
	"go.mod":           "Go",
	"requirements.txt": "Python",
	"pyproject.toml":   "Python",
	"Pipfile":          "Python",
	"Cargo.toml":       "Rust",
	"pom.xml":          "Java",
}

// findDependencyFiles recursively finds all dependency manifest files in a directory
func findDependencyFiles(rootPath string) map[string][]string {
	manifests := make(map[string][]string)
	for name := range manifestFiles {
		manifests[name] = []string{}
	}

	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		// Skip excluded directories
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a manifest file we track
		if _, tracked := manifests[d.Name()]; tracked {
			manifests[d.Name()] = append(manifests[d.Name()], path)
		}

		return nil
	})

	return manifests
}

// getSubprojectPath extracts the relative subproject path from a full file path
func getSubprojectPath(rootPath, filePath string) string {
	rel, err := filepath.Rel(rootPath, filepath.Dir(filePath))
	if err != nil || rel == "." {
		return ""
	}
	return rel
}

var versionRegex = regexp.MustCompile(`^[a-zA-Z0-9\.\-_\+\*]+$`)
var packageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_.@/]+$`)

// parseDependencies parses dependencies recursively from all manifest files found
func parseDependencies(path, language string) ([]core.Dependency, error) {
	// Find all manifest files recursively
	manifests := findDependencyFiles(path)

	var allDeps []core.Dependency

	// Parse all JavaScript/Node.js package.json files
	for _, pkgPath := range manifests["package.json"] {
		subproject := getSubprojectPath(path, pkgPath)
		deps, err := parseNodeJSDependenciesFromFile(pkgPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Go modules
	for _, goPath := range manifests["go.mod"] {
		subproject := getSubprojectPath(path, goPath)
		deps, err := parseGoDependenciesFromFile(goPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Python requirements.txt
	for _, reqPath := range manifests["requirements.txt"] {
		subproject := getSubprojectPath(path, reqPath)
		deps, err := parseRequirementsTxtFromFile(reqPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Python pyproject.toml
	for _, pyPath := range manifests["pyproject.toml"] {
		subproject := getSubprojectPath(path, pyPath)
		deps, err := parsePyprojectTomlFromFile(pyPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Python Pipfiles
	for _, pipPath := range manifests["Pipfile"] {
		subproject := getSubprojectPath(path, pipPath)
		deps, err := parsePipfileFromFile(pipPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Rust Cargo.toml
	for _, cargoPath := range manifests["Cargo.toml"] {
		subproject := getSubprojectPath(path, cargoPath)
		deps, err := parseRustDependenciesFromFile(cargoPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Parse all Java pom.xml
	for _, pomPath := range manifests["pom.xml"] {
		subproject := getSubprojectPath(path, pomPath)
		deps, err := parseJavaDependenciesFromFile(pomPath, subproject)
		if err == nil {
			allDeps = append(allDeps, deps...)
		}
	}

	// Deduplicate dependencies (same name+version from different locations kept separate)
	return deduplicateDependencies(allDeps), nil
}

// deduplicateDependencies removes exact duplicates (same name, version, and subproject)
func deduplicateDependencies(deps []core.Dependency) []core.Dependency {
	seen := make(map[string]bool)
	var result []core.Dependency

	for _, dep := range deps {
		key := fmt.Sprintf("%s|%s|%s", dep.Name, dep.Version, dep.Subproject)
		if !seen[key] {
			seen[key] = true
			result = append(result, dep)
		}
	}

	return result
}

// parseNodeJSDependencies parses package.json (legacy wrapper)
func parseNodeJSDependencies(path string) ([]core.Dependency, error) {
	packageFile := filepath.Join(path, "package.json")
	return parseNodeJSDependenciesFromFile(packageFile, "")
}

// parseNodeJSDependenciesFromFile parses a specific package.json file
func parseNodeJSDependenciesFromFile(packageFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(packageFile)
	if err != nil {
		return dependencies, nil // No package.json found
	}

	var pkg map[string]any
	if err := json.Unmarshal(data, &pkg); err != nil {
		return dependencies, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Parse dependencies and devDependencies
	depTypes := map[string]string{
		"dependencies":    "production",
		"devDependencies": "development",
	}

	for depType, classification := range depTypes {
		if depMap, ok := pkg[depType].(map[string]any); ok {
			for depName, version := range depMap {
				if !isValidPackageName(depName) {
					continue
				}

				dep := core.Dependency{
					Name:       depName,
					Version:    cleanVersion(fmt.Sprintf("%v", version)),
					File:       "package.json",
					Type:       classification,
					Subproject: subproject,
				}
				dependencies = append(dependencies, dep)
			}
		}
	}

	return dependencies, nil
}

// parsePythonDependencies parses requirements.txt, Pipfile, and pyproject.toml (legacy wrapper)
func parsePythonDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	// Try pyproject.toml first (most modern)
	pyprojectFile := filepath.Join(path, "pyproject.toml")
	if deps, err := parsePyprojectTomlFromFile(pyprojectFile, ""); err == nil {
		dependencies = append(dependencies, deps...)
	}

	// Try requirements.txt
	reqFile := filepath.Join(path, "requirements.txt")
	if deps, err := parseRequirementsTxtFromFile(reqFile, ""); err == nil {
		dependencies = append(dependencies, deps...)
	}

	// Also try Pipfile
	pipFile := filepath.Join(path, "Pipfile")
	if deps, err := parsePipfileFromFile(pipFile, ""); err == nil {
		dependencies = append(dependencies, deps...)
	}

	return dependencies, nil
}

// parsePyprojectToml parses pyproject.toml file for Python dependencies (legacy wrapper)
func parsePyprojectToml(path string) ([]core.Dependency, error) {
	pyprojectFile := filepath.Join(path, "pyproject.toml")
	return parsePyprojectTomlFromFile(pyprojectFile, "")
}

// parsePyprojectTomlFromFile parses a specific pyproject.toml file
func parsePyprojectTomlFromFile(pyprojectFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(pyprojectFile)
	if err != nil {
		return dependencies, err
	}

	// Basic TOML parsing for dependencies section
	lines := strings.Split(string(data), "\n")
	inDependencies := false
	inDevDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for dependencies sections
		if line == "[tool.poetry.dependencies]" || line == "[project.dependencies]" {
			inDependencies = true
			inDevDependencies = false
			continue
		}
		if line == "[tool.poetry.group.dev.dependencies]" || line == "[project.optional-dependencies.dev]" {
			inDependencies = false
			inDevDependencies = true
			continue
		}
		if strings.HasPrefix(line, "[") && (inDependencies || inDevDependencies) {
			inDependencies = false
			inDevDependencies = false
			continue
		}

		// Parse dependency lines
		if (inDependencies || inDevDependencies) && strings.Contains(line, "=") {
			dep := parsePyprojectLine(line, inDevDependencies, subproject)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parsePyprojectLine parses a pyproject.toml dependency line
func parsePyprojectLine(line string, isDevDependency bool, subproject string) *core.Dependency {
	if !strings.Contains(line, "=") {
		return nil
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return nil
	}

	name := strings.TrimSpace(parts[0])
	version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

	// Handle special cases like python version constraints
	if name == "python" {
		return nil
	}

	if !isValidPackageName(name) {
		return nil
	}

	depType := "production"
	if isDevDependency {
		depType = "development"
	}

	return &core.Dependency{
		Name:       name,
		Version:    cleanVersion(version),
		File:       "pyproject.toml",
		Type:       depType,
		Subproject: subproject,
	}
}

// parseRequirementsTxt parses requirements.txt file (legacy wrapper)
func parseRequirementsTxt(path string) ([]core.Dependency, error) {
	reqFile := filepath.Join(path, "requirements.txt")
	return parseRequirementsTxtFromFile(reqFile, "")
}

// parseRequirementsTxtFromFile parses a specific requirements.txt file
func parseRequirementsTxtFromFile(reqFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	file, err := os.Open(reqFile)
	if err != nil {
		return dependencies, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		dep := parseRequirementLine(line, subproject)
		if dep != nil {
			dependencies = append(dependencies, *dep)
		}
	}

	if err := scanner.Err(); err != nil {
		return dependencies, fmt.Errorf("error reading requirements.txt at line %d: %w", lineNum, err)
	}

	return dependencies, nil
}

// parseRequirementLine parses a single requirements.txt line
func parseRequirementLine(line string, subproject string) *core.Dependency {
	var name, version string
	operators := []string{"==", ">=", "<=", "~=", "!=", ">", "<"}

	for _, op := range operators {
		if strings.Contains(line, op) {
			parts := strings.SplitN(line, op, 2)
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[0])
				version = cleanVersion(strings.TrimSpace(parts[1]))
				break
			}
		}
	}

	if name == "" {
		name = line
		version = "latest"
	}

	if !isValidPackageName(name) {
		return nil
	}

	return &core.Dependency{
		Name:       name,
		Version:    version,
		File:       "requirements.txt",
		Type:       "production",
		Subproject: subproject,
	}
}

// parsePipfile parses Pipfile for dependencies (legacy wrapper)
func parsePipfile(path string) ([]core.Dependency, error) {
	pipFile := filepath.Join(path, "Pipfile")
	return parsePipfileFromFile(pipFile, "")
}

// parsePipfileFromFile parses a specific Pipfile
func parsePipfileFromFile(pipFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(pipFile)
	if err != nil {
		return dependencies, err
	}

	lines := strings.Split(string(data), "\n")
	inPackages := false
	inDevPackages := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[packages]" {
			inPackages = true
			inDevPackages = false
			continue
		}
		if line == "[dev-packages]" {
			inPackages = false
			inDevPackages = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPackages = false
			inDevPackages = false
			continue
		}

		if (inPackages || inDevPackages) && strings.Contains(line, "=") {
			dep := parsePipfileLine(line, inDevPackages, subproject)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parsePipfileLine parses a Pipfile package line
func parsePipfileLine(line string, isDevPackage bool, subproject string) *core.Dependency {
	if !strings.Contains(line, "=") {
		return nil
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return nil
	}

	name := strings.TrimSpace(parts[0])
	version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

	if !isValidPackageName(name) {
		return nil
	}

	depType := "production"
	if isDevPackage {
		depType = "development"
	}

	return &core.Dependency{
		Name:       name,
		Version:    cleanVersion(version),
		File:       "Pipfile",
		Type:       depType,
		Subproject: subproject,
	}
}

// POMProject represents Maven POM structure
type POMProject struct {
	Dependencies []POMDependency `xml:"dependencies>dependency"`
}

type POMDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// parseJavaDependencies parses Maven pom.xml (legacy wrapper)
func parseJavaDependencies(path string) ([]core.Dependency, error) {
	pomFile := filepath.Join(path, "pom.xml")
	return parseJavaDependenciesFromFile(pomFile, "")
}

// parseJavaDependenciesFromFile parses a specific pom.xml file
func parseJavaDependenciesFromFile(pomFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(pomFile)
	if err != nil {
		return dependencies, nil // No pom.xml found
	}

	var project POMProject
	if err := xml.Unmarshal(data, &project); err != nil {
		return dependencies, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	for _, dep := range project.Dependencies {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}

		name := fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID)
		version := dep.Version
		if version == "" {
			version = "latest"
		}

		dependency := core.Dependency{
			Name:       name,
			Version:    cleanVersion(version),
			File:       "pom.xml",
			Type:       "production",
			Subproject: subproject,
		}
		dependencies = append(dependencies, dependency)
	}

	return dependencies, nil
}

// parseGoDependencies parses go.mod (legacy wrapper)
func parseGoDependencies(path string) ([]core.Dependency, error) {
	goModFile := filepath.Join(path, "go.mod")
	return parseGoDependenciesFromFile(goModFile, "")
}

// parseGoDependenciesFromFile parses a specific go.mod file
func parseGoDependenciesFromFile(goModFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(goModFile)
	if err != nil {
		return dependencies, nil // No go.mod found
	}

	lines := strings.Split(string(data), "\n")
	inRequireBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require") {
			if strings.Contains(line, "(") {
				inRequireBlock = true
				continue
			} else {
				dep := parseGoRequireLine(line, subproject)
				if dep != nil {
					dependencies = append(dependencies, *dep)
				}
				continue
			}
		}

		if inRequireBlock && strings.Contains(line, ")") {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			dep := parseGoRequireLine(line, subproject)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parseGoRequireLine parses a single go.mod require line
func parseGoRequireLine(line string, subproject string) *core.Dependency {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return nil
	}

	line = strings.TrimPrefix(line, "require")
	line = strings.TrimSpace(line)

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	name := parts[0]
	version := parts[1]

	depType := "production"
	if len(parts) > 2 && strings.Contains(strings.Join(parts[2:], " "), "indirect") {
		depType = "indirect"
	}

	if !isValidPackageName(name) {
		return nil
	}

	return &core.Dependency{
		Name:       name,
		Version:    cleanVersion(version),
		File:       "go.mod",
		Type:       depType,
		Subproject: subproject,
	}
}

// parseRustDependencies parses Cargo.toml (legacy wrapper)
func parseRustDependencies(path string) ([]core.Dependency, error) {
	cargoFile := filepath.Join(path, "Cargo.toml")
	return parseRustDependenciesFromFile(cargoFile, "")
}

// parseRustDependenciesFromFile parses a specific Cargo.toml file
func parseRustDependenciesFromFile(cargoFile string, subproject string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	data, err := os.ReadFile(cargoFile)
	if err != nil {
		return dependencies, nil // No Cargo.toml found
	}

	// Basic TOML parsing - in production, use a proper TOML parser
	lines := strings.Split(string(data), "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[dependencies]" {
			inDependencies = true
			continue
		}
		if strings.HasPrefix(line, "[") && line != "[dependencies]" {
			inDependencies = false
			continue
		}

		if inDependencies && strings.Contains(line, "=") {
			dep := parseCargoLine(line, subproject)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parseCargoLine parses a Cargo.toml dependency line
func parseCargoLine(line string, subproject string) *core.Dependency {
	if !strings.Contains(line, "=") {
		return nil
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return nil
	}

	name := strings.TrimSpace(parts[0])
	version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

	if !isValidPackageName(name) {
		return nil
	}

	return &core.Dependency{
		Name:       name,
		Version:    cleanVersion(version),
		File:       "Cargo.toml",
		Type:       "production",
		Subproject: subproject,
	}
}

// Helper functions
func cleanVersion(version string) string {
	if version == "" {
		return "latest"
	}

	operators := []string{">=", "<=", "==", "~=", "!=", ">", "<", "^", "~"}
	cleanedVersion := version

	for _, op := range operators {
		cleanedVersion = strings.TrimPrefix(cleanedVersion, op)
	}

	cleanedVersion = strings.TrimSpace(cleanedVersion)
	cleanedVersion = strings.TrimSuffix(cleanedVersion, ",")

	// Handle complex version patterns more gracefully
	if cleanedVersion == "" {
		return "latest"
	}

	// Remove quotes and brackets if present
	cleanedVersion = strings.Trim(cleanedVersion, `"'(){}[]`)

	// If still empty after cleaning, use latest
	if cleanedVersion == "" {
		return "latest"
	}

	// Allow more version formats (semver, ranges, etc.)
	if strings.Contains(cleanedVersion, " ") {
		// Take first part of version range (e.g., "1.2.3 || 2.0.0" -> "1.2.3")
		parts := strings.Fields(cleanedVersion)
		if len(parts) > 0 {
			cleanedVersion = parts[0]
		}
	}

	// Final validation - be more permissive
	if len(cleanedVersion) > 50 || strings.ContainsAny(cleanedVersion, "<>") {
		return "latest"
	}

	return cleanedVersion
}

func isValidPackageName(name string) bool {
	if name == "" || len(name) > 200 {
		return false
	}
	return packageNameRegex.MatchString(name)
}
