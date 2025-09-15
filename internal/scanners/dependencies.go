package scanners

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JpaulCRN/complyr/internal/core"
)

var versionRegex = regexp.MustCompile(`^[a-zA-Z0-9\.\-_]+$`)
var packageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_.@/]+$`)

// parseDependencies parses dependencies based on project language
func parseDependencies(path, language string) ([]core.Dependency, error) {
	switch language {
	case "JavaScript":
		return parseNodeJSDependencies(path)
	case "Python":
		return parsePythonDependencies(path)
	case "Java":
		return parseJavaDependencies(path)
	case "Go":
		return parseGoDependencies(path)
	case "Rust":
		return parseRustDependencies(path)
	default:
		return []core.Dependency{}, nil // Unknown language, return empty
	}
}

// parseNodeJSDependencies parses package.json
func parseNodeJSDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	packageFile := filepath.Join(path, "package.json")
	data, err := os.ReadFile(packageFile)
	if err != nil {
		return dependencies, nil // No package.json found
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return dependencies, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Parse dependencies and devDependencies
	depTypes := map[string]string{
		"dependencies":    "production",
		"devDependencies": "development",
	}

	for depType, classification := range depTypes {
		if depMap, ok := pkg[depType].(map[string]interface{}); ok {
			for depName, version := range depMap {
				if !isValidPackageName(depName) {
					continue
				}

				dep := core.Dependency{
					Name:    depName,
					Version: cleanVersion(fmt.Sprintf("%v", version)),
					File:    "package.json",
					Type:    classification,
				}
				dependencies = append(dependencies, dep)
			}
		}
	}

	return dependencies, nil
}

// parsePythonDependencies parses requirements.txt and Pipfile
func parsePythonDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	// Try requirements.txt first
	if deps, err := parseRequirementsTxt(path); err == nil {
		dependencies = append(dependencies, deps...)
	}

	// Also try Pipfile
	if deps, err := parsePipfile(path); err == nil {
		dependencies = append(dependencies, deps...)
	}

	return dependencies, nil
}

// parseRequirementsTxt parses requirements.txt file with buffered reading for performance
func parseRequirementsTxt(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	reqFile := filepath.Join(path, "requirements.txt")
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

		dep := parseRequirementLine(line)
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
func parseRequirementLine(line string) *core.Dependency {
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
		Name:    name,
		Version: version,
		File:    "requirements.txt",
		Type:    "production",
	}
}

// parsePipfile parses Pipfile for dependencies
func parsePipfile(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	pipFile := filepath.Join(path, "Pipfile")
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
			dep := parsePipfileLine(line, inDevPackages)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parsePipfileLine parses a Pipfile package line
func parsePipfileLine(line string, isDevPackage bool) *core.Dependency {
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
		Name:    name,
		Version: cleanVersion(version),
		File:    "Pipfile",
		Type:    depType,
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

// parseJavaDependencies parses Maven pom.xml
func parseJavaDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	pomFile := filepath.Join(path, "pom.xml")
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
			Name:    name,
			Version: cleanVersion(version),
			File:    "pom.xml",
			Type:    "production",
		}
		dependencies = append(dependencies, dependency)
	}

	return dependencies, nil
}

// parseGoDependencies parses go.mod
func parseGoDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	goModFile := filepath.Join(path, "go.mod")
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
				dep := parseGoRequireLine(line)
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
			dep := parseGoRequireLine(line)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parseGoRequireLine parses a single go.mod require line
func parseGoRequireLine(line string) *core.Dependency {
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
		Name:    name,
		Version: cleanVersion(version),
		File:    "go.mod",
		Type:    depType,
	}
}

// parseRustDependencies parses Cargo.toml (basic implementation)
func parseRustDependencies(path string) ([]core.Dependency, error) {
	var dependencies []core.Dependency

	cargoFile := filepath.Join(path, "Cargo.toml")
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
			dep := parseCargoLine(line)
			if dep != nil {
				dependencies = append(dependencies, *dep)
			}
		}
	}

	return dependencies, nil
}

// parseCargoLine parses a Cargo.toml dependency line
func parseCargoLine(line string) *core.Dependency {
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
		Name:    name,
		Version: cleanVersion(version),
		File:    "Cargo.toml",
		Type:    "production",
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

	if cleanedVersion != "" && !versionRegex.MatchString(cleanedVersion) {
		return "invalid"
	}

	if cleanedVersion == "" {
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
