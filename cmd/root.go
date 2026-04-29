package cmd

import (
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is resolved from the embedded module info, so `go install ...@v0.1.0`
// produces a binary that reports v0.1.0 and a local `go build` reports (devel).
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "complyr",
	Version: version(),
	Short:   "NIST RMF/ATO compliance scanner for code repositories",
	Long: `Complyr scans your local code repository for NIST RMF compliance,
detecting banned technologies, CVEs, and assessing technical controls
to help prepare for ATO (Authority to Operate) certification.`,
	// Make running complyr without subcommand default to scan
	Run: runScan,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}
