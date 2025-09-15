package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "complyr",
	Short: "NIST RMF/ATO compliance scanner for code repositories",
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
