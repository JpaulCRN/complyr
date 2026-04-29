package cmd

import (
	"fmt"
	"os"

	"github.com/JpaulCRN/complyr/internal/core"
	"github.com/JpaulCRN/complyr/internal/scanners"
	"github.com/JpaulCRN/complyr/pkg/output"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a local repository for RMF compliance",
	Long: `Scan analyzes your code repository for:
- Banned or prohibited technologies
- Known CVEs in dependencies  
- Technical implementation of NIST 800-53 controls
- Overall ATO readiness assessment`,
	Args: cobra.MaximumNArgs(1),
	Run:  runScan,
}

// runScan is the shared scan logic
func runScan(cmd *cobra.Command, args []string) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Validate path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ERROR: Path does not exist: %s\n", path)
		os.Exit(1)
	}

	// Get flags early to determine output mode
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Send banner and progress to stderr for JSON mode, stdout otherwise
	outputStream := os.Stdout
	if jsonOutput {
		outputStream = os.Stderr
	}

	output.PrintBannerTo(outputStream)
	fmt.Fprintf(outputStream, "Scanning %s for NIST RMF compliance...\n\n", path)

	// Perform the scan
	result, err := scanners.PerformScan(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Scan failed: %v\n", err)
		os.Exit(1)
	}

	verbose, _ := cmd.Flags().GetBool("verbose")
	oscalFile, _ := cmd.Flags().GetString("oscal")

	// Export OSCAL document if requested
	if oscalFile != "" {
		oscalDoc, err := core.GenerateOSCALDocument(result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to generate OSCAL document: %v\n", err)
			os.Exit(1)
		}

		oscalJSON, err := core.ExportOSCALJSON(oscalDoc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to export OSCAL JSON: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(oscalFile, oscalJSON, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to write OSCAL file: %v\n", err)
			os.Exit(1)
		}

		// Notify about OSCAL file creation (to stderr for JSON mode)
		fmt.Fprintf(outputStream, "OSCAL assessment-results written to %s (%d bytes)\n", oscalFile, len(oscalJSON))
	}

	// Display results
	if jsonOutput {
		// Pure JSON output to stdout
		if err := output.DisplayJSON(result); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to format JSON output: %v\n", err)
			os.Exit(1)
		}
	} else {
		output.DisplayResults(result, verbose)
	}

	// Exit with appropriate code based on findings
	if result.Summary.CriticalIssues > 0 {
		os.Exit(2)
	} else if result.Summary.HighIssues > 0 {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Persistent flags on root so they work with or without the 'scan' subcommand
	// and are inherited by scanCmd via cmd.Flags().
	rootCmd.PersistentFlags().BoolP("json", "j", false, "Output results in JSON format")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().String("oscal", "", "Export OSCAL document to specified file")
}
