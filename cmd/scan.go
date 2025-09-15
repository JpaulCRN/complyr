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
		fmt.Printf("❌ Path does not exist: %s\n", path)
		os.Exit(1)
	}

	output.PrintBanner()
	fmt.Printf("🔍 Scanning %s for NIST RMF compliance...\n\n", path)

	// Perform the scan
	result, err := scanners.PerformScan(path)
	if err != nil {
		fmt.Printf("❌ Error during scan: %v\n", err)
		os.Exit(1)
	}

	// Get flags with error handling
	jsonOutput, err := cmd.Flags().GetBool("json")
	if err != nil {
		// For root command, check persistent flags
		jsonOutput, err = cmd.Root().PersistentFlags().GetBool("json")
		if err != nil {
			jsonOutput = false
		}
	}

	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		// For root command, check persistent flags
		verbose, err = cmd.Root().PersistentFlags().GetBool("verbose")
		if err != nil {
			verbose = false
		}
	}

	oscalFile, err := cmd.Flags().GetString("oscal")
	if err != nil {
		// For root command, check persistent flags
		oscalFile, err = cmd.Root().PersistentFlags().GetString("oscal")
		if err != nil {
			oscalFile = ""
		}
	}

	// Export OSCAL document if requested
	if oscalFile != "" {
		oscalDoc, err := core.GenerateOSCALDocument(result)
		if err != nil {
			fmt.Printf("❌ Error generating OSCAL document: %v\n", err)
			os.Exit(1)
		}

		oscalJSON, err := core.ExportOSCALJSON(oscalDoc)
		if err != nil {
			fmt.Printf("❌ Error exporting OSCAL JSON: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(oscalFile, oscalJSON, 0644); err != nil {
			fmt.Printf("❌ Error writing OSCAL file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("📄 OSCAL document exported to: %s\n", oscalFile)
	}

	// Display results
	if jsonOutput {
		if err := output.DisplayJSON(result); err != nil {
			fmt.Printf("❌ Error formatting JSON output: %v\n", err)
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
	// Add scan as a subcommand
	rootCmd.AddCommand(scanCmd)

	// Add flags to both root and scan commands
	// Persistent flags on root so they work with or without 'scan' subcommand
	rootCmd.PersistentFlags().BoolP("json", "j", false, "Output results in JSON format")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().String("oscal", "", "Export OSCAL document to specified file")

	// Also add to scan command for better help text
	scanCmd.Flags().BoolP("json", "j", false, "Output results in JSON format")
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().String("oscal", "", "Export OSCAL document to specified file")
}
