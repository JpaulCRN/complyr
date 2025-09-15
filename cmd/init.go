package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"          // Add this import
	"github.com/JpaulCRN/complyr/internal/core" // Add this for TRLDescriptions
	"github.com/JpaulCRN/complyr/internal/scanners"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Complyr configuration for your project",
	Long: `Set up your project's Technology Readiness Level (TRL) and contract type 
for appropriate compliance checking. This creates a .complyr.yaml configuration file
that customizes which controls are checked based on your project's maturity level.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// Get path from flag or use current directory
		path, _ := cmd.Flags().GetString("path")

		if err := runInit(path); err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("path", "p", ".", "Path to initialize (default: current directory)")
}

func runInit(path string) error {
	fmt.Println("\n🚀 Complyr Project Setup")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Check if config already exists
	configPath := filepath.Join(path, ".complyr.yaml")
	if _, err := os.Stat(configPath); err == nil {
		var overwrite bool
		prompt := &survey.Confirm{
			Message: ".complyr.yaml already exists. Overwrite?",
			Default: false,
		}
		if err := survey.AskOne(prompt, &overwrite); err != nil {
			return err
		}
		if !overwrite {
			fmt.Println("Initialization cancelled.")
			return nil
		}
	}

	// TRL selection
	var trlChoice string
	trlPrompt := &survey.Select{
		Message: "What's your current Technology Readiness Level (TRL)?",
		Options: []string{
			"1-2: Basic Research / Initial Concept",
			"3-4: Proof of Concept / Lab Testing",
			"5-6: Prototype / Environment Demo",
			"7-8: Operational Testing",
			"9: Production System",
		},
		Default: "3-4: Proof of Concept / Lab Testing",
	}
	if err := survey.AskOne(trlPrompt, &trlChoice); err != nil {
		return err
	}

	// Map choice to TRL number
	trlMap := map[string]int{
		"1-2: Basic Research / Initial Concept": 2,
		"3-4: Proof of Concept / Lab Testing":   3,
		"5-6: Prototype / Environment Demo":     5,
		"7-8: Operational Testing":              7,
		"9: Production System":                  9,
	}
	trl := trlMap[trlChoice]

	// Contract type selection
	var contractType string
	contractPrompt := &survey.Select{
		Message: "Contract Type:",
		Options: []string{
			"Phase I SBIR",
			"Phase II SBIR",
			"Other/Direct Award",
			"Internal/No Contract",
		},
		Default: "Phase I SBIR",
	}
	if err := survey.AskOne(contractPrompt, &contractType); err != nil {
		return err
	}

	// Optional: Customer selection
	var customer string
	customerPrompt := &survey.Select{
		Message: "Primary Customer (optional):",
		Options: []string{
			"Skip",
			"DISA",
			"Army",
			"Air Force",
			"Navy",
			"Space Force",
			"Other DoD",
			"Civilian Agency",
		},
		Default: "Skip",
	}
	if err := survey.AskOne(customerPrompt, &customer); err != nil {
		return err
	}

	if customer == "Skip" {
		customer = ""
	}

	// Save configuration
	if err := scanners.InitializeProject(path, trl, contractType, customer); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Printf("\n✅ Created .complyr.yaml with:\n")
	fmt.Printf("   • TRL %d (%s)\n", trl, core.TRLDescriptions[trl])
	fmt.Printf("   • Contract: %s\n", contractType)
	if customer != "" {
		fmt.Printf("   • Customer: %s\n", customer)
	}

	fmt.Println("\n💡 Next step: Run 'complyr scan' to check compliance")
	fmt.Println("📝 You can edit .complyr.yaml to customize requirements")

	return nil
}
