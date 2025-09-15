package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/JpaulCRN/complyr/cmd"
)

func main() {
	// Set reasonable defaults for the application
	runtime.GOMAXPROCS(runtime.NumCPU())

	if err := cmd.Execute(); err != nil {
		// More descriptive error output with program name
		fmt.Fprintf(os.Stderr, "complyr: %v\n", err)
		os.Exit(1)
	}
}
