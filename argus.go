package main

import (
	"fmt"
	"os"

	"github.com/redcarbon-dev/argus/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
