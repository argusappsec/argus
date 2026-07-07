package main

import (
	"fmt"
	"os"

	"github.com/argusappsec/argus/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
