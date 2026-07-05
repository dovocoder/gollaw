package main

import (
	"os"

	"github.com/dovocoder/gollaw/internal/cli"
)

//gollaw:ignore thin-wrappers
func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
