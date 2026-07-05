package main

import (
	"os"

	"github.com/dovocoder/gollaw/internal/cli"
)

//gollaw:keep
func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
