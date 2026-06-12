// Command runclave runs coding agents in a disposable, egress-controlled box
// with no access to the real filesystem. See ../../ and the design
// docs in ../../runclave-design/.
package main

import (
	"os"

	"github.com/saimeda/runclave/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
