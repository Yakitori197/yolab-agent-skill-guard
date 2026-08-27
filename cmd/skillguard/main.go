// Command skillguard is the CLI entry point. All logic lives in internal/app
// so that every command is testable in-process; this file is deliberately a
// thin shim excluded from coverage accounting.
package main

import (
	"os"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/app"
)

func main() {
	os.Exit(app.New().Run(os.Args[1:]))
}
