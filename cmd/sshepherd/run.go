package main

import (
	"flag"
	"fmt"
	"io"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>". Defaults to "dev" for local builds.
var version = "dev"

// run is the testable entrypoint: it parses args, writes to the provided
// streams instead of the process stdio, and returns a process exit code.
// This keeps main trivial and lets tests drive the CLI without touching
// os.Args, os.Stdout, or os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sshepherd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2 // flag package already wrote the error/usage to stderr
	}

	if *showVersion {
		fmt.Fprintln(stdout, "sshepherd", version)
		return 0
	}

	fmt.Fprintln(stderr, "sshepherd: no command given (try --version)")
	return 2
}
