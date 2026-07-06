// Command sshepherd manages SSH authorized_keys across a fleet of servers.
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
