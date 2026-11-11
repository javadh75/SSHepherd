package keyfile

import (
	"os"
	"testing"

	"go.uber.org/goleak"
)

// helperEnv names the role a re-executed test binary plays (helpers maps a
// role to its body); see tty_jobctl_test.go.
const helperEnv = "SSHEPHERD_KEYFILE_TEST_HELPER"

var helpers = map[string]func() int{}

func TestMain(m *testing.M) {
	if role := os.Getenv(helperEnv); role != "" {
		run, ok := helpers[role]
		if !ok {
			os.Exit(97)
		}
		os.Exit(run())
	}
	goleak.VerifyTestMain(m)
}
