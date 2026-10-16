package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

// identityFlags are the key-file flags audit, adopt and apply declare
// (per command, like --known-hosts; import makes no connection).
type identityFlags struct {
	paths       []string
	defaultFile string
	perKey      []string
}

// register declares the three flags on cmd. The backticked words are the
// --help varnames (PATH, FILE, KEY=FILE) the README tables mirror.
func (f *identityFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&f.paths, "identity", nil,
		"private key `PATH` to authenticate with, in addition to ssh-agent (repeatable; ~/ expands from $HOME)")
	cmd.Flags().StringVar(&f.defaultFile, "identity-passphrase-file", "",
		"`FILE` holding the default passphrase for any encrypted --identity key")
	cmd.Flags().StringArrayVar(&f.perKey, "identity-passphrase", nil,
		"`KEY=FILE`: passphrase file for one --identity key (repeatable; split at the first =)")
}

// identities is a run's validated key-file inputs: step 1 of every
// connecting command's order of operations. Nothing is read yet.
type identities struct {
	specs []keyfile.Spec
	pp    keyfile.Passphrases
}

// resolve validates the flags lexically (keyfile.Resolve) — exit 3 before
// the manifest is even loaded.
func (f *identityFlags) resolve() (identities, error) {
	home, _ := os.UserHomeDir() // "" makes Resolve refuse a ~/ path with a clear error
	cwd, err := os.Getwd()
	if err != nil {
		return identities{}, fmt.Errorf("--identity: working directory: %w", err)
	}
	specs, pp, err := keyfile.Resolve(f.paths, f.defaultFile, f.perKey, home, cwd)
	if err != nil {
		return identities{}, fmt.Errorf("invalid flags: %w", err)
	}
	return identities{specs: specs, pp: pp}, nil
}

// validateFlags is step 1 of every connecting command's order of
// operations — --parallel and the identity flags — before the manifest is
// even loaded.
func validateFlags(parallel int, idf *identityFlags) (identities, error) {
	if parallel < 1 {
		return identities{}, fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
	}
	return idf.resolve()
}

// newPrompter builds the passphrase prompter; a test seam (the real one
// needs a controlling terminal).
var newPrompter = func() keyfile.Prompter { return keyfile.NewTTY() }

// credentials loads the key files (it may prompt on /dev/tty) and builds
// the run's one Credentials, shared by every reader, writer and probe:
// step 5, after the manifest, the empty-fleet return and the known_hosts
// preflight, so a typo there never costs the operator a passphrase. A
// Ctrl-C at the prompt is the interrupted path (exit 3, nothing
// connected).
func (ids identities) credentials(ctx context.Context, log *slog.Logger) (*sshconn.Credentials, error) {
	files, err := keyfile.Load(ctx, ids.specs, ids.pp, newPrompter(), keyfile.OSFS{}, log)
	if err != nil {
		if ctx.Err() != nil {
			return nil, interrupted(ctx)
		}
		// errors.Join puts one key per line; the log handler would fold
		// them into spaces, so separate them visibly.
		return nil, fmt.Errorf("identity: %s", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	return &sshconn.Credentials{Files: files, AgentSock: os.Getenv("SSH_AUTH_SOCK"), Log: log}, nil
}

// checkCredentials is step 6: something must be able to authenticate
// (needHeld: apply's guard needs plain keys). Without --identity the
// prefix and message are the agent preflight's, as before key files.
func checkCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error {
	err := sshread.CheckCredentials(ctx, creds, needHeld)
	switch {
	case err == nil:
		return nil
	case len(creds.Files) == 0:
		return fmt.Errorf("agent preflight: %w", err)
	default:
		return fmt.Errorf("credentials preflight: %w", err)
	}
}
