package keyfile

import "context"

// Spec names one --identity key file by its cleaned absolute path
// (Resolve builds it).
type Spec struct{ Path string }

// Passphrases names the passphrase files of a run: Default for any
// encrypted key, PerKey (key path -> passphrase file path) for one key.
// Paths are cleaned and absolute (Resolve builds them); "" means none.
type Passphrases struct {
	Default string
	PerKey  map[string]string
}

// Prompter asks the operator for a passphrase: the controlling terminal in
// production (NewTTY), a fake in tests. Available reports whether a prompt
// can be answered at all; ReadPassphrase returns ctx.Err() (wrapped) when
// ctx ends mid-prompt.
type Prompter interface {
	Available() bool
	ReadPassphrase(ctx context.Context, prompt string) ([]byte, error)
}
