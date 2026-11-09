package keyfile

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"golang.org/x/crypto/ssh"
)

// promptAttempts matches ssh's NumberOfPasswordPrompts default.
const promptAttempts = 3

// candidate is one key file on its way to an Identity.
type candidate struct {
	path    string
	data    []byte
	cls     classification
	pub     ssh.PublicKey // pre-decryption public key: a label, never the fingerprint
	pubName string        // where pub came from, for the mismatch refusal
	signer  ssh.Signer
	// defaultTried records that the default passphrase file was tried and
	// did not unlock this key (the no-source message says so).
	defaultTried bool
}

// label is the pre-decryption fingerprint shown in the prompt, or "".
func (c *candidate) label() string {
	if c.pub == nil {
		return ""
	}
	return ssh.FingerprintSHA256(c.pub)
}

type loader struct {
	fsys  FS
	pp    Passphrases
	cache map[string][]byte
	p     Prompter
	log   *slog.Logger
}

// Load reads, classifies and unlocks every spec (flag order) and returns
// the identities de-duplicated by decrypted fingerprint (first path wins).
// Every passphrase file is read exactly once, before any key is tried, and
// wiped (best effort) when Load returns. Non-interactive errors for every
// key are returned together (errors.Join), and nothing prompts while any
// exists; a prompt failure (exhausted attempts, ctx canceled) returns at
// once. log receives the info lines (loaded keys, duplicates, unused
// certificates); nil discards.
func Load(ctx context.Context, specs []Spec, pp Passphrases, p Prompter, fsys FS, log *slog.Logger) ([]Identity, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cache, err := readPassphrases(fsys, pp)
	defer wipeCache(cache)
	l := &loader{fsys: fsys, pp: pp, cache: cache, p: p, log: log}
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	cands, needPrompt, cerrs := l.prepareAll(specs)
	errs = append(errs, cerrs...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for _, c := range needPrompt {
		if err := l.prompt(ctx, c); err != nil {
			return nil, err
		}
	}
	return l.finish(cands), nil
}

// prepareAll runs every non-interactive step for every key: read,
// classify, parse, passphrase files. It returns the candidates in flag
// order, those still needing a prompt, and every error.
func (l *loader) prepareAll(specs []Spec) (cands, needPrompt []*candidate, errs []error) {
	promptable := l.p != nil && l.p.Available()
	for _, s := range specs {
		c, err := l.prepare(s.Path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cands = append(cands, c)
		if c.signer != nil {
			continue
		}
		err = l.unlockFromFiles(c)
		switch {
		case errors.Is(err, errUnavailable):
			// its passphrase file failed to read; that error is already reported
		case err != nil:
			errs = append(errs, err)
		case c.signer != nil:
		case promptable:
			needPrompt = append(needPrompt, c)
		default:
			errs = append(errs, noSourceError(c, l.pp.Default))
		}
	}
	return cands, needPrompt, errs
}

// prepare reads and classifies one key file and parses it when it is not
// encrypted (signer set); an encrypted key comes back without a signer.
func (l *loader) prepare(path string) (*candidate, error) {
	data, err := readChecked(l.fsys, path, maxKeyFile, "key file")
	if err != nil {
		return nil, err
	}
	cls, err := classify(path, data)
	if err != nil {
		return nil, err
	}
	c := &candidate{path: path, data: data, cls: cls}
	if cls.format == formatOpenSSH {
		c.pub, c.pubName = cls.pub, "embedded public key"
	} else if pub := readPublic(l.fsys, path+".pub"); pub != nil {
		c.pub, c.pubName = pub, path+".pub"
	}
	if cls.encrypted {
		return c, nil
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		c.cls.encrypted = true
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: cannot parse the private key: %w — rewrite it with `ssh-keygen -p -f %s`", path, err, path)
	}
	return c, l.accept(c, raw)
}

// errUnavailable marks a passphrase attempt skipped because its file
// could not be read (readPassphrases already reported why).
var errUnavailable = errors.New("passphrase file unavailable")

// unlockFromFiles tries the passphrase files in resolution order: the
// per-key mapping (wrong is a configuration error: no fallback), then the
// default (wrong falls through to the prompt). On return without error and
// without a signer, the key still needs a prompt.
func (l *loader) unlockFromFiles(c *candidate) error {
	if file, ok := l.pp.PerKey[c.path]; ok {
		pass, ok := l.cache[file]
		if !ok {
			return errUnavailable
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
		switch {
		case err == nil:
			return l.accept(c, raw)
		case wrongPassphrase(c, err):
			return fmt.Errorf("%s: the passphrase in %s (--identity-passphrase) does not unlock it", c.path, file)
		default:
			return decryptError(c, err)
		}
	}
	if l.pp.Default == "" {
		return nil
	}
	pass, ok := l.cache[l.pp.Default]
	if !ok {
		return errUnavailable
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
	switch {
	case err == nil:
		return l.accept(c, raw)
	case wrongPassphrase(c, err):
		c.defaultTried = true // a shared guess, not a claim about this key
		return nil
	default:
		return decryptError(c, err)
	}
}

// prompt asks on the terminal, up to promptAttempts times.
func (l *loader) prompt(ctx context.Context, c *candidate) error {
	for attempt := range promptAttempts {
		pass, err := l.p.ReadPassphrase(ctx, promptText(c, attempt))
		if err != nil {
			return fmt.Errorf("passphrase for %s: %w", c.path, err)
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
		clear(pass)
		switch {
		case err == nil:
			return l.accept(c, raw)
		case !wrongPassphrase(c, err):
			return decryptError(c, err)
		}
	}
	return fmt.Errorf("%s: %d incorrect passphrase attempts", c.path, promptAttempts)
}

// promptText is the terminal prompt: the waiting line first, then ssh's
// own wording (with the pre-decryption fingerprint as a label when known).
func promptText(c *candidate, attempt int) string {
	if attempt > 0 {
		return fmt.Sprintf("Bad passphrase, try again for %s: ", c.path)
	}
	head := fmt.Sprintf("waiting for passphrase for %s on the terminal\n", c.path)
	if fp := c.label(); fp != "" {
		return head + fmt.Sprintf("Enter passphrase for %s (%s): ", c.path, fp)
	}
	return head + fmt.Sprintf("Enter passphrase for %s: ", c.path)
}

// accept builds the signer from a parsed private key and refuses a key
// whose pre-decryption public key disagrees with it.
func (l *loader) accept(c *candidate, raw any) error {
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return fmt.Errorf("%s: unsupported private key: %w", c.path, err)
	}
	if c.pub != nil && ssh.FingerprintSHA256(c.pub) != ssh.FingerprintSHA256(signer.PublicKey()) {
		return fmt.Errorf("%s: %s does not match the private key — refusing the key (regenerate the public half with `ssh-keygen -y -f %s`)", c.path, c.pubName, c.path)
	}
	c.signer = signer
	return nil
}

// finish de-duplicates by decrypted fingerprint (first path wins) and logs
// each loaded key once.
func (l *loader) finish(cands []*candidate) []Identity {
	out := make([]Identity, 0, len(cands))
	for _, c := range cands {
		fp := ssh.FingerprintSHA256(c.signer.PublicKey())
		if i := slices.IndexFunc(out, func(id Identity) bool { return id.Fingerprint == fp }); i >= 0 {
			l.log.Info(fmt.Sprintf("identity %s is the same key as %s (%s); using %s", c.path, out[i].Path, fp, out[i].Path))
			continue
		}
		if exists(l.fsys, c.path+"-cert.pub") {
			l.log.Info(fmt.Sprintf("certificate %s-cert.pub not used; authenticating with the plain key", c.path))
		}
		l.log.Info("identity loaded", "path", c.path, "fp", fp)
		out = append(out, Identity{Path: c.path, Fingerprint: fp, Signer: c.signer})
	}
	return out
}

// wrongPassphrase reports whether a decryption failure means "wrong
// passphrase". OpenSSH keys carry a reliable check value, so only
// x509.IncorrectPasswordError counts. Legacy encrypted PEM cannot always
// detect a wrong password (about 1 in 256 yields valid padding and
// garbage), and classify already validated its headers, so any failure
// counts.
func wrongPassphrase(c *candidate, err error) bool {
	if c.cls.format == formatPEM {
		return true
	}
	return errors.Is(err, x509.IncorrectPasswordError)
}

func decryptError(c *candidate, err error) error {
	return fmt.Errorf("%s: cannot decrypt the private key: %w", c.path, err)
}

// noSourceError is the headless verdict for an encrypted key.
func noSourceError(c *candidate, defaultFile string) error {
	msg := fmt.Sprintf("%s is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase PATH=FILE)", c.path)
	if c.defaultTried {
		msg += fmt.Sprintf("; the default passphrase file %s did not unlock it", defaultFile)
	}
	return errors.New(msg)
}

// wipe clears the cached passphrases — best effort: Go cannot guarantee no
// copies, and bcrypt intermediates are not zeroed.
func wipe(cache map[string][]byte) {
	for _, b := range cache {
		clear(b[:cap(b)]) // the stripped newline too
	}
}

// wipeCache is the wipe Load defers; a test seam.
var wipeCache = wipe
