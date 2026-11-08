package fleet

// ReadResult is the outcome of reading a server's authorized_keys.
// FileAbsent means login succeeded but the audited file does not exist —
// a strong signal sshd consults a different key source on that host.
type ReadResult struct {
	Content    []byte
	FileAbsent bool
	// SessionKeyFP is the SHA256 fingerprint of the key (--identity file or
	// agent) that completed
	// this read's SSH handshake — apply's guard note ("removes the key this
	// session logged in with") consumes it. Empty for readers that do not
	// authenticate (fakes).
	SessionKeyFP string
	// AuthorizedKeys2 reports that ~/.ssh/authorized_keys2 exists and is
	// non-empty. OpenSSH's compiled-in AuthorizedKeysFile consults it after
	// authorized_keys, so keys in it log in although SSHepherd neither reads
	// nor manages them. Probed only when the audited path is the default.
	AuthorizedKeys2 bool
}

// SourceAgent is HeldKey.Source for a key the ssh-agent holds.
const SourceAgent = "agent"

// HeldKey is one plain key the run can authenticate with: its SHA256
// fingerprint and where it comes from — the --identity path, or
// SourceAgent.
type HeldKey struct {
	Fingerprint string
	Source      string
}

// Label renders the key with its source, as refusals list it:
// "SHA256:… (/home/op/.ssh/ci)" or "SHA256:… (agent)".
func (k HeldKey) Label() string { return k.Fingerprint + " (" + k.Source + ")" }

// MaxRemoteOutput caps remote stdout/stderr buffering (1 MiB) and, so a
// written file can always be read back, the rendered file size.
const MaxRemoteOutput = 1 << 20
