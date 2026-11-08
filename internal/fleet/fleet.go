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
	// Keys2 holds ~/.ssh/authorized_keys2's bytes when the reader was asked
	// for them (sshread.Client.ReadKeys2) and AuthorizedKeys2 is true;
	// Keys2Err is why they could not be read (the main read still stands).
	// Only the post-revoke sweep asks.
	Keys2    []byte
	Keys2Err error
	// Posture lists the StrictModes problems on the managed file and its
	// directories, as the posture probe reported them. Nil on a clean path.
	Posture []PostureIssue
}

// The posture issue names: the JSON "issue" values and the probe's grammar.
const (
	PostureSymlink       = "symlink"
	PostureForeignOwner  = "foreign_owner"
	PostureGroupWritable = "group_writable"
	PostureWorldWritable = "world_writable"
)

// PostureIssue is one problem on the managed authorized_keys file or one of
// its directories, the conditions sshd's StrictModes refuses.
type PostureIssue struct {
	Path  string // sanitized; remote-controlled once resolved
	Issue string // one of the Posture* names
	Mode  string // ls -ldn's first field, e.g. "drwxrwxrwx"
	UID   string // the owner's uid as printed
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
