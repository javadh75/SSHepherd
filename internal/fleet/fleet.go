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
