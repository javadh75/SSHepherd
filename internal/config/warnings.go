package config

// The manifest_warnings kinds config records. Consumers ignore kinds they do
// not know; validate adds its own in cmd/sshepherd.
const (
	WarnTombstoneUnknownServer = "tombstone_unknown_server"
	WarnCommentOnMultiKey      = "comment_on_multi_key"
	WarnWeakKeyUngranted       = "weak_key_ungranted"
	WarnKeyExpired             = "key_expired"
)

// ManifestWarning is one load warning in structured form: an object of
// manifest_warnings in the audit, apply and validate JSON. RevokedIndex and
// User belong to tombstone_unknown_server; Server also to validate's
// host_key_not_recorded. RevokedIndex is a pointer so revoked[0] still prints.
type ManifestWarning struct {
	Kind         string `json:"kind"`
	RevokedIndex *int   `json:"revoked_index,omitempty"`
	User         string `json:"user,omitempty"`
	Server       string `json:"server,omitempty"`
	Message      string `json:"message"`
}

// warn records one load warning in both forms, so Warnings (stderr) and
// ManifestWarnings (JSON) can never disagree.
func (c *Config) warn(w ManifestWarning) {
	c.Warnings = append(c.Warnings, w.Message)
	c.ManifestWarnings = append(c.ManifestWarnings, w)
}
