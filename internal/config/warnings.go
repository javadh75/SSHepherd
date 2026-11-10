package config

// The manifest_warnings kinds config records. Consumers ignore kinds they do
// not know; validate adds its own in cmd/sshepherd.
const (
	WarnTombstoneUnknownServer = "tombstone_unknown_server"
	WarnCommentOnMultiKey      = "comment_on_multi_key"
	WarnWeakKeyUngranted       = "weak_key_ungranted"
	WarnKeyExpired             = "key_expired"
	WarnWildcardRoot           = "wildcard_root"
	WarnTombstoneBlocksGrant   = "tombstone_blocks_grant"
	WarnEmptyGroup             = "empty_group"
	WarnOperatorGrantRedundant = "operator_grant_redundant"
	WarnJumpOnlyUnused         = "jump_only_unused"
)

// ManifestWarning is one load warning in structured form: an object of
// manifest_warnings in the audit, apply and validate JSON. RevokedIndex, User
// and Server belong to tombstone_unknown_server and tombstone_blocks_grant;
// User also to operator_grant_redundant, Server to validate's
// host_key_not_recorded and to jump_only_unused. RevokedIndex is a pointer so
// revoked[0] still prints.
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
