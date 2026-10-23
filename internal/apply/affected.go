package apply

import (
	"bytes"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// AffectedSet is the scope of a manifest edit (revoke/rotate): the servers
// whose rendered desired file changes between the old and the new config.
type AffectedSet struct {
	// Servers lists the servers whose rendered desired bytes differ, in
	// manifest order — including servers where reality already matches
	// the new render (apply reports them converged).
	Servers []string
	// Emptied is the subset whose desired set is empty under the new config
	// but not the old: apply never empties a server, so a key removed by
	// the edit cannot be removed there by SSHepherd.
	Emptied []string
}

// Affected compares, per server, the file apply would render under old and
// under edited. Pure. Both configs must hold the same servers (revoke and
// rotate never change the server list); servers are walked in edited's
// manifest order.
func Affected(old, edited *config.Config) AffectedSet {
	var s AffectedSet
	for _, srv := range edited.Servers {
		before, after := renderFor(old, srv.Name), renderFor(edited, srv.Name)
		if before != nil && after != nil && bytes.Equal(before, after) {
			continue
		}
		s.Servers = append(s.Servers, srv.Name)
		if len(edited.DesiredFor(srv.Name)) == 0 && len(old.DesiredFor(srv.Name)) > 0 {
			s.Emptied = append(s.Emptied, srv.Name)
		}
	}
	return s
}

// renderFor renders a server's desired file exactly as Build does; nil on
// a render failure (impossible for a validated config), which Affected
// treats as "changed" — over-including a server is the safe direction.
func renderFor(cfg *config.Config, server string) []byte {
	out, err := authkeys.Render(desiredEntries(cfg, server))
	if err != nil {
		return nil
	}
	return out
}
