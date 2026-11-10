package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// settingLoss is one kind of manifest-only setting a fresh import cannot
// derive from an ssh config (F1 Q1). lost names what FILE (old) holds that
// the fresh output does not reproduce, in manifest order.
type settingLoss struct {
	what        string // the setting, as the warning names it
	verb        string // what the fresh import does to it
	consequence string
	remedy      string // ends just before "with --merge FILE"
	lost        func(old, fresh *config.Config) []string
}

// settingLosses is checked in manifest order: users, groups, then the
// server fields in config.Server order. One warning per kind keeps each
// remedy beside its names (only an operator can be re-marked from the
// command line).
var settingLosses = []settingLoss{
	{"operator: true users", "does not mark", "they lose their fleet-wide grant", "re-mark them with --operator-key PATH, or keep them",
		func(old, fresh *config.Config) []string {
			return lostUsers(old, fresh, func(u config.User) bool { return u.Operator })
		}},
	{"protected: true users", "does not mark", "their keys lose the critical audit tier and the --operator gate", "keep them",
		func(old, fresh *config.Config) []string {
			return lostUsers(old, fresh, func(u config.User) bool { return u.Protected })
		}},
	{"groups:", "drops", "their members lose the grants made through them", "keep them", lostGroups},
	{"authorized_keys_file: overrides on servers", "drops", "where they stay, apply and audit would use ~/.ssh/authorized_keys", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return s.AuthorizedKeysFile != "" },
				func(was, now config.Server) bool { return was.AuthorizedKeysFile == now.AuthorizedKeysFile }, serverName)
		}},
	{"tags: on servers", "drops", "@tag grants no longer reach them", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return len(s.Tags) > 0 },
				func(was, now config.Server) bool { return slices.Equal(was.Tags, now.Tags) }, serverName)
		}},
	{"via: routes", "does not reproduce", "where they stay, they would be dialed another way", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return s.Via != "" },
				func(was, now config.Server) bool { return was.Via == now.Via },
				func(s config.Server) string { return s.Name + " via " + s.Via })
		}},
	{"jump_only: true servers", "does not mark", "where they stay, apply would manage their authorized_keys", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return s.JumpOnly },
				func(_, now config.Server) bool { return now.JumpOnly }, serverName)
		}},
	{"preserve: rules on servers", "drops", "where they stay, apply would remove the lines they keep", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return len(s.Preserve) > 0 },
				func(was, now config.Server) bool { return slices.Equal(was.Preserve, now.Preserve) }, serverName)
		}},
}

// warnSettingsLost: a fresh import -o FILE --force drops whatever its ssh
// config cannot reproduce. One line per kind of setting, each ending with
// the paste-ready --merge FILE that keeps it (F1 Q1).
func warnSettingsLost(w *importWarnings, out string, old, fresh *config.Config) {
	for _, l := range settingLosses {
		names := l.lost(old, fresh)
		if len(names) == 0 {
			continue
		}
		w.addAll(importWarnSettingsDropped, fmt.Sprintf("%s holds %s (%s) that this fresh import %s: %s; %s with --merge %s",
			out, l.what, strings.Join(names, ", "), l.verb, l.consequence, l.remedy, hintArg(out)))
	}
}

// lostUsers names old's users that has marks when no fresh user that has
// marks holds one of their keys. A fresh import names users after their
// identity files, so users are matched by key, never by name.
func lostUsers(old, fresh *config.Config, has func(config.User) bool) []string {
	var names []string
	for _, u := range old.Users {
		if has(u) && !markedByKey(fresh, u.Keys, has) {
			names = append(names, u.Name)
		}
	}
	return names
}

// markedByKey reports whether a fresh user that has marks owns one of keys.
func markedByKey(fresh *config.Config, keys []string, has func(config.User) bool) bool {
	for _, line := range keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil {
			if owner, ok := fresh.OwnerOf(k.Fingerprint); ok && has(owner) {
				return true
			}
		}
	}
	return false
}

// lostGroups names old's groups the fresh output has no group of that name for.
func lostGroups(old, fresh *config.Config) []string {
	var names []string
	for _, g := range old.Groups {
		if !slices.ContainsFunc(fresh.Groups, func(f config.Group) bool { return f.Name == g.Name }) {
			names = append(names, g.Name)
		}
	}
	return names
}

// lostServers labels old's servers that has selects when the fresh output
// has no server of that name (marked "[not in this import]": apply will not
// touch it, so the consequence applies only where the server stays), or one
// whose setting same rejects.
func lostServers(old, fresh *config.Config, has func(config.Server) bool, same func(was, now config.Server) bool, label func(config.Server) string) []string {
	var names []string
	for _, s := range old.Servers {
		if !has(s) {
			continue
		}
		now, ok := fresh.ServerNamed(s.Name)
		switch {
		case !ok:
			names = append(names, label(s)+" [not in this import]")
		case !same(s, now):
			names = append(names, label(s))
		}
	}
	return names
}

func serverName(s config.Server) string { return s.Name }
