package manifest

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// FuzzMergeRoundTrip asserts the merge machinery's core safety property: any
// manifest Load accepts must survive an append-nothing re-encode with every
// user name, server name, and access entry intact, and the output must still
// satisfy config.Parse. A merge round-trip is a parser, so it gets fuzzed
// like every other parser in this project.
func FuzzMergeRoundTrip(f *testing.F) {
	seeds := []string{
		commentedFixture(f),
		"users: []\nservers: []\naccess: []\n",
		"",
		"users:\nservers:\naccess:\n",
		"{}\n",
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n",
		"users:\nservers:\n&0000: ", // found by fuzzing: anchored empty key survived config.Parse but broke the reparse
		tagEditFixture(f),
		groupEditFixture(f),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		mf, err := Load([]byte(in))
		if err != nil {
			t.Skip() // not a valid manifest; nothing to round-trip
		}
		out, err := mf.Encode()
		if err != nil {
			t.Fatalf("Encode failed on Load-accepted input %q: %v", in, err)
		}
		got, err := config.Parse(out)
		if err != nil {
			t.Fatalf("re-encoded manifest rejected by config.Parse for input %q:\n%s\nerr: %v", in, out, err)
		}
		want := mf.Config()
		if !reflect.DeepEqual(userNames(want), userNames(got)) {
			t.Errorf("user names changed: %v -> %v (input %q)", userNames(want), userNames(got), in)
		}
		if !reflect.DeepEqual(serverNames(want), serverNames(got)) {
			t.Errorf("server names changed: %v -> %v (input %q)", serverNames(want), serverNames(got), in)
		}
		if !reflect.DeepEqual(accessPairs(want), accessPairs(got)) {
			t.Errorf("access entries changed: %v -> %v (input %q)", accessPairs(want), accessPairs(got), in)
		}

		// Second pass: the mutation half of the invariant. Appending a fixed
		// user, a fixed server, and a grant tying them together through the
		// real node surgery must still yield a manifest config.Parse accepts,
		// with the originals AND every addition intact. Skipped when the
		// fuzzed input already claims the name, the key, or the server name
		// (config validation would rightly reject the duplicate). The server
		// guard also covers every shape incompatible with the fixed grant: a
		// pre-existing grant or except: naming "fuzz-added-server" can only
		// exist in a manifest that already declares that server.
		keyLine := testkeys.Line(t, 7)
		k, err := authkeys.ParseLine(keyLine)
		if err != nil || k == nil {
			t.Fatalf("parse fuzz key line: %v", err)
		}
		if _, taken := want.OwnerOf(k.Fingerprint); taken {
			return
		}
		for _, u := range want.Users {
			if u.Name == "fuzz-added-user" {
				return
			}
		}
		for _, s := range want.Servers {
			if s.Name == "fuzz-added-server" {
				return
			}
		}
		mf2, err := Load([]byte(in))
		if err != nil {
			t.Fatalf("second Load of accepted input %q failed: %v", in, err)
		}
		if err := mf2.Append([]string{"fuzz merge marker"}, []config.User{
			{Name: "fuzz-added-user", Keys: []string{keyLine}},
		}, []config.Server{
			{Name: "fuzz-added-server", Host: "10.0.0.99", User: "deploy"},
		}, []config.Access{
			{User: "fuzz-added-user", Servers: []string{"fuzz-added-server"}},
		}); err != nil {
			t.Fatalf("Append on Load-accepted input %q: %v", in, err)
		}
		out2, err := mf2.Encode()
		if err != nil {
			t.Fatalf("Encode after Append on input %q: %v", in, err)
		}
		got2, err := config.Parse(out2)
		if err != nil {
			t.Fatalf("appended manifest rejected by config.Parse for input %q:\n%s\nerr: %v", in, out2, err)
		}
		if !reflect.DeepEqual(append(userNames(want), "fuzz-added-user"), userNames(got2)) {
			t.Errorf("after append, user names = %v, want originals plus fuzz-added-user (input %q)", userNames(got2), in)
		}
		if !reflect.DeepEqual(append(serverNames(want), "fuzz-added-server"), serverNames(got2)) {
			t.Errorf("after append, server names = %v, want originals plus fuzz-added-server (input %q)", serverNames(got2), in)
		}
		if !reflect.DeepEqual(append(accessPairs(want), "fuzz-added-user\x00fuzz-added-server"), accessPairs(got2)) {
			t.Errorf("after append, access pairs = %v, want originals plus the fuzz grant (input %q)", accessPairs(got2), in)
		}
	})
}

func userNames(c *config.Config) []string {
	names := make([]string, 0, len(c.Users))
	for _, u := range c.Users {
		names = append(names, u.Name)
	}
	return names
}

func serverNames(c *config.Config) []string {
	names := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		names = append(names, s.Name)
	}
	return names
}

// accessPairs flattens every grant to "user\x00server" strings so entry
// order, server order, and except carve-outs all participate in the compare.
func accessPairs(c *config.Config) []string {
	var pairs []string
	for _, a := range c.Access {
		for _, s := range a.Servers {
			pairs = append(pairs, a.User+"\x00"+s)
		}
		for _, e := range a.Except {
			pairs = append(pairs, a.User+"\x00except\x00"+e)
		}
	}
	return pairs
}
