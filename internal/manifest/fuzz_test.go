package manifest

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
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
