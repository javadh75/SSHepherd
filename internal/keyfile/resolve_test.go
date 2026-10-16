package keyfile

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	const home, cwd = "/home/op", "/work"
	tests := []struct {
		name       string
		ids        []string
		def        string
		perKey     []string
		wantSpecs  []Spec
		wantPP     Passphrases
		wantErrSub string
	}{
		{name: "no flags", wantSpecs: nil},
		{name: "lexical: ~/ expands, relative joins cwd, Clean", ids: []string{"~/.ssh/ci", "keys/../keys/ci_new", "/abs/./k"},
			wantSpecs: []Spec{{"/home/op/.ssh/ci"}, {"/work/keys/ci_new"}, {"/abs/k"}}},
		{name: "duplicate cleaned path de-duplicated silently, first order kept", ids: []string{"/k", "/x/../k", "/j"},
			wantSpecs: []Spec{{"/k"}, {"/j"}}},
		{name: "default file is cleaned", ids: []string{"/k"}, def: "~/pw",
			wantSpecs: []Spec{{"/k"}}, wantPP: Passphrases{Default: "/home/op/pw"}},
		{name: "mapping split at the FIRST =", ids: []string{"/k"}, perKey: []string{"/k=/dev/fd/63=x"},
			wantSpecs: []Spec{{"/k"}}, wantPP: Passphrases{PerKey: map[string]string{"/k": "/dev/fd/63=x"}}},
		{name: "mapping matches lexically before de-dup", ids: []string{"~/.ssh/ci", "/home/op/.ssh/ci"}, perKey: []string{"/home/op/.ssh/./ci=pw"},
			wantSpecs: []Spec{{"/home/op/.ssh/ci"}}, wantPP: Passphrases{PerKey: map[string]string{"/home/op/.ssh/ci": "/work/pw"}}},
		{name: "passphrase flags need --identity (default)", def: "/pw", wantErrSub: "passphrase flags need --identity"},
		{name: "passphrase flags need --identity (per key)", perKey: []string{"/k=/pw"}, wantErrSub: "passphrase flags need --identity"},
		{name: "unmatched KEY lists the cleaned paths", ids: []string{"~/.ssh/a", "b"}, perKey: []string{"/c=/pw"},
			wantErrSub: "--identity-passphrase: /c matches no --identity (--identity paths: /home/op/.ssh/a, /work/b)"},
		{name: "symlinks are not resolved: a different spelling does not match", ids: []string{"/link/k"}, perKey: []string{"/real/k=/pw"},
			wantErrSub: "matches no --identity"},
		{name: "matching is case sensitive", ids: []string{"/K"}, perKey: []string{"/k=/pw"}, wantErrSub: "matches no --identity"},
		{name: "same KEY twice", ids: []string{"/k"}, perKey: []string{"/k=/a", "/k=/b"}, wantErrSub: "--identity-passphrase: /k is given twice"},
		{name: "missing =", ids: []string{"/k"}, perKey: []string{"/k"}, wantErrSub: `--identity-passphrase "/k": want KEY=FILE`},
		{name: "empty FILE", ids: []string{"/k"}, perKey: []string{"/k="}, wantErrSub: "want KEY=FILE"},
		{name: "empty KEY", ids: []string{"/k"}, perKey: []string{"=/pw"}, wantErrSub: "want KEY=FILE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, pp, err := Resolve(tt.ids, tt.def, tt.perKey, home, cwd)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("err = %v, want %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if !reflect.DeepEqual(specs, tt.wantSpecs) {
				t.Errorf("specs = %v, want %v", specs, tt.wantSpecs)
			}
			if !reflect.DeepEqual(pp, tt.wantPP) {
				t.Errorf("passphrases = %+v, want %+v", pp, tt.wantPP)
			}
		})
	}
}

func TestResolveUnknownHome(t *testing.T) {
	if _, _, err := Resolve([]string{"~/k"}, "", nil, "", "/work"); err == nil || !strings.Contains(err.Error(), "home directory unknown") {
		t.Fatalf("err = %v, want the unknown-home error", err)
	}
	if _, _, err := Resolve([]string{"/k"}, "~/pw", nil, "", "/work"); err == nil {
		t.Fatal("unexpandable default file accepted")
	}
	if _, _, err := Resolve([]string{"/k"}, "", []string{"~/k=/pw"}, "", "/work"); err == nil {
		t.Fatal("unexpandable mapping key accepted")
	}
	if _, _, err := Resolve([]string{"/k"}, "", []string{"/k=~/pw"}, "", "/work"); err == nil {
		t.Fatal("unexpandable mapping file accepted")
	}
}
