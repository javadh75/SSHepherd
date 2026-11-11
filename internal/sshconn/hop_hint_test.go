package sshconn

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestKeyscanCompareCmdThroughBastion: a via server's comparison scan runs
// on its bastion, never from the operator's machine, and says so.
func TestKeyscanCompareCmdThroughBastion(t *testing.T) {
	key := sshtest.Signer(t, sshtest.Key(40)).PublicKey()
	target := config.Server{Name: "web-1", Host: "10.0.5.5", Port: 22, User: "deploy", Via: "bastion-eu"}
	bastion := config.Server{Name: "bastion-eu", Host: "bastion.example.com", Port: 22, User: "jump"}
	edge := config.Server{Name: "edge", Host: "edge.example.com", Port: 2200, User: "ops"}
	const label = " | ssh-keygen -lf - (as seen by the bastion; still compare with the console)"
	for _, tt := range []struct {
		name  string
		srv   config.Server
		route []config.Server
		want  string
	}{
		{"direct: unchanged", config.Server{Host: "10.0.0.1", Port: 22}, nil,
			"ssh-keyscan -t ed25519 -p 22 '10.0.0.1' | ssh-keygen -lf -"},
		{"one bastion", target, []config.Server{bastion},
			"ssh -p 22 jump@bastion.example.com ssh-keyscan -t ed25519 -p 22 10.0.5.5" + label},
		{"two bastions", target, []config.Server{edge, bastion},
			"ssh -J ops@edge.example.com:2200 -p 22 jump@bastion.example.com ssh-keyscan -t ed25519 -p 22 10.0.5.5" + label},
		{"a host that is not a plain word", config.Server{Host: "db$(x)", Port: 22}, []config.Server{bastion},
			`ssh -p 22 jump@bastion.example.com ssh-keyscan -t ed25519 -p 22 ''\''db$(x)'\'''` + label},
		{"an IPv6 bastion", target, []config.Server{{Name: "b6", Host: "2001:db8::1", Port: 22, User: "jump"}},
			"ssh -p 22 jump@2001:db8::1 ssh-keyscan -t ed25519 -p 22 10.0.5.5" + label},
		// A bastion word that could be read as an ssh option (or that needs
		// quoting ssh might undo in a ProxyJump command) is never pasted
		// into a local ssh command: the scan is named, run on the bastion.
		{"a bastion user that reads as an option", target,
			[]config.Server{{Name: "bastion-eu", Host: "bastion.example.com", Port: 22, User: "-oProxyCommand=touch${IFS}/tmp/pwned"}},
			`on bastion "bastion-eu": ssh-keyscan -t ed25519 -p 22 10.0.5.5` + label},
		{"a plain bastion user with a leading dash", target,
			[]config.Server{{Name: "bastion-eu", Host: "bastion.example.com", Port: 22, User: "-v"}},
			`on bastion "bastion-eu": ssh-keyscan -t ed25519 -p 22 10.0.5.5` + label},
		{"a bastion host with a leading dash", target,
			[]config.Server{{Name: "bastion-eu", Host: "-oProxyCommand=x", Port: 22, User: "jump"}},
			`on bastion "bastion-eu": ssh-keyscan -t ed25519 -p 22 10.0.5.5` + label},
		{"an outer bastion that reads as an option", target,
			[]config.Server{{Name: "edge", Host: "-edge", Port: 2200, User: "ops"}, bastion},
			`on bastion "bastion-eu": ssh-keyscan -t ed25519 -p 22 10.0.5.5` + label},
		{"an outer bastion user that needs quoting", target,
			[]config.Server{{Name: "edge", Host: "edge.example.com", Port: 2200, User: "o$(x)"}, bastion},
			`on bastion "bastion-eu": ssh-keyscan -t ed25519 -p 22 10.0.5.5` + label},
		{"a target host with a leading dash", config.Server{Host: "-v.example.com", Port: 22}, []config.Server{bastion},
			"ssh -p 22 jump@bastion.example.com ssh-keyscan -t ed25519 -p 22 -- -v.example.com" + label},
		{"direct: a host with a leading dash", config.Server{Host: "-f/etc/hosts", Port: 22}, nil,
			"ssh-keyscan -t ed25519 -p 22 -- '-f/etc/hosts' | ssh-keygen -lf -"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyscanCompareCmd(key, tt.srv, tt.route); got != tt.want {
				t.Errorf("keyscanCompareCmd =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// TestRouteCmd pins the exported route builder (G017's lock-removal
// command goes through it): remote words reach dest's shell as given, every
// bastion goes in one -J, and a route with a word that is not a hopWord
// gets no local ssh command, only what to run on the named bastion.
func TestRouteCmd(t *testing.T) {
	script := `p="${HOME:?}"/'.ssh/authorized_keys'; rmdir -- "$p.sshepherd.lock"`
	target := config.Server{Name: "hopped", Host: "10.9.0.5", Port: 22, User: "deploy"}
	bastion := config.Server{Name: "bastion", Host: "bastion.example.com", Port: 2222, User: "jump"}
	edge := config.Server{Name: "edge", Host: "edge.example.com", Port: 22, User: "ops"}
	onBastion := []string{"ssh", "-p", "22", "deploy@10.9.0.5", ShQuote(script)}
	for _, tt := range []struct {
		name string
		hops []config.Server
		dest config.Server
		want string
	}{
		{"no bastion", nil, target,
			`ssh -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rmdir -- "$p.sshepherd.lock"'`},
		{"one bastion", []config.Server{bastion}, target,
			`ssh -J jump@bastion.example.com:2222 -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rmdir -- "$p.sshepherd.lock"'`},
		{"two bastions, root first", []config.Server{edge, bastion}, target,
			`ssh -J ops@edge.example.com:22,jump@bastion.example.com:2222 -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rmdir -- "$p.sshepherd.lock"'`},
		{"a bastion user that reads as an option", []config.Server{edge, {Name: "bastion", Host: "bastion.example.com", Port: 22, User: "-oProxyCommand=x"}}, target,
			`on bastion "bastion": ssh -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rmdir -- "$p.sshepherd.lock"'`},
		{"a dest host that is not a plain word", []config.Server{bastion}, config.Server{Name: "x", Host: "db$(x)", Port: 22, User: "deploy"},
			`on bastion "bastion": ssh -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rmdir -- "$p.sshepherd.lock"'`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := RouteCmd(tt.hops, tt.dest, []string{script}, "bastion", onBastion); got != tt.want {
				t.Errorf("RouteCmd =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// TestUnknownTargetHostKeyHintThroughHop: an unrecorded target behind a
// bastion is the target's own failure, and its hint scans from the bastion.
func TestUnknownTargetHostKeyHintThroughHop(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
	f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(f.hopKey.PublicKey()))
	_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
	if kindOf(t, err) != fleet.ErrorKindHostKeyUnknown || fleet.FailedHopOf(err) != "" {
		t.Fatalf("err = %v, want the target's own host_key_unknown", err)
	}
	want := "ssh -p " + strconv.Itoa(f.hop.Port) + " jump@127.0.0.1 ssh-keyscan -t ed25519 -p " + strconv.Itoa(f.target.Port) +
		" 127.0.0.1 | ssh-keygen -lf - (as seen by the bastion; still compare with the console)"
	if hint := fleet.HintOf(err); !strings.Contains(hint, want) {
		t.Errorf("hint = %q, want it to contain %q", hint, want)
	}
}
