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
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyscanCompareCmd(key, tt.srv, tt.route); got != tt.want {
				t.Errorf("keyscanCompareCmd =\n%s\nwant\n%s", got, tt.want)
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
