package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestJSONWriteConnectTimeoutIsTimeout: the per-server timeout firing
// during the write connect is a started server that failed — "timeout",
// never "canceled", which the document reserves for a pending server that
// never started. The write connect's AfterFunc cancels its detached ctx
// when the per-server deadline expires, so the transport sees a plain
// cancellation and classifies it "canceled" (ARC-3 repair). This drives the
// real sshwrite.FleetWriter against a stalling sshtest server, so it lives
// with the wiring in cmd rather than in internal/apply (ARC-8).
func TestJSONWriteConnectTimeoutIsTimeout(t *testing.T) {
	hostKey := sshtest.Signer(t, sshtest.Key(200))
	s := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hostKey}, Stall: true})
	w := &sshwrite.FleetWriter{Dialer: &sshconn.Dialer{
		KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(hostKey.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))},
		DialTimeout:    5 * time.Second,
	}}
	line := testkeys.Line(t, 1)
	held, err := authkeys.ParseLine(line)
	if err != nil || held == nil {
		t.Fatalf("ParseLine: %v", err)
	}
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + line + "\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	plans := []apply.ServerPlan{{
		Server:   config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"},
		Class:    apply.ClassChange,
		Outcome:  apply.OutcomePending,
		Desired:  []authkeys.Key{*held},
		Rendered: []byte("rendered for web-1\n"),
		Expect:   fleet.SnapshotOf(false, []byte("phase-1 bytes of web-1\n")),
	}}
	apply.Execute(context.Background(), plans, w, apply.ExecOptions{Parallel: 1, PerServerTimeout: 200 * time.Millisecond,
		Held: []fleet.HeldKey{{Fingerprint: held.Fingerprint, Source: fleet.SourceAgent}}})

	if plans[0].Outcome != apply.OutcomeFailed {
		t.Fatalf("Outcome = %s (err %v), want failed", plans[0].Outcome, plans[0].OutcomeErr)
	}
	var buf bytes.Buffer
	if err := apply.RenderJSON(&buf, cfg, plans, apply.JSONOptions{Command: "apply"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Servers []struct {
			Name      string  `json:"name"`
			Error     *string `json:"error"`
			ErrorKind string  `json:"error_kind"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].Error == nil || doc.Servers[0].ErrorKind != string(fleet.ErrorKindTimeout) {
		t.Errorf("servers = %+v, want one failed server with error_kind timeout\n%s", doc.Servers, buf.String())
	}
}
