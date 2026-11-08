package sshconn

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// offerFixture: a server that accepts only key 3, an agent holding 1, 2, 3.
func offerFixture(t *testing.T) (fixture, string, []string) {
	t.Helper()
	a, b, c := sshtest.Key(1), sshtest.Key(2), sshtest.Key(3)
	host := sshtest.Signer(t, sshtest.Key(40))
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, c).PublicKey()},
	}, a, b, c)
	return f, sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey())),
		[]string{sshtest.Fingerprint(t, a), sshtest.Fingerprint(t, b), sshtest.Fingerprint(t, c)}
}

func grants(fps ...string) func(config.Server) []string {
	return func(config.Server) []string { return fps }
}

func logBuffer() (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func tryConnect(t *testing.T, d *Dialer, srv config.Server) error {
	t.Helper()
	conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// TestRestrictedOfferRevealsOnlyGranted (SEC-5): three keys loaded, two
// granted, neither accepted: the server is asked about exactly those two and
// the login fails. The old order (granted first, then the rest) goes on to
// offer key 3 and logs in, so this fails without the restriction. The
// spec's "3 loaded, 1 granted → 1 query" is TestAuthFailureHintsOfferAllKeys.
func TestRestrictedOfferRevealsOnlyGranted(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0], fps[1])
	err := tryConnect(t, d, f.cfgSrv)
	if err == nil {
		t.Fatal("connect succeeded: a withheld key was offered")
	}
	if k := kindOf(t, err); k != fleet.ErrorKindAuth {
		t.Fatalf("kind = %q, want auth", k)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0], fps[1]}) {
		t.Errorf("server was offered %v, want only the granted keys", got)
	}
}

// TestAuthFailureHintsOfferAllKeys: the granted key is held but not
// installed. No retry widens the offer; the hint names the flag.
func TestAuthFailureHintsOfferAllKeys(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0]) // held, but the server only accepts key 3
	err := tryConnect(t, d, f.cfgSrv)
	if err == nil {
		t.Fatal("connect succeeded")
	}
	if k := kindOf(t, err); k != fleet.ErrorKindAuth {
		t.Fatalf("kind = %q, want auth", k)
	}
	want := "none of the keys the manifest grants here were accepted; 2 other loaded keys were not offered — if one of them still logs in here, re-run with --offer-all-keys (this server then sees every loaded key)"
	if got := fleet.HintOf(err); got != want {
		t.Errorf("hint:\n got %s\nwant %s", got, want)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0]}) {
		t.Errorf("attempts = %v, want exactly the granted key and no second handshake", got)
	}
}

func TestAuthFailureHintSingularAndAbsent(t *testing.T) {
	if got := (offering{withheld: 1}).authHint(fleet.ErrorKindAuth); !strings.Contains(got, "1 other loaded key was not offered") {
		t.Errorf("hint = %q", got)
	}
	if got := (offering{withheld: 2}).authHint(fleet.ErrorKindDial); got != "" {
		t.Errorf("a non-auth failure carries no offer hint: %q", got)
	}
	if got := (offering{}).authHint(fleet.ErrorKindAuth); got != "" {
		t.Errorf("nothing withheld, nothing to hint: %q", got)
	}
}

// TestOfferAllKeysLogsInWithAnotherHeldKey: the escape hatch restores
// today's offer, granted first and then the rest.
func TestOfferAllKeysLogsInWithAnotherHeldKey(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0])
	d.OfferAll = true
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0], fps[1], fps[2]}) {
		t.Errorf("attempts = %v, want granted first, then the rest", got)
	}
}

func TestFallbackWarnsOnceAndOffersEveryKey(t *testing.T) {
	f, kh, fps := offerFixture(t)
	buf, log := logBuffer()
	d := f.dialer(kh)
	d.PreferKeys = grants("SHA256:unheld")
	d.Log = log
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, fps) {
		t.Errorf("attempts = %v, want every held key", got)
	}
	want := "web-1: none of the keys granted here are loaded; offering all 3 held keys"
	if n := strings.Count(buf.String(), want); n != 1 || !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("want one WARN %q, got:\n%s", want, buf.String())
	}
}

// TestQuietFallbackIsDebug (OP6): after the run's preflight warned, the
// per-server fallback line is debug level.
func TestQuietFallbackIsDebug(t *testing.T) {
	f, kh, _ := offerFixture(t)
	var buf bytes.Buffer
	d := f.dialer(kh)
	d.PreferKeys = grants("SHA256:unheld")
	d.QuietFallback = true
	d.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")
	i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "none of the keys granted here") })
	if i < 0 || !strings.Contains(lines[i], "level=DEBUG") {
		t.Errorf("want the fallback line at debug level, got:\n%s", buf.String())
	}
}

func TestGrantIndex(t *testing.T) {
	user, ca := sshtest.Key(1), sshtest.Key(50)
	plain := sshtest.Signer(t, user).PublicKey()
	cert := sshtest.UserCert(t, user, ca, "deploy")
	fpUser, fpCA := sshtest.Fingerprint(t, user), sshtest.Fingerprint(t, ca)
	if got := GrantIndex(plain, []string{"x", fpUser}); got != 1 {
		t.Errorf("plain key index = %d", got)
	}
	if got := GrantIndex(plain, []string{fpCA}); got != -1 {
		t.Errorf("ungranted key index = %d", got)
	}
	if got := GrantIndex(cert, []string{fpCA, "y", fpUser}); got != 0 {
		t.Errorf("certificate takes its best match, got %d", got)
	}
}
