package fleet

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// managed is a managed-header file (authkeys.ManagedHeader plus one line),
// spelled out so this stdlib-only package's tests import nothing else.
const managed = "# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.\nkey-line\n"

// TestIsRefusal: only errors wrapped by Refused count, through any wrapper;
// the message is the wrapped error's, unchanged.
func TestIsRefusal(t *testing.T) {
	base := errors.New("/home/u/.ssh/authorized_keys changed since the plan was read")
	r := Refused(base)
	if !IsRefusal(r) || !IsRefusal(fmt.Errorf("srv: %w", r)) {
		t.Fatal("wrapped refusal not recognized")
	}
	if r.Error() != base.Error() || !errors.Is(r, base) {
		t.Fatalf("Refused changed the error: %q", r.Error())
	}
	if IsRefusal(base) || IsRefusal(nil) {
		t.Fatal("plain error counted as a refusal")
	}
}

func TestSnapshotOf(t *testing.T) {
	if got := SnapshotOf(true, []byte("ignored")); got != (Snapshot{Absent: true}) {
		t.Errorf("absent = %+v", got)
	}
	if got := SnapshotOf(false, []byte("x\n")); got.Size != 2 || got.Cksum != Cksum([]byte("x\n")) {
		t.Errorf("present = %+v", got)
	}
}

func TestHeldKeyLabel(t *testing.T) {
	if got := (HeldKey{Fingerprint: "SHA256:x", Source: SourceAgent}).Label(); got != "SHA256:x (agent)" {
		t.Errorf("Label = %q", got)
	}
}

func TestCksumMatchesPOSIXCksum(t *testing.T) {
	// Fixed vectors pin the algorithm even where no cksum binary exists.
	vectors := []struct {
		in   string
		want uint32
	}{
		{"", 4294967295},
		{"abc", 1219131554},
	}
	for _, v := range vectors {
		if got := Cksum([]byte(v.in)); got != v.want {
			t.Errorf("Cksum(%q) = %d, want %d", v.in, got, v.want)
		}
	}
	bin, err := exec.LookPath("cksum")
	if err != nil {
		t.Skip("no cksum binary to cross-check against")
	}
	inputs := [][]byte{[]byte(managed), bytes.Repeat([]byte("ssh-ed25519 AAAA x\n"), 4000), {0, 1, 2, 255}}
	for _, in := range inputs {
		c := exec.CommandContext(t.Context(), bin)
		c.Stdin = bytes.NewReader(in)
		out, err := c.Output()
		if err != nil {
			t.Fatalf("cksum: %v", err)
		}
		f := strings.Fields(string(out))
		snap := SnapshotOf(false, in)
		if len(f) < 2 || f[0] != strconv.FormatUint(uint64(snap.Cksum), 10) || f[1] != strconv.Itoa(snap.Size) {
			t.Errorf("cksum binary says %q, Go says %d %d", out, snap.Cksum, snap.Size)
		}
	}
}
