// Package sshconn holds the SSH connection glue and remote-command plumbing
// shared by the read path (sshread) and the write path (sshwrite): POSIX
// quoting, remote command builders, capped output buffers, sanitization of
// remote-controlled text, and the agent-auth/strict-known_hosts connect
// sequence. Extracted verbatim from sshread (2026-07-19 apply spec) so a fix
// to this security-sensitive code can never land in only one copy.
package sshconn

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"unicode"

	"github.com/javadh75/SSHepherd/internal/audit"
)

// DefaultAuthorizedKeysPath is the file read (and written) when a server
// sets no authorized_keys_file override in the manifest.
const DefaultAuthorizedKeysPath = "~/.ssh/authorized_keys"

// FileAbsentExit is the sentinel exit status emitted by the command that
// AuthorizedKeysCmdFor builds, signaling "file does not exist" (vs. cat
// failing for other reasons). sshwrite's symlink sentinel 45 is its sibling.
const FileAbsentExit = 44

// MaxRemoteOutput caps how much remote stdout/stderr is buffered (1 MiB).
// authorized_keys files are tiny; anything larger is hostile or broken.
const MaxRemoteOutput = 1 << 20

// ShQuote returns s as one fully single-quoted POSIX shell token: the result
// is wrapped in single quotes and each embedded single quote is rendered by
// the standard POSIX idiom — close the quote, emit an escaped quote, reopen
// (quote, backslash, quote, quote; pinned exactly by TestShQuote — the
// four-character sequence cannot be written literally in a doc comment
// because gofmt rewrites doubled apostrophes). Inside single quotes every
// other byte is literal, so shell metacharacters (;, $(), backticks, |,
// spaces, double quotes) in s are inert. Callers splice the returned token
// verbatim — never add surrounding quotes. Correctness is load-bearing
// (the input is manifest-controlled and runs on every server): pinned by
// table tests and FuzzShQuote's sh round-trip.
func ShQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// PathAssign builds the `p=<path>` shell assignment every remote command
// starts with. The caller-controlled path enters exactly once, as a
// ShQuote-d token — config validation has already rejected control and
// format characters, and the quoting renders everything else inert (defense
// in depth). "~/" paths become "${HOME:?}"/<rest>: tilde expansion inside an
// assignment next to quoted text is a dash/ash portability footgun, and if
// HOME were ever unset remotely, ${HOME:?} fails the command loudly (a
// normal remote error) instead of silently touching a wrong path.
func PathAssign(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return `p="${HOME:?}"/` + ShQuote(rest)
	}
	return "p=" + ShQuote(path)
}

// AuthorizedKeysCmdFor builds the remote command that reads path, exiting
// with the FileAbsentExit sentinel when the file does not exist. The default
// and override cases share this one code path; sshwrite's verify step reads
// back through this exact command.
func AuthorizedKeysCmdFor(path string) string {
	return PathAssign(path) + `; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
}

// interpretExit maps the remote command's exit status to read semantics.
// Remote stderr is sanitized before it is embedded in an error message.
func interpretExit(code int, stderr string) (fileAbsent bool, err error) {
	switch code {
	case 0:
		return false, nil
	case FileAbsentExit:
		return true, nil
	default:
		return false, fmt.Errorf("remote read failed (exit %d): %s", code, strings.TrimSpace(SanitizeRemote(stderr)))
	}
}

// SanitizeRemote strips control characters (except newline and tab) from
// remote-controlled text so a malicious host cannot inject terminal escape
// sequences into operator-facing error messages. unicode.IsControl covers
// C0, DEL, and C1 — C1 CSI (U+009B) acts like ESC [ in some terminals.
// Format (Cf) runes are dropped too: bidi overrides like U+202E can visually
// reorder the message. internal/clog's sanitize applies the same class of
// defense on the log path (collapsing newlines besides); keep the two in
// mind together when changing either.
func SanitizeRemote(s string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// SanitizedError control-strips the wrapped error's message while preserving
// the errors.Is/As chain. Both the read and write paths wrap their returned
// errors in it: handshake and remote-command errors can embed
// server-supplied text, which must never reach an operator's terminal raw.
type SanitizedError struct{ Err error }

func (e SanitizedError) Error() string { return SanitizeRemote(e.Err.Error()) }
func (e SanitizedError) Unwrap() error { return e.Err }

// CappedBuffer buffers writes up to limit bytes, silently discards the rest,
// and flags that truncation happened. Write never fails: the remote session
// should still finish and report its exit status even when output is
// oversized; the caller decides what truncation means.
type CappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

// NewCappedBuffer returns a buffer that keeps at most limit bytes.
func NewCappedBuffer(limit int) *CappedBuffer { return &CappedBuffer{limit: limit} }

// Write buffers p up to the limit, discarding the excess; it always reports
// len(p) and nil so the remote session can finish and report its exit status.
func (b *CappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.limit - b.buf.Len(); room > 0 {
		if n > room {
			p = p[:room]
			b.truncated = true
		}
		b.buf.Write(p)
	} else if n > 0 {
		b.truncated = true
	}
	return n, nil
}

// String returns the retained bytes as a string.
func (b *CappedBuffer) String() string { return b.buf.String() }

// Bytes returns the retained bytes.
func (b *CappedBuffer) Bytes() []byte { return b.buf.Bytes() }

// Len reports the retained byte count.
func (b *CappedBuffer) Len() int { return b.buf.Len() }

// FinishRead maps the remote command outcome (exit code + captured output)
// to a ReadResult. Pure — unit-testable without a connection. Truncated
// stdout is an error (a partial authorized_keys must never be diffed as
// truth: missing tail keys would be misreported as drift); truncated stderr
// is diagnostics only and is worth a WARN, not a failure.
func FinishRead(code int, stdout, stderr *CappedBuffer, addr string, log *slog.Logger) (audit.ReadResult, error) {
	var zero audit.ReadResult
	if stderr.truncated {
		log.Warn(fmt.Sprintf("%s: remote stderr exceeded %d bytes; diagnostics truncated", addr, MaxRemoteOutput))
	}
	absent, err := interpretExit(code, stderr.String())
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	if stdout.truncated {
		return zero, fmt.Errorf("remote read on %s: remote output exceeded 1MiB — refusing to audit a truncated authorized_keys", addr)
	}
	if absent {
		return audit.ReadResult{FileAbsent: true}, nil
	}
	log.Debug("read authorized_keys", "addr", addr, "bytes", stdout.Len())
	return audit.ReadResult{Content: stdout.Bytes()}, nil
}
