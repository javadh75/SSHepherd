# Owner answers: full review 2026-11-10

Waves: 1 security and data loss (F001, F007, F010, G016) · 2 access model and preserve (G002, G014, F005, G003, G019, G015) · 3 import, manifest and apply (F006, G005, G006, G022, G028, F030, F035) · 4 CI, release, supply chain (F017, F018, F019, F039, F040) · 5 project health and docs (F022, F044, F045, F029, G023, G030, re-rates).

## Wave 1
- F001 (2026-11-11): (a) a host certificate refused because its CA or its key is @revoked is host_key_revoked, exit 2, with a hint.
- F007 (2026-11-11): (a) the forwarding guard judges the first surviving key in OfferOrder (the key the hop logs in with) and refuses when it cannot forward to every dependent; the post-write forward probe covers every dependent, not deps[0]. OfferOrder (D31) unchanged.
- F010 (2026-11-11): (c) a first-contact write (snapshot absent) removes a stale .sshepherd.bak with the same `rm -f "$b" || exit 1` step the normal branch uses, after the absent check; the lockout/unknown-state messages for that case say there was no previous file and the undo is deleting it; test plants an old .bak; mutation run on the line.
- G016 (2026-11-11): (a) explain and test: a pre-banner handshake EOF gets a hint naming sshd PerSourcePenalties (server log "drop connection ... penalty", fix the account or PerSourcePenaltyExemptList); README connection-posture section; one integration container keeps the distro default penalties and pins the classification of audit and the login check. No fan-out change.

## Wave 2
- G002 (2026-11-11): (a) a preserve: rule keeps a line only when it cannot forward (port, agent, X11 forwarding and tunnel blocked, e.g. restrict or the no-*-forwarding options; no permitopen/permitlisten); a matching line that can forward is not kept (audit: unknown key; apply removes it).
- G014 (2026-11-11): (a) a command: preserve pattern that can match a shell metacharacter (; | & $ backtick ( ) < > quotes backslash newline; any char, \S, negated classes) is a load error (exit 3), decided by walking the regexp syntax tree; README says patterns should also be tight on arguments.
- F005 (2026-11-11): (a) reverses the earlier OP6 confirmation for this sub-case: a restriction clash does not hold a removal-only write (every kept line equal to what is installed, at least one line removed), like the weak-key exception; the clash still refuses every other write; the follow-up hint no longer loops.
- G003 (2026-11-11): (a) revoke/rotate exit 2 whenever the run itself read a server and saw a key it just revoked still installed there (emptied, clash, serial or any other refusal), without --sweep; no extra servers are read; TestRevokeSoleGrantee flips to 2; README exit table updated.
- G019 (2026-11-11): (a) a never-wipe (emptied-server) refusal is save-neutral like weak-key and clash refusals: revoke saves the tombstone and removes the user even when no affected server can be written; the server is still never emptied; audit then reports the key REVOKED; README and TestRevokeNothingCanLand updated.
- G015 (2026-11-11): (a) reverses S6 "an owned key is always managed": a line whose key the manifest owns is kept when a preserve: rule matches and that user has no grant on this server and no access tombstone for it; a key tombstone still wins; audit lists it as externally managed; adopt --merge does not extend the user there. revoke --from-server cannot trim it (no grant): use revoke USER or revoke --key.

## Wave 3
- F006 (2026-11-11): (c) git holds the serial: a removal is never written without a serial that covers it; when the manifest cannot be saved, exit 3 names the fix (set serial: N in the manifest's source, N = max server header + 1); README CronJob and CI recipes rewritten (bump in the offboarding commit, PR check with apply --dry-run); new apply flag --no-manifest-save treats a writable CI checkout like a read-only manifest (never saves; refuses with the same hint when a bump is needed).
