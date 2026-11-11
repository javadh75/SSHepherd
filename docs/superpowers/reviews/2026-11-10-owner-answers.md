# Owner answers: full review 2026-11-10

Waves: 1 security and data loss (F001, F007, F010, G016) · 2 access model and preserve (G002, G014, F005, G003, G019, G015) · 3 import, manifest and apply (F006, G005, G006, G022, G028, F030, F035) · 4 CI, release, supply chain (F017, F018, F019, F039, F040) · 5 project health and docs (F022, F044, F045, F029, G023, G030, re-rates).

## Wave 1
- F001 (2026-11-11): (a) a host certificate refused because its CA or its key is @revoked is host_key_revoked, exit 2, with a hint.
- F007 (2026-11-11): (a) the forwarding guard judges the first surviving key in OfferOrder (the key the hop logs in with) and refuses when it cannot forward to every dependent; the post-write forward probe covers every dependent, not deps[0]. OfferOrder (D31) unchanged.
- F010 (2026-11-11): (c) a first-contact write (snapshot absent) removes a stale .sshepherd.bak with the same `rm -f "$b" || exit 1` step the normal branch uses, after the absent check; the lockout/unknown-state messages for that case say there was no previous file and the undo is deleting it; test plants an old .bak; mutation run on the line.
- G016 (2026-11-11): (a) explain and test: a pre-banner handshake EOF gets a hint naming sshd PerSourcePenalties (server log "drop connection ... penalty", fix the account or PerSourcePenaltyExemptList); README connection-posture section; one integration container keeps the distro default penalties and pins the classification of audit and the login check. No fan-out change.
