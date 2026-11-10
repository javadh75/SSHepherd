## Upgrade notes

**Weak keys are now policy conflicts.** A DSA key, or an RSA key under 2048 bits, that a
manifest grants on at least one server is no longer accepted silently:

- `audit` reports every server that grants it as critical, so a scheduled `audit` that
  passed before now exits `2`.
- `apply` refuses those servers (exit `1`) and writes the rest of the fleet. A write that
  grants nothing and only removes keys still proceeds.
- `validate` exits `3`.
- A command that saves the manifest refuses a save that would **add** a weak key (exit `3`,
  nothing saved). Every other save goes through. `adopt` and `import` skip a weak key they
  find, with a warning.
- The manifest still loads. A weak key granted on no server is only a warning.

Fix it by replacing or removing the key: `sshepherd rotate USER --old KEY --new NEWKEY` or
`sshepherd revoke --key KEY`. Both always save, even while the manifest holds a weak key.
OpenSSH 9.8 and later build sshd without DSA by default, so a DSA key usually could not log in
on a current server anyway.
