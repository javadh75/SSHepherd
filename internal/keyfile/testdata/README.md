# keyfile test fixtures

Throwaway keys produced by the real `ssh-keygen`, used only as parser and
interop fixtures and as fuzz seeds. They authorize nothing anywhere;
`.gitleaks.toml` allowlists this directory (and only it). Regenerate with:

```sh
cd internal/keyfile/testdata
rm -f throwaway_*
ssh-keygen -q -t ed25519 -N '' -C throwaway -f throwaway_ed25519
ssh-keygen -q -t ed25519 -N 'throwaway-fixture' -a 16 -C throwaway -f throwaway_ed25519_enc
ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -C throwaway -f throwaway_rsa_pem
ssh-keygen -q -t rsa -b 2048 -m PEM -N 'throwaway-fixture' -C throwaway -f throwaway_rsa_pem_enc
```

`throwaway.ppk` is a hand-written PuTTY header (not a usable key): only its
`PuTTY-User-Key-File-` prefix matters to the classifier.
