#!/usr/bin/env bash
# Writes the OpenPGP test fixtures used by src/proton/keys.rs, made with GnuPG
# (a different implementation from the rPGP the app uses), shaped like a Proton
# account: an Ed25519 primary key with a Curve25519 encryption subkey, locked
# with a key password, and an Authenticator key (32 random bytes) encrypted to
# it and signed by it. The keys are throwaway and belong to no account.
#
#   tests/fixtures/make-pgp-fixtures.sh
set -euo pipefail

out="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
home="$(mktemp -d)"
trap 'gpgconf --homedir "$home" --kill all 2>/dev/null || true; rm -rf "$home"' EXIT
password="test key password"
gpg=(gpg --homedir "$home" --batch --yes --pinentry-mode loopback --passphrase "$password")

"${gpg[@]}" --quick-generate-key "Fixture <fixture@example.invalid>" ed25519 sign never
fingerprint="$("${gpg[@]}" --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')"
"${gpg[@]}" --quick-add-key "$fingerprint" cv25519 encr never

"${gpg[@]}" --armor --export-secret-keys "$fingerprint" >"$out/user-key.asc"
printf '%s' "$password" >"$out/user-key.password"

head -c 32 /dev/urandom >"$out/authenticator-key.bin"
"${gpg[@]}" --recipient "$fingerprint" --local-user "$fingerprint" --sign --encrypt \
    --output "$out/authenticator-key.pgp" "$out/authenticator-key.bin"

# The same key, signed by an unrelated key: must be rejected.
"${gpg[@]}" --quick-generate-key "Stranger <stranger@example.invalid>" ed25519 sign never
stranger="$("${gpg[@]}" --list-keys --with-colons stranger@example.invalid | awk -F: '/^fpr/ {print $10; exit}')"
"${gpg[@]}" --recipient "$fingerprint" --local-user "$stranger" --sign --encrypt \
    --output "$out/authenticator-key-wrong-signer.pgp" "$out/authenticator-key.bin"
echo "Fixtures written to $out"
