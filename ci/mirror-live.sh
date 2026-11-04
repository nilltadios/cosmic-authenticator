#!/usr/bin/env bash
# Copy the published, signed Flatpak repository so a site-only release can
# redeploy the page without rebuilding the app.
#
# Usage: mirror-live.sh BASE_URL GPG_KEY REPO_DIR
# Mirrors BASE_URL/repo/ into REPO_DIR (which must not exist), checks that the
# app ref is the commit BASE_URL/state.json names and is signed by GPG_KEY, and
# refuses if anything that goes into the app changed since state.json's
# source_commit. Prints that source commit. Signs nothing and publishes nothing.
set -euo pipefail

base=${1%/}/ key=$2 repo=$3
app=dev.nilltadios.CosmicAuthenticator
ref=app/$app/x86_64/stable
[[ ! -e $repo ]] || { echo "$repo already exists" >&2; exit 1; }

state=$(curl -fsSL "${base}state.json")
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$state" "$1"; }
source_commit=$(field source_commit)
ostree_commit=$(field ostree_commit)

# Only the page, CI and docs may differ from the build that is live.
changed=$(git diff --name-only "$source_commit" HEAD)
app_inputs=$(grep -v -E '^(ci/|\.github/|[^/]*\.md$|LICENSE$)' <<<"$changed" || true)
if [[ -n $app_inputs ]]; then
    echo "App files changed since the live build ($source_commit); a full release is needed:" >&2
    echo "$app_inputs" >&2
    exit 1
fi

keyring=$(mktemp -d)
trap 'rm -rf "$keyring"' EXIT
gpg --batch --export "$key" > "$keyring/key.gpg"
[[ -s $keyring/key.gpg ]] || { echo "signing key $key not found" >&2; exit 1; }
ostree --repo="$repo" init --mode=archive-z2
ostree --repo="$repo" remote add --gpg-import="$keyring/key.gpg" live "${base}repo/" >&2
ostree --repo="$repo" pull --mirror live >&2
ostree --repo="$repo" remote delete live
got=$(ostree --repo="$repo" rev-parse "$ref")
[[ $got == "$ostree_commit" ]] || { echo "live $ref is $got, state.json says $ostree_commit" >&2; exit 1; }
echo "$source_commit"
