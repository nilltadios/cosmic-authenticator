#!/usr/bin/env bash
# Releases a new version to the Flatpak installed on this machine:
#
#   flatpak/release.sh 0.3.0
#
# Raises the version (Cargo.toml, login/Cargo.toml, Cargo.lock, metainfo),
# runs the tests, builds with flatpak/build.sh, commits the version change, and
# updates the installed app from the local repository flatpak/repo (the
# `cosmicauthenticator` remote, added here if missing). The vault, app lock and
# Proton session are left as they are.
#
# The Flatpak builds the working tree, so it must be clean: the build then
# matches the release commit.
set -euo pipefail

app_id="dev.nilltadios.CosmicAuthenticator"
remote="cosmicauthenticator"
flatpak_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")"
project_dir="$(dirname "$flatpak_dir")"
cd "$project_dir"

version="${1:-}"
current="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: flatpak/release.sh VERSION   (current: $current)" >&2
    exit 2
fi
if [[ "$version" == "$current" ]]; then
    echo "Version $version is already the current version." >&2
    exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Commit or stash your changes first; the Flatpak builds the working tree." >&2
    exit 1
fi

trap 'echo "Release stopped. Undo the version change with: git checkout -- ." >&2' ERR

# The version line is the first one in each [package] table.
for manifest in Cargo.toml login/Cargo.toml; do
    sed -i "0,/^version = \".*\"/s//version = \"$version\"/" "$manifest"
done
cargo update --offline --workspace --quiet
sed -i "s|<releases>|<releases>\n    <release version=\"$version\" date=\"$(date +%F)\"/>|" \
    "resources/$app_id.metainfo.xml"

# Same limits as build.sh, so the tests cannot run the laptop out of memory.
CARGO_BUILD_JOBS="${BUILD_JOBS:-6}" systemd-run --user --scope --quiet \
    -p MemoryMax="${BUILD_MEMORY:-6G}" -p MemorySwapMax=2G nice -n 10 cargo test --release
"$flatpak_dir/build.sh"

# Git may have no identity set on this machine; use the project's author then.
identity=()
if ! git config user.name >/dev/null; then
    # Not `git log --reverse | head -1`: head closes the pipe early, git dies of
    # SIGPIPE, and pipefail stops the release after the build (2026-10-23).
    author="$(git log -1 --format='%an%x09%ae' "$(git rev-list --max-parents=0 HEAD)")"
    identity=(-c "user.name=${author%%$'\t'*}" -c "user.email=${author##*$'\t'}")
fi
git "${identity[@]}" commit --quiet -am "Release $version"
trap - ERR

if ! flatpak remotes --user --columns=name | grep -qx "$remote"; then
    flatpak remote-add --user --no-gpg-verify "$remote" "file://$flatpak_dir/repo"
fi
origin="$(flatpak info --user --show-origin "$app_id" 2>/dev/null || true)"
if [[ "$origin" == "$remote" ]]; then
    flatpak update --user --noninteractive "$app_id"
    echo "Released $version and updated the installed app."
else
    echo "Released $version. The installed app comes from '${origin:-nowhere}', not '$remote', so"
    echo "flatpak update cannot reach it. Switch it once (your data is kept):"
    echo "  flatpak install --user --reinstall $remote $app_id"
fi
