#!/usr/bin/env bash
# Builds flatpak/dev.nilltadios.CosmicAuthenticator.flatpak, a single-file bundle.
#
#   flatpak/build.sh
#   flatpak install --user flatpak/dev.nilltadios.CosmicAuthenticator.flatpak
#
# Needs flatpak-builder (or the org.flatpak.Builder app), org.gnome.Sdk 51,
# and the org.freedesktop.Sdk rust-stable extension for 26.08 (the base of
# GNOME 51). Crates are vendored into flatpak/vendor first (the one step that
# downloads), pinned by Cargo.lock, because the build sandbox has no network.
set -euo pipefail

app_id="dev.nilltadios.CosmicAuthenticator"
flatpak_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")"
project_dir="$(dirname "$flatpak_dir")"
cd "$flatpak_dir"

cargo vendor --locked --manifest-path "$project_dir/Cargo.toml" "$flatpak_dir/vendor" \
    | sed "s|$flatpak_dir/vendor|flatpak/vendor|" >"$flatpak_dir/cargo-config.toml"

# Some systems (CachyOS here) have flatpak-builder only as the Flathub app.
if command -v flatpak-builder >/dev/null; then
    builder=(flatpak-builder)
else
    builder=(flatpak run org.flatpak.Builder)
fi

# The full build compiles hundreds of crates. Uncapped, 16 parallel rustc jobs
# ran this 14 GB laptop out of memory (2026-09-25). Limit the jobs, and run the
# build in its own scope with a memory ceiling, so a runaway build is stopped
# instead of the desktop. Override with BUILD_JOBS and BUILD_MEMORY.
jobs="${BUILD_JOBS:-6}"
memory="${BUILD_MEMORY:-6G}"
systemd-run --user --scope --quiet -p MemoryMax="$memory" -p MemorySwapMax=2G \
    nice -n 10 "${builder[@]}" --jobs="$jobs" --force-clean --disable-rofiles-fuse \
    --state-dir="$flatpak_dir/.flatpak-builder" --repo="$flatpak_dir/repo" \
    "$flatpak_dir/build-dir" "$flatpak_dir/$app_id.yml"
flatpak build-bundle "$flatpak_dir/repo" "$flatpak_dir/$app_id.flatpak" "$app_id"
echo "Bundle: $flatpak_dir/$app_id.flatpak"
