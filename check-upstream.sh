#!/usr/bin/env bash
# Compares what this app is built on with the newest upstream versions:
#
#   ./check-upstream.sh
#
# - The official Proton Authenticator: the version in Proton's own update feed
#   (the one the official app checks) against APP_VERSION, which this app sends
#   to Proton. When Proton ships a new version, port its changes from
#   ../Proton-WebClients/applications/authenticator before raising APP_VERSION;
#   Proton eventually refuses old versions (error 5003).
# - Proton's Rust core and libcosmic: the commits pinned in Cargo.lock against
#   each repository's HEAD.
#
# Exits 1 when the official app has a version this app does not match yet.
set -euo pipefail

project_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
cd "$project_dir"
status=0

ours="$(sed -n 's/^pub const APP_VERSION: &str = "linux-authenticator@\(.*\)";/\1/p' src/proton/api.rs)"
feed="https://proton.me/download/authenticator/linux/latest.json"
if official="$(curl -fsS --max-time 20 "$feed" | sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' | head -1)" \
    && [[ -n "$official" ]]; then
    if [[ "$official" == "$ours" ]]; then
        echo "Official app:  $official, matches APP_VERSION"
    else
        echo "Official app:  $official, but APP_VERSION is $ours. Port the changes, then raise"
        echo "               APP_VERSION and USER_AGENT in src/proton/api.rs and docs/proton-sync.md."
        status=1
    fi
else
    echo "Official app:  could not read $feed"
fi

# Prints the pinned commit and upstream HEAD of a git dependency in Cargo.lock.
check_pin() {
    local label="$1" crate="$2" url="$3" pinned head
    pinned="$(grep -A2 "^name = \"$crate\"$" Cargo.lock | sed -n 's/^source = "git+.*#\([0-9a-f]*\)"/\1/p' | head -1)"
    if ! head="$(git ls-remote "$url" HEAD | cut -f1)" || [[ -z "$head" ]]; then
        echo "$label could not reach $url"
    elif [[ "$pinned" == "$head" ]]; then
        echo "$label ${pinned:0:7}, up to date"
    else
        echo "$label ${pinned:0:7} pinned, upstream at ${head:0:7}. Update with: cargo update -p $crate"
    fi
}
check_pin "Proton core:  " proton-authenticator https://github.com/protonpass/proton-pass-common.git
check_pin "libcosmic:    " libcosmic https://github.com/pop-os/libcosmic.git

# The reference checkout, if present, shows which upstream commits touch the core.
core="vendor-ref/proton-pass-common"
pinned="$(grep -A2 '^name = "proton-authenticator"$' Cargo.lock | sed -n 's/^source = "git+.*#\([0-9a-f]*\)"/\1/p' | head -1)"
if [[ -d "$core/.git" ]] && git -C "$core" fetch --quiet origin 2>/dev/null; then
    changes="$(git -C "$core" log --oneline "$pinned..origin/HEAD" -- proton-authenticator 2>/dev/null || true)"
    if [[ -n "$changes" ]]; then
        echo "               Commits touching proton-authenticator since the pin:"
        sed 's/^/                 /' <<<"$changes"
    fi
fi

exit "$status"
