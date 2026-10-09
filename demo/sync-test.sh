#!/usr/bin/env bash
# End-to-end test of two-way sync against a fake Proton (demo/mock-proton.py),
# never a real account.
#
#   demo/sync-test.sh [screenshot dir]
#
# 1. Two devices sync through the server over real HTTP and encryption
#    (the ignored test two_devices_through_a_local_server).
# 2. The app itself, on a fresh server: it starts with two codes and a
#    session, then adds, edits, deletes and reorders codes through the preview
#    hook, while a "phone" adds and deletes codes. After each launch the
#    server's state is checked. Windows open on the screen in use; with a
#    screenshot dir, each launch is captured there (whole desktop: delete after).
#
# Everything uses the test keyring service and a scratch XDG_DATA_HOME.
set -euo pipefail

project_dir="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"
shots="${1:-}"
work="$(mktemp -d)"
port=$((20000 + RANDOM % 20000))
export AUTHENTICATOR_API_URL="http://127.0.0.1:$port"
export AUTHENTICATOR_KEYRING_SERVICE=dev.nilltadios.CosmicAuthenticator.test
export XDG_DATA_HOME="$work/data"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}"
binary="$project_dir/target/release/cosmic-authenticator"
server_pid=""

clear_keyring() {
    secret-tool clear service "$AUTHENTICATOR_KEYRING_SERVICE" 2>/dev/null || true
}
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
    clear_keyring
    rm -rf "$work"
}
trap cleanup EXIT

start_server() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null && wait "$server_pid" 2>/dev/null || true
    python3 "$project_dir/demo/mock-proton.py" "$port" &
    server_pid=$!
    for _ in $(seq 50); do curl -fs "$AUTHENTICATOR_API_URL/_state" >/dev/null && return; sleep 0.1; done
    echo "The fake server did not start" >&2
    exit 1
}

# Prints the server's entries with their revisions, in order; contents are encrypted.
state() {
    curl -fs "$AUTHENTICATOR_API_URL/_state" | python3 -c '
import json, sys
s = json.load(sys.stdin)
print(len(s["Keys"]), "key(s);", len(s["Entries"]), "entries:", " ".join(e["EntryID"] + "@r" + str(e["Revision"]) for e in s["Entries"]))'
}

capped() {
    systemd-run --user --scope --quiet -p MemoryMax=6G -p MemorySwapMax=2G nice -n 10 "$@"
}

test_bin() {
    local output
    output="$(capped cargo test --release --features preview --manifest-path "$project_dir/Cargo.toml" -q -- \
        --ignored --exact "$@" 2>&1)" || true
    grep -E "test result|panicked|assert|left|right" <<<"$output" || true
    grep -q "test result: ok. 1 passed" <<<"$output" || failed=1
}

# Runs the app with a preview step until `condition` holds (or 20 s pass).
launch() {
    local name="$1" step="$2" condition="$3"
    AUTHENTICATOR_PREVIEW="$step" "$binary" >"$work/$name.log" 2>&1 &
    local app=$!
    local ok=0
    for _ in $(seq 200); do
        if eval "$condition"; then ok=1; break; fi
        sleep 0.1
    done
    sleep 1.5 # let the follow-up sync and toast land
    if [[ -n "$shots" ]]; then
        cosmic-screenshot --interactive=false --modal=false --notify=false -s "$work" >/dev/null
        mv "$work"/Screenshot_*.png "$shots/sync-$name.png"
    fi
    kill "$app" 2>/dev/null; wait "$app" 2>/dev/null || true
    printf '%-14s %s  %s\n' "$name" "$([[ $ok == 1 ]] && echo PASS || echo FAIL)" "$(state)"
    [[ $ok == 1 ]] || failed=1
}

entries() { curl -fs "$AUTHENTICATOR_API_URL/_state" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["Entries"]))'; }
revisions() { curl -fs "$AUTHENTICATOR_API_URL/_state" | python3 -c 'import json,sys; print(" ".join(str(e["Revision"]) for e in json.load(sys.stdin)["Entries"]))'; }
order() { curl -fs "$AUTHENTICATOR_API_URL/_state" | python3 -c 'import json,sys; print(" ".join(e["EntryID"] for e in json.load(sys.stdin)["Entries"]))'; }
requests() { curl -fs "$AUTHENTICATOR_API_URL/_state" | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)["Requests"]))'; }

[[ -n "$shots" ]] && mkdir -p "$shots"
clear_keyring
failed=0

echo "== Building (preview feature)"
capped cargo build --release --features preview --manifest-path "$project_dir/Cargo.toml" -q

echo "== Two devices through the fake server"
start_server
test_bin proton::sync::tests::two_devices_through_a_local_server
echo "server: $(state)"

echo "== The app"
start_server
test_bin proton::sync::tests::seed_app_device >/dev/null
launch startup "" '[[ $(entries) == 2 ]]'
launch add sync-add '[[ $(entries) == 3 ]]'
launch edit sync-edit '[[ $(revisions) == *2* ]]'
launch delete sync-delete '[[ $(entries) == 2 ]]'
before="$(order)"
launch reorder sync-reorder '[[ $(order) != "$before" ]]'
test_bin proton::sync::tests::phone_changes_codes >/dev/null
launch phone-added "" '[[ -f "$work/data/cosmic-authenticator/sync.json" ]] && grep -o remote_id "$work/data/cosmic-authenticator/sync.json" | wc -l | grep -qx 3'
AUTHENTICATOR_TEST_DELETE=Phone test_bin proton::sync::tests::phone_changes_codes >/dev/null
launch phone-deleted "" 'grep -o remote_id "$work/data/cosmic-authenticator/sync.json" | wc -l | grep -qx 2'
launch sign-out sync-off 'requests | grep -q "DELETE core/v4/auth"'

echo "== Requests the app made"
requests | sort | uniq -c
exit "$failed"
