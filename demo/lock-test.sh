#!/usr/bin/env bash
# End-to-end test of the app lock, off-screen: runs the app in headless sway
# through turning the lock on, the unlock screen, a wrong and a right password,
# and turning the lock off, and checks the files and keyring after each step.
# Screenshots go to the output folder.
#
#   demo/lock-test.sh [output-dir]        # default: demo/screenshots/lock
#
# Uses a throwaway data folder and a keyring name of its own
# (dev.nilltadios.CosmicAuthenticator.test), removed at the end, so the real
# vault key and Proton session are never touched. Needs sway, grim, secret-tool.
set -euo pipefail

project_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
out_dir="$(readlink -f "${1:-$project_dir/demo/screenshots/lock}")"
work_dir="$(mktemp -d)"
service="dev.nilltadios.CosmicAuthenticator.test"
mkdir -p "$out_dir" "$work_dir"/{data,config,cache}
ln -s "${XDG_CONFIG_HOME:-$HOME/.config}/cosmic" "$work_dir/config/cosmic"

cleanup() {
    [[ -n "${SWAYSOCK:-}" ]] && swaymsg exit >/dev/null 2>&1 || true
    secret-tool clear service "$service" 2>/dev/null || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

# Capped: an uncapped build next to another once ran the laptop out of memory.
systemd-run --user --scope --quiet -p MemoryMax=5G -p MemorySwapMax=2G nice -n 10 \
    cargo build --release -j 6 --features preview --manifest-path "$project_dir/Cargo.toml"
binary="$project_dir/target/release/cosmic-authenticator"
export XDG_DATA_HOME="$work_dir/data" XDG_CONFIG_HOME="$work_dir/config" XDG_CACHE_HOME="$work_dir/cache"
export AUTHENTICATOR_KEYRING_SERVICE="$service"
data="$work_dir/data/cosmic-authenticator"
secret-tool clear service "$service" 2>/dev/null || true
"$binary" --import "$project_dir/demo/demo-export.json"

cat >"$work_dir/sway.conf" <<EOF
output HEADLESS-1 resolution 1600x1000 scale 1
default_border none
xwayland disable
exec env | grep -E '^(WAYLAND_DISPLAY|SWAYSOCK)=' > $work_dir/sway.env
EOF
env -u WAYLAND_DISPLAY -u DISPLAY WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
    sway --config "$work_dir/sway.conf" >"$work_dir/sway.log" 2>&1 &
for _ in $(seq 50); do [[ -s "$work_dir/sway.env" ]] && break; sleep 0.1; done
set -a; source "$work_dir/sway.env"; set +a

failures=0
check() {  # check DESCRIPTION COMMAND...
    if "${@:2}"; then echo "  ok   $1"; else echo "  FAIL $1"; failures=$((failures + 1)); fi
}
has_vault_key() { secret-tool lookup service "$service" username vault-key >/dev/null 2>&1; }
failed_attempts() { sed -n 's/.*"failed_attempts":\([0-9]*\).*/\1/p' "$data/lock.json"; }
# Opens the app with a preview step, waits, takes a picture, closes it.
step() {  # step NAME PREVIEW SECONDS
    echo "$1:"
    AUTHENTICATOR_PREVIEW="$2" "$binary" >"$work_dir/$1.log" 2>&1 &
    local app=$!
    sleep "$3"
    grim "$out_dir/$1.png"
    kill "$app"
    wait "$app" 2>/dev/null || true
}

check "the keyring holds the vault key before the lock" has_vault_key

step 1-lock-on lock-create 10  # Argon2 with 512 MiB takes a few seconds
check "lock.json exists" test -f "$data/lock.json"
check "the keyring vault key is gone" bash -c "! secret-tool lookup service '$service' username vault-key >/dev/null 2>&1"
check "the CLI refuses to import while locked" bash -c "! '$binary' --import '$project_dir/demo/demo-export.json' 2>/dev/null"

step 2-locked "" 4
check "nothing unlocked the vault by itself" test -f "$data/lock.json"

step 3-wrong-password unlock-wrong 10
check "one failed attempt is counted" test "$(failed_attempts)" = 1

step 4-unlocked unlock 10
check "the right password resets the count" test "$(failed_attempts)" = 0

step 5-lock-off unlock-then-remove 16  # two Argon2 runs
check "lock.json is gone" test ! -f "$data/lock.json"
check "the keyring holds a vault key again" has_vault_key
check "the vault opens with the keyring key" bash -c "'$binary' --import '$project_dir/demo/demo-export.json' | grep -q 'Imported 0 codes'"

echo "Screenshots in $out_dir"
if ((failures > 0)); then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
