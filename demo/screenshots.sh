#!/usr/bin/env bash
# Screenshots every view of the app with the demo codes. The app runs inside a
# headless sway session, so nothing appears on the desktop or takes focus, and
# the pictures come from grim. Needs sway and grim; the first run stores the
# app's vault key in the keyring, as the app itself does.
#
#   demo/screenshots.sh [output-dir]      # default: demo/screenshots
#
# The vault, settings and logo cache go to a throwaway folder. The COSMIC
# theme is still read from ~/.config/cosmic, so the pictures use your accent
# colour and light or dark mode.
set -euo pipefail

project_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
out_dir="$(readlink -f "${1:-$project_dir/demo/screenshots}")"
work_dir="$(mktemp -d)"
mkdir -p "$out_dir" "$work_dir"/{data,config,cache}
ln -s "${XDG_CONFIG_HOME:-$HOME/.config}/cosmic" "$work_dir/config/cosmic"

cleanup() {
    [[ -n "${SWAYSOCK:-}" ]] && swaymsg exit >/dev/null 2>&1 || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

# Capped: an uncapped build next to another once ran the laptop out of memory.
systemd-run --user --scope --quiet -p MemoryMax=5G -p MemorySwapMax=2G nice -n 10 \
    cargo build --release -j 6 --features preview --manifest-path "$project_dir/Cargo.toml"
binary="$project_dir/target/release/cosmic-authenticator"
export XDG_DATA_HOME="$work_dir/data" XDG_CONFIG_HOME="$work_dir/config" XDG_CACHE_HOME="$work_dir/cache"
# A keyring name of its own, so no real key is read, replaced or deleted.
export AUTHENTICATOR_KEYRING_SERVICE="dev.nilltadios.CosmicAuthenticator.test"
"$binary" --import "$project_dir/demo/demo-export.json"

# A 1600x1000 headless output; sway writes its socket names to a file on start.
cat >"$work_dir/sway.conf" <<EOF
output HEADLESS-1 resolution 1600x1000 scale 1
default_border none
# No X server, so apps can only show up through Wayland.
xwayland disable
exec env | grep -E '^(WAYLAND_DISPLAY|SWAYSOCK)=' > $work_dir/sway.env
EOF
env -u WAYLAND_DISPLAY -u DISPLAY WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
    sway --config "$work_dir/sway.conf" >"$work_dir/sway.log" 2>&1 &
for _ in $(seq 50); do [[ -s "$work_dir/sway.env" ]] && break; sleep 0.1; done
set -a; source "$work_dir/sway.env"; set +a

# Headless sway has no pointer device, so views are opened through the app's
# preview hook rather than clicks.
shoot() {  # shoot NAME PREVIEW
    local name="$1" preview="$2"
    AUTHENTICATOR_PREVIEW="$preview" "$binary" >"$work_dir/$name.log" 2>&1 &
    local app=$!
    sleep 4  # window opens, logos load, the grid finishes its slot animation
    grim "$out_dir/$name.png"
    kill "$app"
    wait "$app" 2>/dev/null || true
}

shoot grid ""
for view in add-menu add add-error edit settings delete export search; do
    shoot "$view" "$view"
done
shoot hidden hidden  # saves the hide-codes setting, so it runs last
echo "Screenshots in $out_dir"
