#!/usr/bin/env bash
# Runs a command while KWin places this app's windows on one screen, without
# taking focus from the window you are using. The KWin script is loaded only
# for the length of the command and nothing is saved to KWin's settings.
#
#   demo/on-screen.sh DP-2 ./target/release/cosmic-authenticator
#   demo/on-screen.sh --fullscreen DP-2 ./target/release/cosmic-authenticator
#   demo/on-screen.sh DP-2 demo/measure.sh 60
#
# Screen names come from `kscreen-doctor -o`. KDE Plasma 6 only.
set -euo pipefail

fullscreen=false
if [[ "$1" == --fullscreen ]]; then
    fullscreen=true
    shift
fi
target="$1"
shift
script_name="cosmic-authenticator-on-screen"
script_file="$(mktemp --suffix=.js)"
kwin() { qdbus-qt6 org.kde.KWin /Scripting "org.kde.kwin.Scripting.$1" "${@:2}"; }

sed -e "s/__TARGET__/$target/" -e "s/__FULLSCREEN__/$fullscreen/" "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/kwin-external-screen.js" >"$script_file"
cleanup() {
    kwin unloadScript "$script_name" >/dev/null 2>&1 || true
    rm -f "$script_file"
}
trap cleanup EXIT

kwin unloadScript "$script_name" >/dev/null 2>&1 || true
kwin loadScript "$script_file" "$script_name" >/dev/null
kwin start >/dev/null
"$@"
