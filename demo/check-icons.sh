#!/usr/bin/env bash
# Verifies that the built binary (native and/or Freedesktop 26.08 Flatpak)
# resolves every bundled libcosmic widget icon with NO system icon themes
# available (XDG_DATA_DIRS=/nonexistent, empty disposable HOME/XDG_DATA_HOME).
#
#   demo/check-icons.sh             # check both native (if built) and Flatpak (if built)
#   demo/check-icons.sh --native    # check target/release/cosmic-authenticator
#   demo/check-icons.sh --flatpak   # check flatpak/build-dir inside Freedesktop 26.08
#
# Exits non-zero if any icon is missing or falls outside the app's private theme.
set -euo pipefail

project_dir="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"
mode="${1:-all}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

check_json() {
    local label="$1" out="$2"
    python3 -c '
import json, sys
label, raw = sys.argv[1], sys.argv[2]
data = json.loads(raw)
missing = data.get("icons_missing", ["<unparsed>"])
theme = data.get("icon_theme")
checked = data.get("icons_checked", 0)
if theme != "dev.nilltadios.CosmicAuthenticator" or missing or checked < 20:
    print(f"FAIL [{label}]: theme={theme!r} checked={checked} missing={missing}", file=sys.stderr)
    sys.exit(1)
print(f"PASS [{label}]: {checked} libcosmic widget icons resolved from bundled theme ({theme}); missing={missing}")
' "$label" "$out"
}

checked_any=0

if [[ "$mode" == "all" || "$mode" == "--native" ]]; then
    bin="$project_dir/target/release/cosmic-authenticator"
    if [[ -x "$bin" ]]; then
        checked_any=1
        mkdir -p "$work/native-home" "$work/native-data"
        out="$(env -i PATH="$PATH" HOME="$work/native-home" XDG_DATA_HOME="$work/native-data" \
            XDG_CONFIG_HOME="$work/native-home/.config" XDG_DATA_DIRS=/nonexistent \
            "$bin" --check-icons)"
        check_json "native" "$out"
    elif [[ "$mode" == "--native" ]]; then
        echo "FAIL: native binary not found at $bin" >&2
        exit 1
    fi
fi

if [[ "$mode" == "all" || "$mode" == "--flatpak" ]]; then
    build_dir="$project_dir/flatpak/build-dir"
    if [[ -d "$build_dir/files/bin" ]]; then
        checked_any=1
        mkdir -p "$work/fp-home" "$work/fp-data"
        out="$(flatpak build --filesystem="$work" "$build_dir" sh -c '
            HOME="$1/fp-home" XDG_DATA_HOME="$1/fp-data" XDG_CONFIG_HOME="$1/fp-home/.config" \
                XDG_DATA_DIRS=/nonexistent exec cosmic-authenticator --check-icons
        ' _ "$work")"
        check_json "flatpak" "$out"
    elif [[ "$mode" == "--flatpak" ]]; then
        echo "FAIL: Flatpak build-dir not found at $build_dir" >&2
        exit 1
    fi
fi

if [[ "$checked_any" == 0 ]]; then
    echo "FAIL: neither native binary nor flatpak/build-dir found to check" >&2
    exit 1
fi
