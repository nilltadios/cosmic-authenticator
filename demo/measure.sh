#!/usr/bin/env bash
# Measures an app's idle CPU use and memory on the current desktop session.
# The window opens on your screen for the length of the run; leave it alone.
# CPU and memory are summed over the whole process tree, which matters for
# Flatpak and WebKit apps (bwrap, web processes). Memory is PSS: shared pages
# are split between the processes that share them.
#
#   demo/measure.sh [seconds]              this app's release build
#   demo/measure.sh [seconds] --flatpak    this app's Flatpak, installed from flatpak/build.sh
#   demo/measure.sh [seconds] command ...  any other app, e.g. flatpak run <app-id>
#
# This app runs with the 11 demo codes, so the release build and the Flatpak
# are measured on the same vault. Not counted: the Flatpak D-Bus proxy, which
# Flatpak starts outside the app's process tree.
set -euo pipefail

seconds="${1:-60}"
shift || true
project_dir="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
work_dir="$(mktemp -d)"
app_id="dev.nilltadios.CosmicAuthenticator"
flatpak_vault="$HOME/.var/app/$app_id/data/cosmic-authenticator/vault.json"
placed_vault=""
cleanup() {
    [[ -n "$placed_vault" ]] && rm -f "$placed_vault"
    rm -rf "$work_dir"
}
trap cleanup EXIT

if (($# == 0)) || [[ "$1" == --flatpak ]]; then
    # Capped: an uncapped build next to another once ran the laptop out of memory.
    systemd-run --user --scope --quiet -p MemoryMax=5G -p MemorySwapMax=2G nice -n 10 \
        cargo build --release -j 6 --manifest-path "$project_dir/Cargo.toml"
    # MEASURE_BINARY picks another build of this app, e.g. the GPU renderer's
    # target/wgpu/release/cosmic-authenticator (cargo build --features wgpu --target-dir target/wgpu).
    binary="${MEASURE_BINARY:-$project_dir/target/release/cosmic-authenticator}"
    mkdir -p "$work_dir"/{data,cache}
    # A keyring name of its own, so no real key is read, replaced or deleted.
    export AUTHENTICATOR_KEYRING_SERVICE="dev.nilltadios.CosmicAuthenticator.test"
    XDG_DATA_HOME="$work_dir/data" "$binary" --import "$project_dir/demo/demo-export.json" >/dev/null
    if (($# == 0)); then
        # Throwaway vault and logo cache; the COSMIC theme and settings stay yours.
        set -- env XDG_DATA_HOME="$work_dir/data" XDG_CACHE_HOME="$work_dir/cache" "$binary"
    else
        # Flatpak always sets XDG_DATA_HOME to the app's own folder, so the demo
        # vault is copied there for the run and removed afterwards. A vault
        # already there would be real codes, so the script stops instead.
        if [[ -e "$flatpak_vault" ]]; then
            echo "The Flatpak already has a vault at $flatpak_vault; not measuring over it." >&2
            exit 1
        fi
        mkdir -p "$(dirname "$flatpak_vault")"
        placed_vault="$flatpak_vault"
        cp "$work_dir/data/cosmic-authenticator/vault.json" "$flatpak_vault"
        set -- flatpak run --env=AUTHENTICATOR_KEYRING_SERVICE="$AUTHENTICATOR_KEYRING_SERVICE" "$app_id"
    fi
fi

"$@" >"$work_dir/app.log" 2>&1 &
root=$!
sleep 15  # startup, unlocking and logo downloads are not idle time
if ! kill -0 "$root" 2>/dev/null; then
    echo "The app exited during startup:" >&2
    cat "$work_dir/app.log" >&2
    exit 1
fi

tree() {  # the root process and all its descendants
    local pids=("$root") i=0
    while ((i < ${#pids[@]})); do
        mapfile -t -O "${#pids[@]}" pids < <(ps -o pid= --ppid "${pids[i]}" | tr -d ' ')
        ((i += 1))
    done
    printf '%s\n' "${pids[@]}"
}
# utime + stime of every process in the tree, in clock ticks. The command name
# in field 2 may contain spaces, so fields are counted from after its ')'.
ticks() {
    local total=0 pid
    for pid in $(tree); do
        [[ -r /proc/$pid/stat ]] || continue
        total=$((total + $(sed 's/.*) //' "/proc/$pid/stat" | awk '{print $12 + $13}')))
    done
    echo "$total"
}
pss_kb() {
    local total=0 pid
    for pid in $(tree); do
        [[ -r /proc/$pid/smaps_rollup ]] || continue
        total=$((total + $(awk '/^Pss:/ {print $2}' "/proc/$pid/smaps_rollup")))
    done
    echo "$total"
}

start=$(ticks)
sleep "$seconds"
end=$(ticks)
memory=$(pss_kb)
processes=$(tree | wc -l)
for pid in $(tree | tac); do kill "$pid" 2>/dev/null || true; done

awk -v t=$((end - start)) -v hz="$(getconf CLK_TCK)" -v s="$seconds" -v kb="$memory" -v n="$processes" \
    'BEGIN { printf "Idle over %d s, %d processes: CPU %.1f%% of one core, memory (PSS) %.0f MB\n", s, n, 100 * t / hz / s, kb / 1024 }'
