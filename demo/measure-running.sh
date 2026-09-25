#!/usr/bin/env bash
# Measures the copy of the app that is already running (usually the installed
# Flatpak), without starting, restarting or closing anything. Sums CPU time and
# PSS memory over its whole process tree, and GPU time from the DRM fdinfo.
# Whatever the user does in the app during the run counts too.
#
#   demo/measure-running.sh [seconds]      # default: 60
set -euo pipefail

seconds="${1:-60}"
app_id="dev.nilltadios.CosmicAuthenticator"

# The Flatpak instance's outer process; otherwise a native copy of the app.
root="$(flatpak ps --columns=pid,application 2>/dev/null | awk -v id="$app_id" '$2 == id {print $1; exit}')"
kind="Flatpak"
if [[ -z "$root" ]]; then
    root="$(pgrep -x cosmic-authenti | head -1 || true)"
    kind="native"
fi
if [[ -z "$root" ]]; then
    echo "Authenticator is not running." >&2
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
# GPU time in nanoseconds, per GPU (PCI address), from amdgpu's per-client fdinfo.
gpu_ns() {
    local pid fd
    for pid in $(tree); do
        for fd in /proc/"$pid"/fdinfo/*; do
            awk '/^drm-client-id:/ {c=$2} /^drm-pdev:/ {d=$2} /^drm-engine-gfx:/ {g=$2}
                 END {if (d != "") print c, d, g + 0}' "$fd" 2>/dev/null
        done
    done | sort -u | awk '{sum[$2] += $3} END {for (d in sum) print d, sum[d]}'
}

echo "Measuring the running $kind copy (root PID $root, $(tree | wc -l) processes) for $seconds s..."
start_ticks=$(ticks)
start_gpu="$(gpu_ns)"
sleep "$seconds"
end_ticks=$(ticks)
end_gpu="$(gpu_ns)"
memory=$(pss_kb)

awk -v t=$((end_ticks - start_ticks)) -v hz="$(getconf CLK_TCK)" -v s="$seconds" -v kb="$memory" \
    'BEGIN { printf "CPU: %.1f%% of one core\nMemory (PSS, all processes): %.0f MB\n", 100 * t / hz / s, kb / 1024 }'
join <(echo "$start_gpu" | sort) <(echo "$end_gpu" | sort) 2>/dev/null |
    awk -v s="$seconds" '{printf "GPU %s: %.2f%% busy (%.1f ms of graphics time)\n", $1, 100 * ($3 - $2) / (s * 1e9), ($3 - $2) / 1e6}'
