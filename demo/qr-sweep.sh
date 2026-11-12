#!/bin/sh
# Checks that the app's QR reader reads 48 small, smoothed QR codes made by
# demo/make-small-qr.py (see there). Pass: "test result: ok. 1 passed".
# Optional: QR_IMAGE=/path/to/screenshot.png also checks a real image
# (only pass/fail is printed, never its content).
set -eu
cd "$(dirname "$0")/.."
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
uv run --no-project --with "qrcode[pil]" demo/make-small-qr.py --sweep "$dir"
if [ -n "${QR_IMAGE:-}" ]; then cp "$QR_IMAGE" "$dir/real-image.png"; fi
QR_DIR="$dir" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}" \
    systemd-run --user --scope -q -p MemoryMax=6G -p MemorySwapMax=2G nice -n 10 \
    cargo test --release --bin cosmic-authenticator -- --ignored reads_every_qr_code_in_qr_dir --nocapture
