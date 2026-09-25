#!/usr/bin/env bash
# Installs the release build for the current user: binary, desktop entry, icon.
set -euo pipefail

project_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
app_id="dev.nilltadios.CosmicAuthenticator"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
bin_dir="$HOME/.local/bin"

cargo build --release --manifest-path "$project_dir/Cargo.toml"

install -Dm755 "$project_dir/target/release/cosmic-authenticator" "$bin_dir/cosmic-authenticator"
install -Dm644 "$project_dir/resources/$app_id.svg" "$data_home/icons/hicolor/scalable/apps/$app_id.svg"
# Exec gets the absolute path, so the entry works even when ~/.local/bin is not on PATH.
sed "s|^Exec=.*|Exec=$bin_dir/cosmic-authenticator|" "$project_dir/resources/$app_id.desktop" \
    > "$data_home/applications/$app_id.desktop"
chmod 644 "$data_home/applications/$app_id.desktop"

update-desktop-database "$data_home/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$data_home/icons/hicolor" 2>/dev/null || true
echo "Installed $app_id"
