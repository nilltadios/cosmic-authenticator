#!/usr/bin/env -S uv run
"""Regenerate resources/icons/CosmicAuthenticator from pinned COSMIC Icons."""
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMIT = "f1a282a0822aed1f0083dd2ab2e6c65bd5b401eb"
URL = "https://github.com/pop-os/cosmic-icons.git"
DEST = ROOT / "resources/icons/CosmicAuthenticator"

ICONS = [
    "dialog-warning-symbolic",
    "document-open-symbolic",
    "document-properties-symbolic",
    "edit-clear-symbolic",
    "edit-copy-symbolic",
    "edit-paste-symbolic",
    "edit-symbolic",
    "go-next-symbolic",
    "go-previous-symbolic",
    "image-red-eye-symbolic",
    "image-x-generic-symbolic",
    "list-add-symbolic",
    "list-remove-symbolic",
    "navbar-closed-symbolic",
    "navbar-open-symbolic",
    "object-select-symbolic",
    "open-menu-symbolic",
    "pan-down-symbolic",
    "pan-end-symbolic",
    "pan-up-symbolic",
    "preferences-system-symbolic",
    "system-lock-screen-symbolic",
    "system-search-symbolic",
    "user-trash-symbolic",
    "window-close-symbolic",
    "window-maximize-symbolic",
    "window-minimize-symbolic",
    "window-restore-symbolic",
]

if DEST.exists():
    raise SystemExit("Refusing to overwrite existing theme. Move it aside before regenerating.")

with tempfile.TemporaryDirectory(prefix="authenticator-icons-") as work:
    source = pathlib.Path(work) / "source"
    subprocess.run(["git", "clone", "--quiet", URL, str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "checkout", "--quiet", COMMIT], check=True)
    DEST.mkdir(parents=True)

    available = {}
    for tree in ("freedesktop", "extra"):
        base = source / tree / "scalable"
        if not base.exists():
            continue
        for svg in sorted(base.rglob("*.svg")):
            available.setdefault(svg.stem, (svg, svg.relative_to(base)))

    for name in ICONS:
        if name not in available:
            raise SystemExit(f"Missing icon in cosmic-icons@{COMMIT}: {name}")
        svg, rel = available[name]
        target = DEST / "scalable" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(svg.resolve(), target)

    # Alias used in src/ui_icons.rs (COSMIC Icons names it edit-symbolic).
    shutil.copy2(DEST / "scalable/actions/edit-symbolic.svg", DEST / "scalable/actions/document-edit-symbolic.svg")
    shutil.copy2(source / "LICENSE", DEST / "LICENSE")

    directories = sorted(str(p.relative_to(DEST)) for p in (DEST / "scalable").iterdir() if p.is_dir())
    index = (
        "[Icon Theme]\n"
        "Name=COSMIC Authenticator\n"
        "Comment=Bundled COSMIC symbolic icons for COSMIC Authenticator\n"
        "Inherits=breeze,Adwaita,hicolor\n"
        "Directories=" + ",".join(directories) + "\n"
    )
    for directory in directories:
        index += (
            f"\n[{directory}]\n"
            "Size=16\nMinSize=8\nMaxSize=512\nType=Scalable\n"
            f"Context={directory.split('/')[-1].title()}\n"
        )
    (DEST / "index.theme").write_text(index)
    (DEST / "SOURCE.txt").write_text(
        f"Cosmic Icons by System76\n{URL}\nCommit: {COMMIT}\n"
        "Icon assets: CC-BY-SA-4.0 (see LICENSE).\n"
        "Minimal scalable symbolic subset used by cosmic-authenticator and libcosmic.\n"
    )

print(DEST)
