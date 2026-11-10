#!/usr/bin/env python3
"""Lay out a signed Flatpak repository for GitHub Pages; never overwrite a site.

Usage: publish.py REPO SITE BASE_URL GPG_KEY SOURCE_COMMIT
This only writes local files. It does not deploy or publish anything itself.
Adapted from Warehouse COSMIC's ci/publish.py.
"""
import base64
import datetime
import html
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse

APP = "dev.nilltadios.CosmicAuthenticator"
REMOTE = "cosmic-authenticator"
TITLE = "COSMIC Authenticator"
RUNTIME = "GNOME 51"

root = pathlib.Path(__file__).resolve().parents[1]
repo, site, base, key, commit = sys.argv[1:]
repo, site = pathlib.Path(repo), pathlib.Path(site)
base = base.rstrip("/") + "/"
parsed = urllib.parse.urlsplit(base)
if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
    raise SystemExit("BASE_URL must be an HTTPS directory URL without a query or fragment")
if site.exists():
    raise SystemExit("SITE already exists. Choose a new output directory.")
version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
ref = f"app/{APP}/x86_64/stable"
ostree_commit = subprocess.check_output(["ostree", f"--repo={repo}", "rev-parse", ref], text=True).strip()
# Refuse an unsigned input instead of advertising a key that does not sign it.
pub = subprocess.check_output(["gpg", "--batch", "--export", key])
if not pub:
    raise SystemExit("Signing public key not found")
# The key is published in every .flatpakrepo/.flatpakref; its user IDs must not carry an email address.
uids = [line.split(":")[9] for line in subprocess.run(
    ["gpg", "--batch", "--with-colons", "--show-keys"], input=pub, capture_output=True, check=True
).stdout.decode(errors="replace").splitlines() if line.startswith("uid:")]
if any("@" in uid for uid in uids):
    raise SystemExit(f"Signing key user ID contains an email address; remove it before publishing: {uids}")
with tempfile.TemporaryDirectory(prefix="authenticator-verify-") as keyring:
    os.chmod(keyring, 0o700)
    # OSTree reads an exported legacy keyring, not GnuPG's newer keybox format.
    (pathlib.Path(keyring) / "pubring.gpg").write_bytes(pub)
    verified = subprocess.run(["ostree", f"--repo={repo}", "show", f"--gpg-homedir={keyring}", ostree_commit],
                              env={**os.environ, "LC_ALL": "C"}, capture_output=True, text=True)
    if verified.returncode or "Good signature from" not in verified.stdout:
        raise SystemExit("Repository commit signature verification failed: " + verified.stdout + verified.stderr)
site.mkdir(parents=True)
shutil.copytree(repo, site / "repo")
(site / "repo/.lock").unlink(missing_ok=True)
gpg = base64.b64encode(pub).decode()
fingerprint = subprocess.check_output(["gpg", "--batch", "--with-colons", "--fingerprint", key],
                                      text=True).split("fpr:::::::::", 1)[1].split(":", 1)[0]
fingerprint = " ".join(fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4))
common = f"Url={base}repo/\nHomepage={base}\nIcon={base}icon.png\nGPGKey={gpg}\n"
remote_file = f"{REMOTE}.flatpakrepo"
(site / remote_file).write_text(f"[Flatpak Repo]\nTitle={TITLE}\nComment=Two-factor codes on Proton Authenticator's open-source core\n"
                                f"Description=Signed {TITLE} builds (not an official Proton app)\n" + common)
(site / f"{APP}.flatpakref").write_text(f"[Flatpak Ref]\nTitle={TITLE}\nName={APP}\nBranch=stable\nSuggestRemoteName={REMOTE}\n"
                                        "IsRuntime=false\nRuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo\n" + common)
shutil.copy2(root / "resources" / f"{APP}.svg", site / "icon.svg")
# Software stores render PNG icons more reliably than SVG.
shutil.copy2(root / "resources" / f"{APP}.png", site / "icon.png")
(site / ".nojekyll").touch()
published = datetime.datetime.now(datetime.timezone.utc)
state = {"app_id": APP, "version": version, "runtime": RUNTIME, "source_commit": commit, "ostree_commit": ostree_commit,
         "published_at": published.isoformat(), "base_url": base, "signing_key": fingerprint.replace(" ", "")}
(site / "state.json").write_text(json.dumps(state, indent=2) + "\n")
repo_name = os.environ.get("GITHUB_REPOSITORY", "nilltadios/cosmic-authenticator")
values = {
    "APP": APP, "REMOTE": REMOTE, "REPO_FILE": remote_file, "BASE": base, "VERSION": version, "RUNTIME": RUNTIME,
    "PUBLISHED": published.date().isoformat(), "COMMIT": commit, "COMMIT_SHORT": commit[:12],
    "OSTREE_SHORT": ostree_commit[:12], "FINGERPRINT": fingerprint,
    "REPO_URL": f"https://github.com/{repo_name}", "REPO_NAME": repo_name,
}
page = (root / "ci/site/index.html.in").read_text()
for name, value in values.items():
    page = page.replace(f"@{name}@", html.escape(value))
unfilled = sorted(set(re.findall(r"@[A-Z_]+@", page)))
if unfilled:
    raise SystemExit("Unfilled placeholders in index.html: " + ", ".join(unfilled))
(site / "index.html").write_text(page)
print(site)
