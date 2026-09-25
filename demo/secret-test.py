# Checks that the app lock password does not sit in plain text anywhere the
# app controls: the running process's memory after unlocking, the data files,
# and the keyring entries. Runs off-screen in headless sway, with throwaway data
# and a test keyring name, using the preview build's test password.
#
#   uv run --no-project demo/secret-test.py
#
# Needs a preview build (cargo build --release --features preview), sway, and
# secret-tool. The app is started by this script, so reading its memory works
# with the default ptrace_scope=1 (a process may read its own children).
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
BINARY = PROJECT / "target/release/cosmic-authenticator"
PASSWORD = b"preview password"  # PREVIEW_PASSWORD in src/app.rs
SERVICE = "dev.nilltadios.CosmicAuthenticator.test"


UNREADABLE = []
GUARD_PAGES = []
VANISHED = []


def vm_flags(pid: int, span: str) -> str:
    """The kernel's VmFlags for one mapping, from /proc/pid/smaps."""
    inside = False
    for line in Path(f"/proc/{pid}/smaps").read_text().splitlines():
        if line.startswith(span):
            inside = True
        elif inside and line.startswith("VmFlags:"):
            return line.split(":", 1)[1].strip()
    return "?"


def read_memory(pid: int) -> bytes:
    """All readable, private memory of a process (heap, stacks, anonymous maps)."""
    chunks = []
    UNREADABLE.clear()
    GUARD_PAGES.clear()
    VANISHED.clear()
    with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for line in maps:
            fields = line.split()
            start, end = (int(x, 16) for x in fields[0].split("-"))
            path = fields[5] if len(fields) > 5 else ""
            if "r" not in fields[1] or (path and not path.startswith("[")):
                continue  # skip unreadable maps and mapped files (libraries, fonts)
            if path.startswith("[vvar"):
                continue  # the kernel's clock pages, never readable through /proc/pid/mem
            try:
                mem.seek(start)
                chunks.append(mem.read(end - start))
                continue
            except (OSError, ValueError, OverflowError):
                pass
            # Thread stacks carry guard pages (VmFlags "gu") that refuse reads;
            # read the rest page by page so the stacks are still searched.
            skipped = 0
            for page in range(start, end, 4096):
                try:
                    mem.seek(page)
                    chunks.append(mem.read(4096))
                except (OSError, ValueError, OverflowError):
                    skipped += 1
            GUARD_PAGES.append(skipped)
            if skipped == (end - start) // 4096:
                flags = vm_flags(pid, fields[0])
                if flags == "?":
                    VANISHED.append(fields[0])  # freed while the scan ran; not live memory
                else:
                    UNREADABLE.append(f"{fields[0]} {path or '(anonymous)'} flags: {flags}")
    return b"".join(chunks)


def keyring_value(user: str) -> bytes:
    result = subprocess.run(["secret-tool", "lookup", "service", SERVICE, "username", user], capture_output=True)
    return result.stdout


def main() -> int:
    work = Path(tempfile.mkdtemp())
    env = dict(os.environ)
    env.update(
        XDG_DATA_HOME=str(work / "data"),
        XDG_CACHE_HOME=str(work / "cache"),
        AUTHENTICATOR_KEYRING_SERVICE=SERVICE,
    )
    (work / "data").mkdir()
    subprocess.run(["secret-tool", "clear", "service", SERVICE], capture_output=True)
    subprocess.run([str(BINARY), "--import", str(PROJECT / "demo/demo-export.json")], env=env, check=True)

    conf = work / "sway.conf"
    conf.write_text(
        "output HEADLESS-1 resolution 1600x1000 scale 1\ndefault_border none\nxwayland disable\n"
        f"exec env | grep -E '^(WAYLAND_DISPLAY|SWAYSOCK)=' > {work}/sway.env\n"
    )
    sway_env = {k: v for k, v in env.items() if k not in ("WAYLAND_DISPLAY", "DISPLAY")}
    sway_env.update(WLR_BACKENDS="headless", WLR_LIBINPUT_NO_DEVICES="1")
    sway = subprocess.Popen(["sway", "--config", str(conf)], env=sway_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failures = 0
    try:
        for _ in range(50):
            if (work / "sway.env").exists() and (work / "sway.env").stat().st_size:
                break
            time.sleep(0.1)
        for line in (work / "sway.env").read_text().splitlines():
            key, _, value = line.partition("=")
            env[key] = value

        log = work / "app.log"

        def run(preview: str, seconds: float, inspect=None):
            # Full trace logging, so any message or value that gets logged is caught.
            with open(log, "ab") as log_file:
                app = subprocess.Popen([str(BINARY)], env={**env, "AUTHENTICATOR_PREVIEW": preview, "RUST_LOG": "trace"},
                                       stdout=log_file, stderr=log_file)
            time.sleep(seconds)
            result = inspect(app.pid) if inspect else None
            app.send_signal(signal.SIGTERM)
            app.wait(timeout=10)
            return result

        def check(description: str, ok: bool, detail: str = "") -> None:
            nonlocal failures
            print(f"  {'ok  ' if ok else 'FAIL'} {description}{f' ({detail})' if detail else ''}")
            failures += 0 if ok else 1

        print("turning the lock on:")
        run("lock-create", 10)
        # Controls: the scan must find what is certainly there, or a miss means nothing.
        print("control: lock screen with the password typed, not yet submitted:")
        typed = run("lock-typed", 6, read_memory)
        check("control: the typed password is found", PASSWORD in typed, f"searched {len(typed) // 2**20} MiB")
        print("unlocking, then reading the running app's memory:")
        memory = run("unlock", 10, read_memory)
        check("control: a decrypted issuer name is found", b"Sprintax" in memory)
        check("every memory region could be read", not UNREADABLE,
              "; ".join(UNREADABLE) or f"{sum(GUARD_PAGES)} guard pages skipped in {len(GUARD_PAGES)} thread stacks, "
              f"{len(VANISHED)} regions unmapped during the scan")
        hits = [m.start() for m in re.finditer(re.escape(PASSWORD), memory)]
        check("password absent from process memory after unlocking", not hits,
              f"{len(hits)} copies in {len(memory) // 2**20} MiB" if hits else f"searched {len(memory) // 2**20} MiB")

        logged = log.read_bytes()
        if logged.strip():
            check("password absent from the app's trace log", PASSWORD not in logged, f"{len(logged) // 1024} KiB of log")
        else:
            # Nothing to search: the app sets up no logger. Printing is covered
            # by the unit tests on Secret and Key, which never show their contents.
            print("  --   log check not applicable: the app wrote no log even with RUST_LOG=trace")

        files = [p for p in (work / "data").rglob("*") if p.is_file()]
        found = [str(p.relative_to(work)) for p in files if PASSWORD in p.read_bytes()]
        check("password absent from the data files", not found, ", ".join(found))
        for user in ("vault-key", "proton-session"):
            check(f"password absent from keyring entry {user}", PASSWORD not in keyring_value(user))
        check("lock.json holds no password field", b"password" not in (work / "data/cosmic-authenticator/lock.json").read_bytes())
    finally:
        sway.send_signal(signal.SIGTERM)
        sway.wait(timeout=10)
        subprocess.run(["secret-tool", "clear", "service", SERVICE], capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
    print("All checks passed" if not failures else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
