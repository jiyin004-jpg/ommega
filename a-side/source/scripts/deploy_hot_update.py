#!/usr/bin/env python3
"""
Build, deploy, and hot-restart ommega artifacts.

The script never reboots the device. It updates /data/adb/ommega/keymint and
/data/adb/ommega/ommega-inject, then requests the module daemons to restart through the
restart marker file path. With --full, it builds the full module package through
build.py and installs it with ksud module install.

--restart defaults to `auto`: the target is derived from what actually changed, because
restarting keystore2 costs more than it looks. The payload inside it is the only place
that holds the framework's unlock material, so replacing it makes the shadow answer
LOCKED to every auth-bound key init until the user unlocks the device again (see
ommega-injector/src/hook/rewrite/replay). A keymint-only change therefore restarts only
keymint, and a no-op deploy does not restart anything.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_ROOT = REPO_ROOT / "target"
DEFAULT_PLATFORM = 24
DEFAULT_ABI = "arm64-v8a"
DEFAULT_PROFILE = "debug"
DEFAULT_STAGING_DIR = "/data/local/tmp"
DEFAULT_WAIT_SECONDS = 15

ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

RESTART_TARGETS = {
    "all": "restart.all",
    "keymint": "restart.keymint",
    "injector": "restart.injector",
}

AUTO_RESTART = "auto"

REMOTE_DIR = "/data/adb/ommega"

ANSI_WHITE = "\033[37m"
ANSI_RESET = "\033[0m"


def print_status(message: str, *, file=None) -> None:
    print(f"{ANSI_RESET}{ANSI_WHITE}{message}{ANSI_RESET}", file=file)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture_output: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    if not quiet:
        print_status(f"+ {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def adb(
    serial: str | None,
    *args: str,
    capture_output: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    return run(cmd, capture_output=capture_output, quiet=quiet)


def adb_shell_root(
    serial: str | None,
    command: str,
    *,
    capture_output: bool = False,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    return adb(
        serial,
        "shell",
        f"su -c {quote(command)}",
        capture_output=capture_output,
        quiet=quiet,
    )


def quote(value: str) -> str:
    return shlex.quote(value)


def target_dir_for(abi: str, release: bool) -> Path:
    profile = "release" if release else DEFAULT_PROFILE
    return TARGET_ROOT / ABI_TO_TARGET[abi] / profile


def default_keymint_path(abi: str, release: bool) -> Path:
    return target_dir_for(abi, release) / "keymint"


def default_injector_path(abi: str, release: bool) -> Path:
    return target_dir_for(abi, release) / "ommega-inject"


def build_binaries(abi: str, platform: int, release: bool) -> None:
    _ = platform
    target = ABI_TO_TARGET[abi]
    keymint_cmd = [
        "cargo",
        "build",
        "--target",
        target,
        "--bin",
        "keymint",
    ]
    injector_cmd = [
        "cargo",
        "build",
        "--target",
        target,
        "-p",
        "ommega-injector",
        "--bin",
        "ommega-inject",
    ]
    if release:
        keymint_cmd.append("--release")
        injector_cmd.append("--release")
    run(keymint_cmd)
    run(injector_cmd)


def latest_full_package(abi: str, release: bool) -> Path:
    build_type = "release" if release else DEFAULT_PROFILE
    candidates = list(TARGET_ROOT.glob(f"ommega-a-{build_type}-{abi}-*.zip"))
    if not candidates:
        raise FileNotFoundError(f"full package not found for {build_type} {abi}")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def build_full_package(abi: str, platform: int, release: bool) -> Path:
    cmd = [sys.executable, "build.py", "--abi", abi, "--platform", str(platform)]
    if release:
        cmd.append("--release")
    run(cmd)
    package = latest_full_package(abi, release)
    print_status(f"Full package: {package}")
    return package


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a file: {path}")


def remote_path(base_dir: str, name: str) -> str:
    return f"{base_dir.rstrip('/')}/{name}"


def deploy_binaries(
    serial: str | None,
    keymint: Path,
    injector: Path,
    staging_dir: str,
    keep_staging: bool,
) -> dict[str, str]:
    local_shas = {
        "keymint": sha256sum(keymint),
        "ommega-inject": sha256sum(injector),
    }
    print_status(f"Local keymint:  {keymint}")
    print_status(f"Local ommega-inject: {injector}")
    print_status(f"Local keymint SHA-256: {local_shas['keymint']}")
    print_status(f"Local inject SHA-256:  {local_shas['ommega-inject']}")

    suffix = os.getpid()
    remote_keymint_stage = remote_path(staging_dir, f"ommega.keymint.{suffix}.new")
    remote_inject_stage = remote_path(staging_dir, f"ommega.inject.{suffix}.new")
    adb(serial, "push", os.fspath(keymint), remote_keymint_stage)
    adb(serial, "push", os.fspath(injector), remote_inject_stage)

    remote_keymint = remote_path(REMOTE_DIR, "keymint")
    remote_inject = remote_path(REMOTE_DIR, "ommega-inject")
    remote_tmp_keymint = remote_path(REMOTE_DIR, ".keymint.deploy.tmp")
    remote_tmp_inject = remote_path(REMOTE_DIR, ".inject.deploy.tmp")
    cleanup_staging = "" if keep_staging else f"rm -f {quote(remote_keymint_stage)} {quote(remote_inject_stage)}; "
    command = (
        "set -eu; "
        f"mkdir -p {quote(REMOTE_DIR)}; "
        f"rm -f /data/misc/keystore/ommega/rpc.sock; "
        f"cp -f {quote(remote_keymint_stage)} {quote(remote_tmp_keymint)}; "
        f"cp -f {quote(remote_inject_stage)} {quote(remote_tmp_inject)}; "
        f"chmod 0755 {quote(remote_tmp_keymint)} {quote(remote_tmp_inject)}; "
        f"chcon u:object_r:system_file:s0 {quote(remote_tmp_keymint)} {quote(remote_tmp_inject)} 2>/dev/null || true; "
        f"mv -f {quote(remote_tmp_keymint)} {quote(remote_keymint)}; "
        f"mv -f {quote(remote_tmp_inject)} {quote(remote_inject)}; "
        f"chmod 0755 {quote(remote_keymint)} {quote(remote_inject)}; "
        f"{cleanup_staging}"
        "sync; "
        f"sha256sum {quote(remote_keymint)} {quote(remote_inject)}"
    )
    adb_shell_root(serial, command)
    return local_shas


def install_full_package(
    serial: str | None,
    package: Path,
    staging_dir: str,
    keep_staging: bool,
) -> None:
    require_file(package, "full package")
    remote_package = remote_path(staging_dir, f"ommega.module.{os.getpid()}.zip")

    print_status(f"Local full package: {package}")
    adb(serial, "push", os.fspath(package), remote_package)

    cleanup_staging = "" if keep_staging else f"rm -f {quote(remote_package)}; "
    command = (
        "set -eu; "
        "if command -v ksud >/dev/null 2>&1; then "
        f"ksud module install {quote(remote_package)}; "
        "elif [ -x /data/adb/ksud ]; then "
        f"/data/adb/ksud module install {quote(remote_package)}; "
        "else echo 'ksud not found' >&2; exit 1; fi; "
        f"{cleanup_staging}"
        "sync"
    )
    adb_shell_root(serial, command)
    print_status("Installed full module package with ksud module install.")


def remote_sha256s(serial: str | None) -> dict[str, str]:
    remote_keymint = remote_path(REMOTE_DIR, "keymint")
    remote_inject = remote_path(REMOTE_DIR, "ommega-inject")
    output = adb_shell_root(
        serial,
        f"sha256sum {quote(remote_keymint)} {quote(remote_inject)}",
        capture_output=True,
    ).stdout
    result: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            result[Path(parts[1]).name] = parts[0]
    return result


def verify_remote_sha(serial: str | None, local_shas: dict[str, str]) -> None:
    remote_shas = remote_sha256s(serial)
    for name, local_sha in local_shas.items():
        remote_sha = remote_shas.get(name)
        if remote_sha != local_sha:
            raise RuntimeError(
                f"remote SHA-256 mismatch for {name}: local={local_sha} remote={remote_sha}"
            )
    print_status("Remote SHA-256 matches local binaries.")


def service_state(serial: str | None) -> dict[str, tuple[str, ...]]:
    payload = remote_path(REMOTE_DIR, "injector.payload")
    inject = remote_path(REMOTE_DIR, "ommega-inject")
    command = (
        "ks_pid=$(pidof keystore2 2>/dev/null | awk '{print $1}'); "
        "injected=no; "
        f"if [ -n \"$ks_pid\" ] && [ -r {quote(payload)} ]; then "
        f"ident=$(awk -v want_pid=\"$ks_pid\" '$1 == want_pid && $2 != \"\" {{ print $2; exit }}' {quote(payload)}); "
        "if [ -n \"$ident\" ] && grep -aF \"$ident\" /proc/$ks_pid/maps >/dev/null 2>&1; then injected=yes; fi; "
        "fi; "
        f"if [ \"$injected\" = no ] && [ -n \"$ks_pid\" ] && grep -aF {quote(inject)} /proc/$ks_pid/maps >/dev/null 2>&1; then injected=yes; fi; "
        "printf 'keymint='; pidof keymint 2>/dev/null || true; "
        "printf '\\nkeystore2='; pidof keystore2 2>/dev/null || true; "
        "printf '\\ninjected=%s\\n' \"$injected\"; "
        f"printf '\\npayload='; if [ -r {quote(payload)} ]; then "
        f"tail -n 5 {quote(payload)} 2>/dev/null | tr '\\n' ';'; "
        "fi; printf '\\n'"
    )
    output = adb_shell_root(serial, command, capture_output=True, quiet=True).stdout
    state: dict[str, tuple[str, ...]] = {
        "keymint": tuple(),
        "keystore2": tuple(),
        "injected": ("no",),
        "payload": tuple(),
    }
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        state[key] = tuple(item for item in value.strip().split() if item)
    return state


def print_service_state(label: str, state: dict[str, tuple[str, ...]]) -> None:
    keymint = " ".join(state.get("keymint", ())) or "<none>"
    keystore2 = " ".join(state.get("keystore2", ())) or "<none>"
    injected = " ".join(state.get("injected", ())) or "no"
    payload = " ".join(state.get("payload", ())) or "<empty>"
    print_status(f"{label} keymint pid(s):  {keymint}")
    print_status(f"{label} keystore2 pid(s): {keystore2}")
    print_status(f"{label} injector active:  {injected}")
    print_status(f"{label} injector payload: {payload}")


def trigger_restart(serial: str | None, restart: str) -> None:
    if restart == "none":
        print_status("Restart skipped.")
        return
    marker = RESTART_TARGETS[restart]
    marker_path = remote_path(REMOTE_DIR, marker)
    command = (
        "set -eu; "
        f"mkdir -p {quote(REMOTE_DIR)}; "
        f"touch {quote(marker_path)}"
    )
    adb_shell_root(serial, command)
    print_status(f"Requested ommega restart target: {restart}")


def restarted(
    restart: str,
    before: dict[str, tuple[str, ...]],
    after: dict[str, tuple[str, ...]],
) -> bool:
    checks: list[tuple[str, str]] = []
    if restart in ("all", "keymint"):
        checks.append(("keymint", "keymint"))
    if restart in ("all", "injector"):
        checks.append(("keystore2", "injector"))

    for process, _label in checks:
        previous = set(before.get(process, ()))
        current = set(after.get(process, ()))
        if not current:
            return False
        if previous and previous == current:
            return False
    if restart in ("all", "injector") and after.get("injected") != ("yes",):
        return False
    return True


def resolve_restart(
    requested: str,
    remote_before: dict[str, str],
    remote_after: dict[str, str],
) -> str:
    """Pick the smallest restart that still applies the deployed binaries.

    `restart.injector` and `restart.all` replace keystore2, which throws away the unlock
    material the payload holds in memory; every auth-bound key init then answers LOCKED
    until the next unlock. `restart.keymint` only replaces the shadow, so it keeps that
    material and is the right choice whenever the payload did not change.
    """
    if requested != AUTO_RESTART:
        return requested

    keymint_changed = remote_before.get("keymint") != remote_after.get("keymint")
    injector_changed = remote_before.get("ommega-inject") != remote_after.get("ommega-inject")
    if injector_changed:
        # A changed payload only runs in a fresh keystore2 (the old process has the old
        # code mapped), and the new shadow is only needed if its binary moved too.
        return "all" if keymint_changed else "injector"
    if keymint_changed:
        return "keymint"
    return "none"


def wait_for_restart(
    serial: str | None,
    restart: str,
    before: dict[str, tuple[str, ...]],
    wait_seconds: int,
) -> dict[str, tuple[str, ...]]:
    if restart == "none" or wait_seconds <= 0:
        return service_state(serial)

    deadline = time.monotonic() + wait_seconds
    last_state = service_state(serial)
    if restarted(restart, before, last_state):
        return last_state

    while time.monotonic() < deadline:
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        last_state = service_state(serial)
        if restarted(restart, before, last_state):
            return last_state

    print_service_state("Last observed", last_state)
    raise TimeoutError(f"restart target {restart} was not observed within {wait_seconds}s")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build, deploy, hot-restart, or fully install ommega artifacts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), help="adb serial")
    parser.add_argument("--abi", choices=sorted(ABI_TO_TARGET), default=DEFAULT_ABI, help="Android ABI")
    parser.add_argument("--platform", type=int, default=DEFAULT_PLATFORM, help="Android API level kept for compatibility")
    parser.add_argument("--release", action="store_true", help="build and deploy release artifacts instead of debug")
    parser.add_argument("--full", action="store_true", help="build and install the full module package with ksud")
    parser.add_argument("--skip-build", action="store_true", help="deploy or install existing artifacts")
    parser.add_argument("--keymint", type=Path, help="local keymint path")
    parser.add_argument("--injector", type=Path, help="local inject path")
    parser.add_argument("--staging-dir", default=DEFAULT_STAGING_DIR, help="device temporary upload directory")
    parser.add_argument("--keep-staging", action="store_true", help="leave pushed files in the staging directory")
    parser.add_argument(
        "--restart",
        choices=[AUTO_RESTART, "all", "keymint", "injector", "none"],
        default=AUTO_RESTART,
        help=(
            "hot-restart target; 'auto' derives it from which binary changed "
            "(keymint-only deploys never touch keystore2)"
        ),
    )
    parser.add_argument("--wait-seconds", type=int, default=DEFAULT_WAIT_SECONDS, help="restart observation timeout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.full:
        package = (
            latest_full_package(args.abi, args.release)
            if args.skip_build
            else build_full_package(args.abi, args.platform, args.release)
        )
        install_full_package(args.serial, package, args.staging_dir, args.keep_staging)
        return 0

    if not args.skip_build:
        build_binaries(args.abi, args.platform, args.release)

    keymint = args.keymint or default_keymint_path(args.abi, args.release)
    injector = args.injector or default_injector_path(args.abi, args.release)
    require_file(keymint, "keymint binary")
    require_file(injector, "injector binary")

    remote_before = remote_sha256s(args.serial)
    local_shas = deploy_binaries(
        args.serial,
        keymint,
        injector,
        args.staging_dir,
        args.keep_staging,
    )
    verify_remote_sha(args.serial, local_shas)

    restart = resolve_restart(args.restart, remote_before, local_shas)
    if restart == "none":
        print_status("Binaries unchanged; restart skipped.")
        return 0

    before = service_state(args.serial)
    print_service_state("Before restart", before)
    trigger_restart(args.serial, restart)
    after = wait_for_restart(args.serial, restart, before, args.wait_seconds)
    print_service_state("After restart", after)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print_status(f"deploy_hot_update.py failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
