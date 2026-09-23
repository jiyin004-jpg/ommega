#!/usr/bin/env python3
"""
Build script for ommegaclient-b Android targets.
"""

from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

try:
    import tomllib as toml
except ModuleNotFoundError:
    import toml


REPO_ROOT = Path(__file__).resolve().parent
TARGET_ROOT = REPO_ROOT / "target"

# 版本号唯一来源：仓库根的 VERSION（A 模块 / B 模块 / b-app / 服务端 四端必须一致）。
VERSION_FILE = REPO_ROOT.parent.parent / "VERSION"


def ensure_cargo_config() -> None:
    """`.cargo/config.toml` 不入库，干净 clone 里没有它，cargo 不知道 Android
    目标该用哪个链接器，到链接阶段才报一堆错。缺了就地生成一份。"""
    cargo_config = REPO_ROOT / ".cargo" / "config.toml"
    if cargo_config.exists():
        return
    script = REPO_ROOT / "scripts" / "setup_cargo_config.py"
    if not script.exists():
        return
    print("Generating .cargo/config.toml ...")
    subprocess.run([sys.executable, os.fspath(script)], cwd=REPO_ROOT, check=True)
DEFAULT_PLATFORM = 24

ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

BINARY_SPECS = (
    {"package": None, "bin": "relay", "output_name": "relay"},
)

REQUIRED_TEMPLATE_FILES = (
    "customize.sh",
    "module.prop",
    "post-fs-data.sh",
    "relay.conf",
    "service.sh",
    "verify.sh",
)

MODULE_TEXT_FILES = (
    "AOSP.Apache-license-2.0.txt",
    "README.md",
    "customize.sh",
    "module.prop",
    "post-fs-data.sh",
    "relay.conf",
    "sepolicy.rule",
    "service.sh",
    "verify.sh",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
)


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def get_version() -> str:
    """版本号唯一来源 = 仓库根的 VERSION；顺带强制 Cargo.toml 与它一致。"""
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    with (REPO_ROOT / "Cargo.toml").open("r", encoding="utf-8") as fh:
        cargo_version = toml.loads(fh.read())["package"]["version"]
    if cargo_version != version:
        raise SystemExit(
            f"Cargo.toml version ({cargo_version}) != VERSION ({version}): "
            "两个都要改，别只改一个"
        )
    return version


def version_code(version: str) -> str:
    """versionCode 由版本号推出（major*1000000 + minor*1000 + patch）。

    以前用 git 提交数：随便一次无关提交都会让它跳，没有 .git 的源码包还会退化成 0。
    """
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"VERSION must be MAJOR.MINOR.PATCH, got: {version}")
    major, minor, patch = (int(p) for p in parts)
    if minor > 999 or patch > 999:
        raise ValueError(f"VERSION minor/patch must be <= 999: {version}")
    return str(major * 1_000_000 + minor * 1_000 + patch)


def get_git_commit_hash() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Not a git checkout (e.g. a source archive); fall back to a date tag.
        return datetime.datetime.now().strftime("%Y%m%d")
    return result.stdout.strip()[:7]


def cargo_env_for_target(_target: str) -> dict[str, str]:
    return os.environ.copy()


def build_binary(
    *,
    abi: str,
    target: str,
    release: bool,
    package: str | None,
    bin_name: str,
) -> Path:
    build_type = "release" if release else "debug"
    print(f"Building {bin_name} for {abi} ({target}, {build_type})...")

    cmd = ["cargo", "build", "--target", target]
    if package:
        cmd.extend(["-p", package, "--bin", bin_name])
    else:
        cmd.extend(["--bin", bin_name])
    if release:
        cmd.append("--release")

    run(cmd, env=cargo_env_for_target(target))

    binary_path = TARGET_ROOT / target / build_type / bin_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Built binary not found at {binary_path}")
    return binary_path


def copy_binary(binary: Path, output_name: str, abi: str, stage_dir: Path) -> None:
    dest_dir = stage_dir / "libs" / abi
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / output_name
    shutil.copy2(binary, dest_path)
    print(f"Copied {binary} to {dest_path}")


def copy_template_files(stage_dir: Path) -> None:
    template_dir = REPO_ROOT / "template"
    if not template_dir.exists():
        raise FileNotFoundError("Template directory not found")

    missing = [name for name in REQUIRED_TEMPLATE_FILES if not (template_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Template is missing required file(s): {', '.join(missing)}")

    print(f"Copying template files into {stage_dir}...")
    for item in template_dir.iterdir():
        dst = stage_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dst)


def write_text_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def normalize_module_text_files(stage_dir: Path) -> None:
    for relative_path in MODULE_TEXT_FILES:
        path = stage_dir / relative_path
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        content = content.replace("\r\n", "\n").replace("\r", "\n")
        write_text_lf(path, content)


def modify_module_prop(stage_dir: Path, version: str, vcode: str, git_hash: str) -> None:
    module_prop_path = stage_dir / "module.prop"
    if not module_prop_path.exists():
        raise FileNotFoundError(f"module.prop not found at {module_prop_path}")

    version_name = f"{version}-{git_hash}"
    content = module_prop_path.read_text(encoding="utf-8")
    content = content.replace("${versionName}", version_name)
    content = content.replace("${versionCode}", vcode)
    write_text_lf(module_prop_path, content)
    print(f"Updated module.prop: versionName={version_name}, versionCode={vcode}")


def generate_hash_for_file(file_path: Path) -> None:
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)

    hash_path = file_path.with_name(f"{file_path.name}.sha256")
    hash_path.write_text(digest.hexdigest(), encoding="utf-8")
    print(f"Created hash file: {hash_path}")


def generate_hash_files(stage_dir: Path) -> None:
    print(f"Generating SHA256 hash files under {stage_dir}...")
    for item in stage_dir.rglob("*"):
        if item.is_file() and not item.name.endswith(".sha256"):
            generate_hash_for_file(item)


def delete_old_zips(release: bool) -> None:
    """Remove every previously built zip of this build type, whatever its
    naming (with or without an ABI tag) or which ABIs it carried."""
    build_type = "release" if release else "debug"
    old_zips = glob.glob(os.fspath(TARGET_ROOT / f"ommegaclient-b-{build_type}-*.zip"))
    if not old_zips:
        print(f"No old zip files found for build type {build_type}")
        return

    print(f"Found {len(old_zips)} old zip file(s) to delete:")
    for old_zip in old_zips:
        print(f"  Deleting: {old_zip}")
        os.remove(old_zip)


def create_zip_package(
    *,
    stage_dir: Path,
    version: str,
    git_hash: str,
    abi: str | None,
    release: bool,
) -> Path:
    build_type = "release" if release else "debug"
    abi_suffix = f"-{abi}" if abi else ""
    zip_path = TARGET_ROOT / f"ommegaclient-b-{build_type}{abi_suffix}-{version}-{git_hash}.zip"
    print(f"Creating zip package: {zip_path}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(stage_dir):
            for file_name in files:
                file_path = Path(root) / file_name
                arcname = file_path.relative_to(stage_dir)
                zipf.write(file_path, arcname)

    return zip_path


def build_package_for_abi(
    *,
    abi: str,
    release: bool,
    platform: int,
    version: str,
    vcode: str,
    git_hash: str,
) -> Path:
    target = ABI_TO_TARGET[abi]
    stage_dir = TARGET_ROOT / "temp" / abi
    # Kept for compatibility with old invocations; plain Cargo uses .cargo/config.toml.
    _ = platform
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        built_binaries: dict[str, Path] = {}
        for spec in BINARY_SPECS:
            built_binaries[spec["output_name"]] = build_binary(
                abi=abi,
                target=target,
                release=release,
                package=spec["package"],
                bin_name=spec["bin"],
            )

        copy_template_files(stage_dir)
        normalize_module_text_files(stage_dir)
        for spec in BINARY_SPECS:
            copy_binary(
                built_binaries[spec["output_name"]],
                spec["output_name"],
                abi,
                stage_dir,
            )

        modify_module_prop(stage_dir, version, vcode, git_hash)
        normalize_module_text_files(stage_dir)
        generate_hash_files(stage_dir)
        return create_zip_package(
            stage_dir=stage_dir,
            version=version,
            git_hash=git_hash,
            abi=abi,
            release=release,
        )
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)


def build_combined_package(
    *,
    abis: list[str],
    release: bool,
    platform: int,
    version: str,
    vcode: str,
    git_hash: str,
) -> Path:
    """Build every selected ABI into a single module zip.

    The template's customize.sh already picks libs/<abi> at install time, so a
    multi-ABI package is just the union of every ABI's binaries staged together.
    """
    stage_dir = TARGET_ROOT / "temp" / "combined"
    _ = platform
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        built: dict[str, dict[str, Path]] = {}
        for abi in abis:
            built[abi] = {}
            for spec in BINARY_SPECS:
                built[abi][spec["output_name"]] = build_binary(
                    abi=abi,
                    target=ABI_TO_TARGET[abi],
                    release=release,
                    package=spec["package"],
                    bin_name=spec["bin"],
                )

        copy_template_files(stage_dir)
        normalize_module_text_files(stage_dir)
        for abi in abis:
            for spec in BINARY_SPECS:
                copy_binary(
                    built[abi][spec["output_name"]],
                    spec["output_name"],
                    abi,
                    stage_dir,
                )

        modify_module_prop(stage_dir, version, vcode, git_hash)
        normalize_module_text_files(stage_dir)
        generate_hash_files(stage_dir)
        return create_zip_package(
            stage_dir=stage_dir,
            version=version,
            git_hash=git_hash,
            abi=None,
            release=release,
        )
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ommegaclient-b Magisk packages for Android")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--debug", action="store_true", help="Build in debug mode (default)")
    parser.add_argument(
        "--abi",
        dest="abis",
        action="append",
        choices=sorted(ABI_TO_TARGET),
        help="Restrict the package to the selected Android ABI(s). "
        "Defaults to every supported ABI in a single zip.",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Emit one zip per ABI instead of a single multi-ABI package.",
    )
    parser.add_argument(
        "--platform",
        type=int,
        default=DEFAULT_PLATFORM,
        help=(
            "Compatibility option; ordinary cargo builds use .cargo/config.toml "
            f"for the Android API/linker (default: {DEFAULT_PLATFORM})"
        ),
    )
    args = parser.parse_args()

    ensure_cargo_config()

    version = get_version()
    vcode = version_code(version)
    git_hash = get_git_commit_hash()
    selected_abis = args.abis or sorted(ABI_TO_TARGET)

    print(f"Building ommegaclient-b version {version} (versionCode {vcode}, hash {git_hash})")
    print(f"Build mode: {'Release' if args.release else 'Debug'}")
    print(f"Target ABIs: {', '.join(selected_abis)}")

    delete_old_zips(args.release)
    built_packages = []
    if args.split:
        for abi in selected_abis:
            built_packages.append(
                build_package_for_abi(
                    abi=abi,
                    release=args.release,
                    platform=args.platform,
                    version=version,
                    vcode=vcode,
                    git_hash=git_hash,
                )
            )
    else:
        built_packages.append(
            build_combined_package(
                abis=selected_abis,
                release=args.release,
                platform=args.platform,
                version=version,
                vcode=vcode,
                git_hash=git_hash,
            )
        )

    print("Build completed successfully!")
    for zip_path in built_packages:
        print(f"Output: {zip_path}")


if __name__ == "__main__":
    main()
