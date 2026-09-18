#!/usr/bin/env python3
"""
Build script for ommega-a Android targets.
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
import zipfile

try:
    import tomllib as toml
except ModuleNotFoundError:
    import toml


REPO_ROOT = Path(__file__).resolve().parent
TARGET_ROOT = REPO_ROOT / "target"
DEFAULT_PLATFORM = 24

ABI_TO_TARGET = {
    "arm64-v8a": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
}

ABI_TO_MODULE_ARCHES = {
    "arm64-v8a": "arm64 arm64-v8a",
    "x86_64": "x64 x86_64",
}

BINARY_SPECS = (
    {"package": None, "bin": "keymint", "output_name": "keymint"},
    {"package": "ommega-injector", "bin": "ommega-inject", "output_name": "ommega-inject"},
)

REQUIRED_TEMPLATE_FILES = (
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "module.prop",
    "post-fs-data.sh",
    "service.sh",
    "verify.sh",
)

MODULE_TEXT_FILES = (
    "AOSP.Apache-license-2.0.txt",
    "README.md",
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "keybox.xml",
    "module.prop",
    "post-fs-data.sh",
    "sepolicy.rule",
    "service.sh",
    "verify.sh",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "pathmask/UPSTREAM.md",
)

# Official PathMask kernel modules bundled for A-side path masking.  Pinned to
# the v2.8.0 release digests (see template/pathmask/UPSTREAM.md); packaging
# refuses a .ko whose content does not match, so a tampered/corrupted asset can
# never ship.  Keep this table in sync when bumping the upstream release.
PATHMASK_KO_SHA256 = {
    "android12-5.10_pathmask.ko": "a529f89da593c9078712cb9142de8fd94d90ea99a75802f7bf11217e4408d493",
    "android13-5.10_pathmask.ko": "ba12e54a1bdf37df43daa204831aba3a782d970c1bfab5b8610628f22fd3f577",
    "android13-5.15_pathmask.ko": "3c650cb1b2fb2da8a3f08d64a953b1a4828b67298e28e1cdda6f5ddf73f8e9d3",
    "android14-5.15_pathmask.ko": "7f17772c1c3f626095ddd8252d65997606a29cee4c4fa3a60d41bb4b484eff6c",
    "android14-6.1_pathmask.ko": "dd912e7d69ba3f2ec267d07880601c954fbf80470f6b2a0b27da82538768584b",
    "android15-6.6_pathmask.ko": "d1f4a8da78f407d561b3c8207fa23a33111da2f25face9b1d0b5a7ed2d7e5ad0",
    "android16-6.12_pathmask.ko": "6f20c7407235cc78b066ebc710fcdbba45b97fbceb2629e14698a30a2cf5c85f",
}

# Template entries that only make sense for one ABI.  The bundled pathmask
# kernel modules are arm64-only upstream builds, so other ABIs skip that
# directory entirely (customize.sh also only extracts them in the arm64 branch).
TEMPLATE_ABI_EXCLUDES = {
    "x86_64": ("pathmask",),
}


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def get_version_from_cargo_toml() -> str:
    with (REPO_ROOT / "Cargo.toml").open("r", encoding="utf-8") as fh:
        cargo_toml = toml.loads(fh.read())
    return cargo_toml["package"]["version"]


def get_git_commit_count() -> str:
    result = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Not a git checkout (e.g. a source archive); fall back to 0.
        return "0"
    git_count = result.stdout.strip()
    if not git_count.isdigit():
        raise ValueError(f"Git commit count must be numeric only, got: {git_count}")
    return git_count


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

    run(cmd)

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


def verify_pathmask_kos() -> None:
    """Fail the build when a bundled PathMask kernel module is missing/altered."""
    ko_dir = REPO_ROOT / "template" / "pathmask"
    for name, expected in PATHMASK_KO_SHA256.items():
        path = ko_dir / name
        if not path.exists():
            raise FileNotFoundError(f"pathmask kernel module missing: {path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise ValueError(
                f"pathmask kernel module {name} sha256 mismatch: {digest} != {expected}"
            )
    print(f"Verified {len(PATHMASK_KO_SHA256)} pathmask kernel modules")


def copy_template_files(stage_dir: Path, abi: str) -> None:
    template_dir = REPO_ROOT / "template"
    if not template_dir.exists():
        raise FileNotFoundError("Template directory not found")

    missing = [name for name in REQUIRED_TEMPLATE_FILES if not (template_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Template is missing required file(s): {', '.join(missing)}")

    excluded = set(TEMPLATE_ABI_EXCLUDES.get(abi, ()))
    print(f"Copying template files into {stage_dir}...")
    for item in template_dir.iterdir():
        if item.name in excluded:
            print(f"  skipping {item.name} (not applicable to {abi})")
            continue
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


def configure_template_for_abi(stage_dir: Path, abi: str) -> None:
    customize_path = stage_dir / "customize.sh"
    if not customize_path.exists():
        raise FileNotFoundError(f"customize.sh not found at {customize_path}")

    supported_arch = ABI_TO_MODULE_ARCHES[abi]
    content = customize_path.read_text(encoding="utf-8")
    content = content.replace('SUPPORTED_ABIS="arm64 x64"', f'SUPPORTED_ABIS="{supported_arch}"')
    write_text_lf(customize_path, content)
    print(f"Updated customize.sh supported ABI to {supported_arch}")


def modify_module_prop(stage_dir: Path, version: str, git_count: str, git_hash: str) -> None:
    module_prop_path = stage_dir / "module.prop"
    if not module_prop_path.exists():
        raise FileNotFoundError(f"module.prop not found at {module_prop_path}")

    version_name = f"{version}-{git_hash}"
    content = module_prop_path.read_text(encoding="utf-8")
    content = content.replace("${versionName}", version_name)
    content = content.replace("${versionCode}", git_count)
    write_text_lf(module_prop_path, content)
    print(f"Updated module.prop: versionName={version_name}, versionCode={git_count}")


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
        if not item.is_file() or item.name.endswith(".sha256"):
            continue
        if "webroot" in item.relative_to(stage_dir).parts:
            # WebUI webroot is served as-is by the KernelSU/APatch manager,
            # not extracted through verify.sh, so it needs no hash files.
            continue
        generate_hash_for_file(item)


def delete_old_zips(release: bool, selected_abis: list[str]) -> None:
    build_type = "release" if release else "debug"
    old_zips: list[str] = []
    for abi in selected_abis:
        pattern = TARGET_ROOT / f"ommega-a-{build_type}-{abi}-*.zip"
        old_zips.extend(glob.glob(os.fspath(pattern)))
    if not old_zips:
        print(f"No old zip files found for build type {build_type} and ABIs {selected_abis}")
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
    abi: str,
    release: bool,
) -> Path:
    build_type = "release" if release else "debug"
    zip_path = TARGET_ROOT / f"ommega-a-{build_type}-{abi}-{version}-{git_hash}.zip"
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
    git_count: str,
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

        if abi in ("arm64-v8a", "arm64"):
            verify_pathmask_kos()
        copy_template_files(stage_dir, abi)
        normalize_module_text_files(stage_dir)
        configure_template_for_abi(stage_dir, abi)
        for spec in BINARY_SPECS:
            copy_binary(
                built_binaries[spec["output_name"]],
                spec["output_name"],
                abi,
                stage_dir,
            )

        modify_module_prop(stage_dir, version, git_count, git_hash)
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Build ommega-a Magisk packages for Android")
    parser.add_argument("--release", action="store_true", help="Build in release mode")
    parser.add_argument("--debug", action="store_true", help="Build in debug mode (default)")
    parser.add_argument(
        "--abi",
        dest="abis",
        action="append",
        choices=sorted(ABI_TO_TARGET),
        help="Build only the selected Android ABI(s). Defaults to arm64-v8a.",
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

    version = get_version_from_cargo_toml()
    git_count = get_git_commit_count()
    git_hash = get_git_commit_hash()
    selected_abis = args.abis or ["arm64-v8a"]

    print(f"Building ommega-a version {version} (commit {git_count}, hash {git_hash})")
    print(f"Build mode: {'Release' if args.release else 'Debug'}")
    print(f"Target ABIs: {', '.join(selected_abis)}")

    delete_old_zips(args.release, selected_abis)
    built_packages = []
    for abi in selected_abis:
        built_packages.append(
            build_package_for_abi(
                abi=abi,
                release=args.release,
                platform=args.platform,
                version=version,
                git_count=git_count,
                git_hash=git_hash,
            )
        )

    print("Build completed successfully!")
    for zip_path in built_packages:
        print(f"Output: {zip_path}")


if __name__ == "__main__":
    main()
