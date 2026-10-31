#!/usr/bin/env python3
"""
Build script for ommega-a Android targets.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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

# 版本号唯一来源：仓库根的 VERSION（三端同号，b-app 跟 B 端一起走）。
VERSION_FILE = REPO_ROOT.parent.parent / "VERSION"

# 构建时现生成的本地兜底 ATTK（PKCS#8 PEM，不要提交，*.pem 已被 .gitignore 排掉）。
SOTER_ATTK_PATH = REPO_ROOT / "ommega-injector" / "assets" / "soter_attk.pem"


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
    "armeabi-v7a": "armv7-linux-androideabi",
    "x86": "i686-linux-android",
    "x86_64": "x86_64-linux-android",
}

ABI_TO_MODULE_ARCHES = {
    "arm64-v8a": "arm64 arm64-v8a",
    "armeabi-v7a": "arm armeabi-v7a",
    "x86": "x86",
    "x86_64": "x64 x86_64",
}

BINARY_SPECS = (
    {"package": None, "bin": "keymint", "output_name": "keymint"},
    {"package": "ommega-injector", "bin": "ommega-inject", "output_name": "ommega-inject"},
)

# resetprop 单列：它是独立 crate（`resetprop/`），走自己的 target 目录。
# 实现是 vendor/ 下那两个 crate（resetprop-rs），运行时要 dlopen 设备的 libc.so
# 去用 bionic 自己的属性实现，所以**不能**静态链接（静态 libc 里没有可用的 dlopen）。
# 单独开一个 target 目录，只是不想跟 keymint/inject 那几个 PIE 载荷的缓存互相顶掉。
RESETPROP_PACKAGE = "ommega-resetprop"
RESETPROP_BIN = "resetprop"
RESETPROP_TARGET_DIR = TARGET_ROOT / "resetprop"

REQUIRED_TEMPLATE_FILES = (
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "layout.sh",
    "module.prop",
    "post-fs-data.sh",
    "service.sh",
    "verify.sh",
    "adbr-daemon.sh",
    "keybox_tee.xml",
    "keybox_strongbox.xml",
)

MODULE_TEXT_FILES = (
    "AOSP.Apache-license-2.0.txt",
    "README.md",
    "adbr-daemon.sh",
    "customize.sh",
    "daemon",
    "daemon-injector",
    "injector.toml",
    "keybox_tee.xml",
    "keybox_strongbox.xml",
    "layout.sh",
    "module.prop",
    "post-fs-data.sh",
    "sepolicy.rule",
    "service.sh",
    "verify.sh",
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "pathmask/UPSTREAM.md",
)

# adbr（公网调试通道）的设备侧二进制，两种模块共用仓库根 vendor/adbrd/ 里那一份。
# 上游只给 arm64 构建，所以只有 arm64-v8a 会带上它。
ADBRD_SOURCE = REPO_ROOT.parent.parent / "vendor" / "adbrd" / "arm64-v8a" / "adbrd"
ADBRD_ABI = "arm64-v8a"

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
    "armeabi-v7a": ("pathmask",),
    "x86": ("pathmask",),
    "x86_64": ("pathmask",),
}


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def ndk_roots() -> list[Path]:
    """所有可能的 NDK 根。

    只修 `ANDROID_NDK_ROOT` 那一个是不够的：cc-rs 给 lsplt 这类带 build.rs 的
    依赖定 sysroot 时看的是它自己那套环境变量（Runner 上预装的
    `/usr/local/lib/android/sdk/ndk/27.3.13750724`），结果链接时 `-L` 指的是预装
    那个 NDK、clang 却是 `.cargo/config.toml` 里指定的 r27d —— 修了一份没用。
    """
    roots: list[Path] = []
    for key in (
        "ANDROID_NDK_ROOT",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK",
        "ANDROID_NDK_LATEST_HOME",
    ):
        value = os.environ.get(key)
        if value:
            roots.append(Path(value))
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(key)
        if value:
            roots.extend(sorted((Path(value) / "ndk").glob("*")))
    # GitHub 的 Linux 镜像把 NDK 预装在这儿，那边不一定设 ANDROID_HOME。
    roots.extend(sorted(Path("/usr/local/lib/android/sdk/ndk").glob("*")))
    seen: list[Path] = []
    for root in roots:
        if root.is_dir() and root not in seen:
            seen.append(root)
    return seen


def ensure_x86_builtins() -> None:
    """给 i686 目标补一份 `libclang_rt.builtins-x86-android.a`。

    Rust 的 `i686-linux-android` 在链接时去要 `-lclang_rt.builtins-x86-android`，
    而 NDK 里那份资源库在某些版本/某些宿主包里只叫 `-i686-`（本地 27.3 两份都有，
    CI 的 r27d 只有 i686，于是 `ld.lld: unable to find library
    -lclang_rt.builtins-x86-android`）。缺了就从 i686 那份复制一份，两边都齐的时候
    这一步什么也不做。所有能看到的 NDK 都补一遍，谁被拿去当 sysroot 都能找到。
    """
    for ndk in ndk_roots():
        for host in ("linux-x86_64", "darwin-x86_64", "windows-x86_64"):
            base = ndk / "toolchains" / "llvm" / "prebuilt" / host / "lib" / "clang"
            if not base.is_dir():
                continue
            for ver in base.iterdir():
                linux_dir = ver / "lib" / "linux"
                if not linux_dir.is_dir():
                    continue
                want = linux_dir / "libclang_rt.builtins-x86-android.a"
                src = linux_dir / "libclang_rt.builtins-i686-android.a"
                if want.is_file() or not src.is_file():
                    continue
                try:
                    shutil.copyfile(src, want)
                    print(f"补上 {want}", flush=True)
                except OSError as exc:
                    print(f"补 {want} 失败（继续，交给链接器报错）: {exc}", flush=True)


def ensure_rust_targets(targets: list[str]) -> None:
    """缺哪个 Rust target 就现装哪个。

    CI 那边以前只在 workflow 里列了三个 target，A 端要出四个 ABI，跑到 i686 就
    `can't find crate for core`；本地新机器同理。装不上不算错（比如离线），让
    后面真正的编译去报错，信息更直接。
    """
    try:
        listed = subprocess.run(
            ["rustup", "target", "list", "--installed"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return
    if listed.returncode != 0:
        return
    installed = {line.strip() for line in listed.stdout.splitlines() if line.strip()}
    missing = [t for t in targets if t not in installed]
    if not missing:
        return
    print(f"安装缺失的 Rust target: {' '.join(missing)}")
    subprocess.run(["rustup", "target", "add", *missing], check=False)


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


# 同版本号重发（热修）的时候 versionCode 必须继续往上走，模块管理器才认得出更新。
#
# 别把这个数归零：公式是 major*1e6 + minor*1e3 + patch，patch 只值 1，而历史热修
# 攒出来的偏移早就超过 10 了，一归零版本号反而变小（1.6.8+19 = 1006027，而
# 1.6.9+0 = 1006009）—— 管理器会当成降级，1.6.9 根本推不下去。所以换版本号也
# 只能接着往上加：必须 > 线上那颗 1006026，18 刚好到 1006027。
# 这个数跟 b-side 各算各的，别顺手对齐。
VERSION_CODE_OFFSET = 84


def version_code(version: str) -> str:
    """versionCode 由版本号推出（major*1000000 + minor*1000 + patch + VERSION_CODE_OFFSET）。

    以前用 git 提交数：随便一次无关提交都会让它跳，没有 .git 的源码包还会退化成 0。
    """
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"VERSION must be MAJOR.MINOR.PATCH, got: {version}")
    major, minor, patch = (int(p) for p in parts)
    if minor > 999 or patch > 999:
        raise ValueError(f"VERSION minor/patch must be <= 999: {version}")
    return str(major * 1_000_000 + minor * 1_000 + patch + VERSION_CODE_OFFSET)


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


def build_resetprop(*, abi: str, target: str, release: bool) -> Path:
    """编一个 resetprop（模块自带，不依赖 root 管理器提供）。"""
    build_type = "release" if release else "debug"
    print(f"Building resetprop for {abi} ({target}, {build_type})...")

    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = os.fspath(RESETPROP_TARGET_DIR)

    cmd = [
        "cargo",
        "build",
        "-p",
        RESETPROP_PACKAGE,
        "--bin",
        RESETPROP_BIN,
        "--target",
        target,
    ]
    if release:
        cmd.append("--release")
    run(cmd, env=env)

    binary_path = RESETPROP_TARGET_DIR / target / build_type / RESETPROP_BIN
    if not binary_path.exists():
        raise FileNotFoundError(f"Built binary not found at {binary_path}")
    return binary_path


def copy_adbrd(stage_dir: Path) -> None:
    """把 adbr 的设备侧 adbrd 放进 libs/arm64-v8a/。

    它不参与 attestation，跑不跑由 WebUI 的 adbr 开关（A 端配置里的 `adbr:`，
    默认关）决定，service.sh 交给 adbr-daemon.sh 监管。只有 arm64 一份。
    """
    if not ADBRD_SOURCE.exists():
        raise FileNotFoundError(f"adbrd binary not found at {ADBRD_SOURCE}")
    dest_dir = stage_dir / "libs" / ADBRD_ABI
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / "adbrd"
    shutil.copy2(ADBRD_SOURCE, dest_path)
    print(f"Copied {ADBRD_SOURCE} to {dest_path}")


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


def copy_template_files(stage_dir: Path, abi: str | None = None) -> None:
    template_dir = REPO_ROOT / "template"
    if not template_dir.exists():
        raise FileNotFoundError("Template directory not found")

    missing = [name for name in REQUIRED_TEMPLATE_FILES if not (template_dir / name).exists()]
    if missing:
        raise FileNotFoundError(f"Template is missing required file(s): {', '.join(missing)}")

    # abi=None means a combined multi-ABI package: nothing may be excluded,
    # since any of the ABIs inside might need it at install time.
    excluded = set(TEMPLATE_ABI_EXCLUDES.get(abi, ())) if abi else set()
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


def configure_template_for_abis(stage_dir: Path, abis: list[str]) -> None:
    """Rewrite SUPPORTED_ABIS in the staged customize.sh to exactly the set of
    ABIs the package carries, so the installer accepts a device whose $ARCH is
    any of them."""
    customize_path = stage_dir / "customize.sh"
    if not customize_path.exists():
        raise FileNotFoundError(f"customize.sh not found at {customize_path}")

    arches: list[str] = []
    for abi in abis:
        for arch in ABI_TO_MODULE_ARCHES[abi].split():
            if arch not in arches:
                arches.append(arch)
    supported_arch = " ".join(arches)

    content = customize_path.read_text(encoding="utf-8")
    content = content.replace('SUPPORTED_ABIS="arm64 x64"', f'SUPPORTED_ABIS="{supported_arch}"')
    write_text_lf(customize_path, content)
    print(f"Updated customize.sh supported ABIs to {supported_arch}")


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
        if not item.is_file() or item.name.endswith(".sha256"):
            continue
        if "webroot" in item.relative_to(stage_dir).parts:
            # WebUI webroot is served as-is by the KernelSU/APatch manager,
            # not extracted through verify.sh, so it needs no hash files.
            continue
        generate_hash_for_file(item)


def delete_old_zips(release: bool) -> None:
    """Remove every previously built zip of this build type, whatever its
    naming (with or without an ABI tag) or which ABIs it carried."""
    build_type = "release" if release else "debug"
    old_zips = glob.glob(os.fspath(TARGET_ROOT / f"ommega-a-{build_type}-*.zip"))
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
    zip_path = TARGET_ROOT / f"ommega-a-{build_type}{abi_suffix}-{version}-{git_hash}.zip"
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
        built_binaries["resetprop"] = build_resetprop(abi=abi, target=target, release=release)

        if abi in ("arm64-v8a", "arm64"):
            verify_pathmask_kos()
        copy_template_files(stage_dir, abi)
        normalize_module_text_files(stage_dir)
        configure_template_for_abis(stage_dir, [abi])
        for spec in BINARY_SPECS:
            copy_binary(
                built_binaries[spec["output_name"]],
                spec["output_name"],
                abi,
                stage_dir,
            )
        # resetprop 不在 BINARY_SPECS 里（它是独立 crate），得单独拷。
        copy_binary(built_binaries["resetprop"], "resetprop", abi, stage_dir)
        if abi == ADBRD_ABI:
            copy_adbrd(stage_dir)

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
    serial: bool = False,
) -> Path:
    """Build every selected ABI into a single module zip.

    customize.sh already picks libs/<abi> (and the matching pathmask .ko set) at
    install time, so a multi-ABI package is the union of every ABI's binaries in
    one stage directory plus a SUPPORTED_ABIS line listing all of them.
    """
    stage_dir = TARGET_ROOT / "temp" / "combined"
    _ = platform
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        built: dict[str, dict[str, Path]] = {}

        def compile_one_abi(abi: str) -> tuple[str, dict[str, Path]]:
            """Compile every binary of one ABI (kept sequential inside the ABI:
            those builds share target/<triple>/ and cargo would serialise them
            anyway)."""
            compiled: dict[str, Path] = {}
            for spec in BINARY_SPECS:
                compiled[spec["output_name"]] = build_binary(
                    abi=abi,
                    target=ABI_TO_TARGET[abi],
                    release=release,
                    package=spec["package"],
                    bin_name=spec["bin"],
                )
            compiled["resetprop"] = build_resetprop(
                abi=abi,
                target=ABI_TO_TARGET[abi],
                release=release,
            )
            return abi, compiled

        # Different ABIs land in disjoint target/<triple>/ directories with their
        # own cargo build locks, so they are safe to compile at the same time.
        # With lto=true + codegen-units=1 the final link of each binary is
        # single-threaded, so running the ABIs concurrently is where the wall
        # time actually goes.  Everything below (staging, zip) stays serial
        # because it writes into one shared stage directory.
        if len(abis) > 1 and not serial:
            jobs = len(abis)
            print(f"Compiling {len(abis)} ABIs in parallel ({jobs} jobs)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                for abi, compiled in pool.map(compile_one_abi, abis):
                    built[abi] = compiled
        else:
            for abi in abis:
                _, compiled = compile_one_abi(abi)
                built[abi] = compiled

        if any(abi in ("arm64-v8a", "arm64") for abi in abis):
            verify_pathmask_kos()
        copy_template_files(stage_dir)
        normalize_module_text_files(stage_dir)
        configure_template_for_abis(stage_dir, abis)
        for abi in abis:
            for spec in BINARY_SPECS:
                copy_binary(
                    built[abi][spec["output_name"]],
                    spec["output_name"],
                    abi,
                    stage_dir,
                )
            # resetprop 不在 BINARY_SPECS 里（它是独立 crate），得单独拷。
            copy_binary(built[abi]["resetprop"], "resetprop", abi, stage_dir)
        if ADBRD_ABI in abis:
            copy_adbrd(stage_dir)

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


def ensure_soter_attk() -> None:
    """每次构建现生成一把 ATTK（PKCS#8 RSA-2048），编进 injector。

    以前是从 CI secret 还原一把固定的 ASK 编进二进制；现在不内置固定材料：
    ATTK 每次发版构建时按当时时间重新生成一把自签的，进了二进制就不再变（除非
    设备上手动换 ATTK 文件）；ASK 由运行时按 uid 现生成、落盘复用。
    """
    path = SOTER_ATTK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")
    tmp = path.with_name(path.name + ".tmp")
    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            os.fspath(tmp),
        ]
    )
    # 生成完当场验一遍，坏钥匙宁可构建失败也不要编进包里。
    run(["openssl", "pkey", "-in", os.fspath(tmp), "-noout", "-check"])
    body = tmp.read_text(encoding="ascii")
    tmp.unlink()
    with path.open("w", encoding="ascii", newline="\n") as fh:
        fh.write(f"# ommega local ATTK, generated at {stamp}\n")
        fh.write(body)
        if not body.endswith("\n"):
            fh.write("\n")
    print(f"Generated a fresh self-signed ATTK at {path} ({stamp})")


def main() -> None:

    # 四个 ABI 都要：arm64 / armv7 / x86_64 / x86。缺 target 就现装，别让 CI 的
    # workflow 里那份清单成为唯一的真源。
    ensure_rust_targets(
        ["aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android", "i686-linux-android"]
    )
    ensure_x86_builtins()
    parser = argparse.ArgumentParser(description="Build ommega-a Magisk packages for Android")
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
    parser.add_argument(
        "--serial",
        action="store_true",
        help="Compile the selected ABIs one after another instead of in "
        "parallel (slower; only useful to make the build log readable).",
    )
    parser.add_argument(
        "--version-code",
        type=int,
        default=None,
        help="Override versionCode (default: derived from VERSION). "
        "Use it to re-release the same version number as a hotfix, otherwise "
        "the module manager sees no update to install.",
    )
    args = parser.parse_args()

    ensure_cargo_config()
    ensure_soter_attk()

    version = get_version()
    vcode = str(args.version_code) if args.version_code else version_code(version)
    git_hash = get_git_commit_hash()
    selected_abis = args.abis or sorted(ABI_TO_TARGET)

    print(f"Building ommega-a version {version} (versionCode {vcode}, hash {git_hash})")
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
                serial=args.serial,
            )
        )

    print("Build completed successfully!")
    for zip_path in built_packages:
        print(f"Output: {zip_path}")


if __name__ == "__main__":
    main()
