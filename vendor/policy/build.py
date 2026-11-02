"""编 ommega-policy（自带的 sepolicy 兜底工具）：libsepol core + 我们那个 CLI。

    python vendor/policy/build.py <abi>        # arm64-v8a / armeabi-v7a / x86 / x86_64
    python vendor/policy/build.py host         # 本机跑的那份（Linux/WSL 上自测用）

产物：vendor/policy/out/<abi>/ommega-policy

libsepol 用仓库里 libsepol/ 这份（AOSP external/selinux，LGPL-2.1），只编 core，不编 CIL，
所以不需要 flex/bison。中间 .o 缓存在 vendor/policy/.build/<abi>/，改了源码才重编。
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "ommega_policy.c"
SEPOL = ROOT / "libsepol"
OUT = ROOT / "out"
CACHE = ROOT / ".build"

API = "29"
TRIPLES = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7a-linux-androideabi",
    "x86": "i686-linux-android",
    "x86_64": "x86_64-linux-android",
}
# 这三份走 CIL 的转储路径，我们只用「读 → 插 avtab → 写」这一条，编了也是白占地方。
SKIP_SOURCES = {"src/kernel_to_cil.c", "src/module_to_cil.c", "src/optimize.c"}


def sepol_sources() -> list[pathlib.Path]:
    """libsepol 的 core 源码清单。

    直接照 Android.bp 里的 srcs 取，省得自己列。Android.bp 没跟着源码一起放进仓库
    （用不上），所以清单退化成一个写死的列表，改 libsepol 版本时跟着看一眼。
    """
    fixed = """
        src/assertion.c src/avrule_block.c src/avtab.c src/boolean_record.c
        src/booleans.c src/conditional.c src/constraint.c src/context.c
        src/context_record.c src/debug.c src/ebitmap.c src/expand.c src/handle.c
        src/hashtab.c src/hierarchy.c src/iface_record.c src/interfaces.c
        src/kernel_to_common.c src/kernel_to_conf.c src/link.c src/mls.c
        src/module.c src/node_record.c src/nodes.c src/polcaps.c src/policydb.c
        src/policydb_convert.c src/policydb_public.c src/policydb_validate.c
        src/port_record.c src/ports.c src/services.c src/sidtab.c src/symtab.c
        src/user_record.c src/users.c src/util.c src/write.c
    """.split()
    paths = [SEPOL / name for name in fixed]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise SystemExit(f"libsepol 源码缺文件：{', '.join(missing)}")
    return paths


def ndk_roots() -> list[pathlib.Path]:
    """能用的 NDK 根，顺序跟 a-side/build.py 那边一致（本地 r27d、CI 预装）。"""
    roots: list[pathlib.Path] = []
    for key in (
        "ANDROID_NDK_ROOT",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK",
        "ANDROID_NDK_LATEST_HOME",
    ):
        value = os.environ.get(key)
        if value:
            roots.append(pathlib.Path(value))
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(key)
        if value:
            roots.extend(sorted((pathlib.Path(value) / "ndk").glob("*")))
    # CI 的 Linux 镜像把 NDK 预装在这儿；本地就显式指一下装的 r27d。
    roots.extend(sorted(pathlib.Path("/usr/local/lib/android/sdk/ndk").glob("*")))
    roots.append(pathlib.Path(r"D:\android-ndk-r27d"))
    valid: list[pathlib.Path] = []
    for root in roots:
        if not (root / "toolchains" / "llvm").is_dir():
            continue
        if root not in valid:
            valid.append(root)
    return valid


def host_bin(ndk: pathlib.Path, name: str) -> pathlib.Path:
    for host in ("linux-x86_64", "windows-x86_64", "darwin-x86_64"):
        for filename in (name, f"{name}.exe"):
            candidate = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin" / filename
            if candidate.is_file():
                return candidate
    raise SystemExit(f"{ndk} 里找不到 {name}")


def cache_key(files: list[pathlib.Path], flags: list[str]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path).encode())
        digest.update(path.read_bytes())
    digest.update(" ".join(flags).encode())
    return digest.hexdigest()[:16]


def compile_all(cc: list[str], sources: list[pathlib.Path], flags: list[str],
                work: pathlib.Path) -> None:
    """并行编译；失败的文件名和第一行报错都打出来，别只说「编译失败」。"""

    def one(src: pathlib.Path):
        obj = work / (src.stem + ".o")
        if obj.is_file() and obj.stat().st_mtime >= src.stat().st_mtime:
            return src, 0, ""
        proc = subprocess.run(
            [*cc, *flags, "-c", str(src), "-o", str(obj)],
            capture_output=True, text=True,
        )
        return src, proc.returncode, proc.stderr.strip()

    failed = []
    with ThreadPoolExecutor(max_workers=max(2, os.cpu_count() or 4)) as pool:
        for src, rc, err in pool.map(one, sources):
            if rc != 0:
                failed.append((src, err))
    if failed:
        for src, err in failed:
            first = err.splitlines()[0] if err else ""
            print(f"  FAIL {src.name}: {first}", file=sys.stderr)
        raise SystemExit("编译失败")


def build(abi: str) -> pathlib.Path:
    target = OUT / abi / "ommega-policy"
    target.parent.mkdir(parents=True, exist_ok=True)

    if abi == "host":
        cc = ["cc"]
        ar = ["ar"]
        flags = [
            "-O2", "-D_GNU_SOURCE", "-DHAVE_REALLOCARRAY", "-DNDEBUG",
            "-I", str(SEPOL / "include"), "-I", str(SEPOL / "src"),
            "-Wno-unused-parameter",
        ]
        link = [
            "-O2", str(SRC), "-o", str(target),
            "-I", str(SEPOL / "include"), "-I", str(SEPOL / "src"),
        ]
    else:
        if abi not in TRIPLES:
            raise SystemExit(f"不认识的 ABI：{abi}")
        ndks = ndk_roots()
        if not ndks:
            raise SystemExit("找不到 NDK：设 ANDROID_NDK_ROOT，或者装到默认位置")
        # 多个 NDK 时挨个试，第一个能拿出 clang 的算数（CI 上可能有好几个版本）。
        ndk = None
        for candidate in ndks:
            try:
                host_bin(candidate, "clang")
                ndk = candidate
                break
            except SystemExit:
                continue
        if ndk is None:
            raise SystemExit(f"这些 NDK 里都没 clang：{', '.join(str(p) for p in ndks)}")
        triple = f"{TRIPLES[abi]}{API}"
        cc = [str(host_bin(ndk, "clang"))]
        ar = [str(host_bin(ndk, "llvm-ar"))]
        flags = [
            f"--target={triple}",
            "-O2", "-fPIC", "-D_GNU_SOURCE", "-DHAVE_REALLOCARRAY", "-DNDEBUG",
            "-I", str(SEPOL / "include"), "-I", str(SEPOL / "src"),
            "-Wno-unused-parameter", "-Wno-deprecated-declarations",
            "-Wno-incompatible-pointer-types-discards-qualifiers",
        ]
        link = [
            f"--target={triple}", "-O2", "-fPIE", "-pie", str(SRC), "-o", str(target),
            "-I", str(SEPOL / "include"), "-I", str(SEPOL / "src"),
        ]

    sources = [*sepol_sources(), SRC]
    key = cache_key(sources, flags)
    work = CACHE / abi / key
    work.mkdir(parents=True, exist_ok=True)

    print(f"[{abi}] 编 {len(sepol_sources())} 个 libsepol 源文件 + CLI ...")
    compile_all(cc, sources, flags, work)

    lib = work / "libsepol.a"
    if lib.is_file():
        lib.unlink()
    objs = sorted(str(p) for p in work.glob("*.o") if p.name != "ommega_policy.o")
    subprocess.run([*ar, "rcs", str(lib), *objs], check=True)

    print(f"[{abi}] 链接 ...")
    proc = subprocess.run([*cc, *link, str(lib)], capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"{abi} 链接失败")
    target.chmod(0o755)
    print(f"[{abi}] {target} {target.stat().st_size} bytes")
    return target


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    build(sys.argv[1])


if __name__ == "__main__":
    main()
