#!/usr/bin/env python3
"""Whole-VM export/import benchmark, using release libkrun with blk,net.

HVF: benchmark.py --firmware /path/to/libkrunfw-directory
KVM: LD_LIBRARY_PATH=/path/to/libkrunfw-directory benchmark.py
Snapshots are deleted after verification; timings and logs remain in target/.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--sizes", type=int, nargs="+", default=[256, 512, 1024, 2048])
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    hvf = platform.system() == "Darwin"
    work = Path(tempfile.mkdtemp(prefix="checkpoint-benchmark-", dir=repo / "target"))
    libdir = work / "lib"
    libdir.mkdir()
    suffix = "dylib" if hvf else "so"
    lib = repo / f"target/release/libkrun.{suffix}"
    for name in (["libkrun.dylib", "libkrun.1.dylib"] if hvf else ["libkrun.so", "libkrun.so.1"]):
        (libdir / name).symlink_to(lib)
    env = os.environ.copy()
    key = "DYLD_LIBRARY_PATH" if hvf else "LD_LIBRARY_PATH"
    env[key] = str(libdir) + ":" + (str(args.firmware.resolve()) if args.firmware else env.get(key, ""))
    if hvf and not args.firmware:
        parser.error("HVF requires --firmware")
    source = Path(__file__).parent
    guest = work / "benchmark-guest"
    if hvf:
        sysroot = repo / "linux-sysroot"
        gcc = sysroot / "usr/lib/gcc/aarch64-linux-gnu/12"
        compiler = ["/usr/bin/clang", "-target", "aarch64-linux-gnu", "-fuse-ld=/opt/homebrew/opt/lld/bin/ld.lld", f"--sysroot={sysroot}", f"-B{gcc}", f"-L{gcc}"]
    else:
        compiler = ["cc"]
    subprocess.run(compiler + ["-static", "-O2", str(source / "benchmark-guest.c"), "-o", str(guest)], check=True)
    host = work / "host"
    subprocess.run(["cc", "-O2", "-pthread", "-I", str(repo / "include"), str(source / "benchmark-host.c"), "-L", str(libdir), "-lkrun", f"-Wl,-rpath,{libdir}", "-o", str(host)], check=True, env=env)
    if hvf:
        subprocess.run(["codesign", "--entitlements", str(repo / "hvf-entitlements.plist"), "--force", "-s", "-", str(host)], check=True)

    def command(cmd):
        return subprocess.check_output(cmd, text=True).strip()

    result = {
        "platform": "macos-aarch64-hvf" if hvf else "linux-x86_64-kvm",
        "system": platform.platform(),
        "cpu": command(["sysctl", "-n", "machdep.cpu.brand_string"]) if hvf else command(["lscpu"]),
        "host_memory": command(["sysctl", "-n", "hw.memsize"]) if hvf else command(["free", "-b"]),
        "filesystem": command(["df", "-h", str(work)]),
        "library_sha256": hashlib.sha256(lib.read_bytes()).hexdigest(),
        "profile": "release", "vcpus": 2, "guest_filled_fraction": 0.5,
        "payload": "Full RAM + CPU + device state; virtio-fs root; no block disks or network",
        "export_scope": "krun_save_checkpoint call through return, including fsync and resume",
        "import_scope": "krun_start_enter through first restored guest response, excluding later integrity scan",
        "cache": "all snapshot files read before import; no global cache eviction",
        "warmups_per_size": 1, "repeats_per_size": args.repeats,
        "work": str(work), "samples": [], "summary": [],
    }
    print(f"WORK {work}", flush=True)

    def wait(predicate, proc, log, timeout=240):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            if proc.poll() is not None:
                raise RuntimeError(f"process exited {proc.returncode}: {log.read_text(errors='replace')}")
            time.sleep(0.005)
        raise TimeoutError(f"timeout: {log}\n{log.read_text(errors='replace')}")

    def stop(proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=15)

    for size in args.sizes:
        for iteration in range(args.repeats + 1):
            trial = work / f"{size}-{iteration}"
            root = trial / "root"
            root.mkdir(parents=True)
            for name in ("dev", "proc", "sys", "tmp", "run", "etc"):
                (root / name).mkdir()
            shutil.copyfile(guest, root / "benchmark-guest")
            (root / "benchmark-guest").chmod(0o755)
            snapshot = trial / "snapshot"
            source_proc = restored_proc = None

            def start(mode):
                log = trial / f"{mode}.log"
                with log.open("wb") as output:
                    proc = subprocess.Popen([str(host), mode, str(root), str(snapshot), str(trial / f"{mode}.console"), str(size)], stdout=output, stderr=subprocess.STDOUT, env=env)
                return proc, log

            try:
                source_proc, log = start("boot")
                wait(lambda: (root / "ready").exists(), source_proc, log)
                source_proc.send_signal(signal.SIGUSR1)
                match = wait(lambda: re.search(r"EXPORT_NS (\d+) RESULT (-?\d+)", log.read_text(errors="replace")), source_proc, log)
                if int(match[2]) != 0:
                    raise RuntimeError(log.read_text())
                export_ns = int(match[1])
                stop(source_proc)
                artifacts = [p for p in snapshot.rglob("*") if p.is_file()]
                snapshot_bytes = sum(p.stat().st_size for p in artifacts)
                # Explicit warm-cache condition, outside the import timer.
                for path in artifacts:
                    with path.open("rb") as stream:
                        while stream.read(8 * 1024 * 1024):
                            pass
                (root / "request").touch()
                restored_proc, log = start("restore")
                match = wait(lambda: re.search(r"IMPORT_NS (\d+)", log.read_text(errors="replace")), restored_proc, log)
                import_ns = int(match[1])
                wait(lambda: (root / "verified").exists() or (root / "corrupt").exists(), restored_proc, log)
                if (root / "corrupt").exists():
                    raise RuntimeError("restored RAM integrity check failed")
                sample = {"memory_mib": size, "iteration": iteration, "warmup": iteration == 0,
                          "export_ms": export_ns / 1e6, "import_ms": import_ns / 1e6,
                          "snapshot_bytes": snapshot_bytes, "filled_mib": size // 2,
                          "source_pid": source_proc.pid, "restore_pid": restored_proc.pid,
                          "integrity_verified": True}
                result["samples"].append(sample)
                print(json.dumps(sample), flush=True)
                (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
            finally:
                stop(source_proc)
                stop(restored_proc)
            shutil.rmtree(snapshot)
        samples = [s for s in result["samples"] if s["memory_mib"] == size and not s["warmup"]]
        row = {"memory_mib": size}
        for name in ("export_ms", "import_ms"):
            values = [s[name] for s in samples]
            row[name] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        result["summary"].append(row)
        (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print("SUMMARY " + json.dumps(row), flush=True)
    result["status"] = "passed"
    (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
