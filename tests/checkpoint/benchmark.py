#!/usr/bin/env python3
"""Whole-VM export/import benchmark, using release libkrun with blk,net.

HVF: benchmark.py --firmware /path/to/libkrunfw-directory
KVM: LD_LIBRARY_PATH=/path/to/libkrunfw-directory benchmark.py
Snapshots are deleted after verification; timings and logs remain in target/.
"""
import argparse
import csv
from datetime import datetime
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
    env["KRUN_CHECKPOINT_TIMINGS"] = "1"
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
        "started_at": datetime.now().astimezone().isoformat(),
        "platform": "macos-aarch64-hvf" if hvf else "linux-x86_64-kvm",
        "system": platform.platform(),
        "cpu": command(["sysctl", "-n", "machdep.cpu.brand_string"]) if hvf else command(["lscpu"]),
        "host_memory": command(["sysctl", "-n", "hw.memsize"]) if hvf else command(["free", "-b"]),
        "filesystem": command(["df", "-h", str(work)]),
        "library_sha256": hashlib.sha256(lib.read_bytes()).hexdigest(),
        "source_commit": command(["git", "rev-parse", "HEAD"]),
        "source_dirty": bool(command(["git", "status", "--porcelain"])),
        "firmware_sha256": hashlib.sha256((args.firmware / "libkrunfw.5.dylib").read_bytes()).hexdigest() if hvf else None,
        "profile": "release", "vcpus": 2, "guest_filled_fraction": 0.5,
        "memory_hotplug": False, "dax": False,
        "response_poll_us": 100, "guest_request_poll_us": 1000,
        "payload": "Full RAM + CPU + device state; virtio-fs root; no block disks or network",
        "export_scope": "krun_pause + krun_save_checkpoint through return, including fsync; source stays paused",
        "import_scope": "krun_start_enter through first restored guest response, excluding later integrity scan",
        "cache": "checkpoint read into host file cache before import; no global cache eviction",
        "process_import_scope": "parent process launch attempt through first restored guest response; includes loader and context setup",
        "verification_scope": "host-observed response through full guest pattern verification; recorded separately",
        "timings": "CLOCK_MONOTONIC end-to-end; Instant phase timers; tracing enabled, buffered until each operation completes",
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
                run_env = env.copy()
                with log.open("wb") as output:
                    run_env["KRUN_BENCH_PROCESS_LAUNCH_NS"] = str(time.clock_gettime_ns(time.CLOCK_MONOTONIC))
                    proc = subprocess.Popen([str(host), mode, str(root), str(snapshot), str(trial / f"{mode}.console"), str(size)], stdout=output, stderr=subprocess.STDOUT, env=run_env)
                return proc, log

            try:
                source_proc, log = start("boot")
                wait(lambda: (root / "ready").exists(), source_proc, log)
                source_proc.send_signal(signal.SIGUSR1)
                match = wait(lambda: re.search(r"EXPORT_NS (\d+) RESULT (-?\d+)", log.read_text(errors="replace")), source_proc, log)
                if int(match[2]) != 0:
                    raise RuntimeError(log.read_text())
                export_ns = int(match[1])
                export_log = log.read_text(errors="replace")
                if hvf:
                    with snapshot.open("rb") as file:
                        header = file.read(16)
                        length = int.from_bytes(header[12:16], "little")
                        saved = json.loads(file.read(length))
                        result["gic"] = "native" if saved["vm"]["native_gic"] else "software"
                stop(source_proc)
                artifacts = [snapshot]
                snapshot_bytes = sum(p.stat().st_size for p in artifacts)
                allocated_bytes = sum(p.stat().st_blocks * 512 for p in artifacts)
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
                wait(lambda: "RESPONSE_TO_VERIFIED_NS " in log.read_text(errors="replace"), restored_proc, log)
                import_log = log.read_text(errors="replace")
                def scalar(text, name):
                    return int(re.search(rf"^{name} (\d+)$", text, re.M)[1])

                phases_ns = {f"{operation}.{phase}": int(ns)
                             for operation, phase, ns in re.findall(r"^KRUN_CHECKPOINT_PHASE (\w+) (\w+) (\d+)$", export_log + import_log, re.M)}
                for operation, expected in (("pause", "freeze_devices"), ("save", "sync_file"), ("restore", "resume_vcpus")):
                    if f"{operation}.{expected}" not in phases_ns:
                        raise RuntimeError(f"missing {operation} phase timings")
                for operation, total in (("pause", scalar(export_log, "PAUSE_NS")),
                                         ("save", scalar(export_log, "SAVE_NS")),
                                         ("restore", import_ns)):
                    accounted = sum(ns for phase, ns in phases_ns.items() if phase.startswith(operation + "."))
                    if accounted > total:
                        raise RuntimeError(f"{operation} phases exceed end-to-end time")
                    phases_ns[f"{operation}.control_logging_and_response"] = total - accounted
                for phase, ns in re.findall(r"^SETUP_PHASE (\w+) (\d+)$", import_log, re.M):
                    phases_ns[f"setup.{phase}"] = int(ns)
                setup_ns = scalar(import_log, "IMPORT_SETUP_NS")
                phases_ns["setup.other"] = setup_ns - sum(ns for name, ns in phases_ns.items() if name.startswith("setup."))
                phases_ns["setup.process_launch_to_main"] = scalar(import_log, "IMPORT_LAUNCH_NS")
                verified_ns = scalar(import_log, "RESPONSE_TO_VERIFIED_NS")
                sample = {"memory_mib": size, "iteration": iteration, "warmup": iteration == 0,
                          "export_ms": export_ns / 1e6, "import_ms": import_ns / 1e6,
                          "pause_ms": scalar(export_log, "PAUSE_NS") / 1e6,
                          "save_ms": scalar(export_log, "SAVE_NS") / 1e6,
                          "setup_ms": setup_ns / 1e6,
                          "process_import_ms": scalar(import_log, "IMPORT_PROCESS_NS") / 1e6,
                          "response_to_verified_ms": verified_ns / 1e6,
                          "verified_import_ms": (import_ns + verified_ns) / 1e6,
                          "phases_ms": {name: ns / 1e6 for name, ns in phases_ns.items()},
                          "snapshot_bytes": snapshot_bytes, "allocated_bytes": allocated_bytes, "filled_mib": size // 2,
                          "source_pid": source_proc.pid, "restore_pid": restored_proc.pid,
                          "integrity_verified": True}
                result["samples"].append(sample)
                print(json.dumps(sample), flush=True)
                (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
            finally:
                stop(source_proc)
                stop(restored_proc)
            snapshot.unlink()
        samples = [s for s in result["samples"] if s["memory_mib"] == size and not s["warmup"]]
        row = {"memory_mib": size}
        for name in ("export_ms", "pause_ms", "save_ms", "import_ms", "setup_ms", "process_import_ms", "response_to_verified_ms", "verified_import_ms"):
            values = [s[name] for s in samples]
            row[name] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        row["phases_ms"] = {}
        for name in samples[0]["phases_ms"]:
            values = [s["phases_ms"][name] for s in samples]
            row["phases_ms"][name] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        result["summary"].append(row)
        (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print("SUMMARY " + json.dumps(row), flush=True)
    result["status"] = "passed"
    result["finished_at"] = datetime.now().astimezone().isoformat()
    (work / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    with (work / "phases.csv").open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["memory_mib", "iteration", "warmup", "operation", "phase", "elapsed_ms"])
        for sample in result["samples"]:
            for name, ms in sample["phases_ms"].items():
                operation, phase = name.split(".", 1)
                writer.writerow([sample["memory_mib"], sample["iteration"], sample["warmup"], operation, phase, ms])
    lines = ["# Checkpoint benchmark", "", f"Platform: {result['platform']}; CPU: {result['cpu']}; 2 vCPUs; release build.",
             f"Started: {result['started_at']}; system: {result['system']}; host memory: {result['host_memory']} bytes.",
             f"Source: {result['source_commit']}; dirty: {result['source_dirty']}; library SHA-256: {result['library_sha256']}.",
             "Guest fills half of configured RAM with pseudorandom data. Full logical RAM layout, sparse unused pages. No disks or network.",
             "One warmup excluded; five measured repetitions by default. Warm host file cache before import. Times in milliseconds.",
             "Export includes pause + save + fsync + publication; source stays paused. Import runs from start_enter to guest response.",
             "Process import also includes process launch, dynamic loader, and context setup. Integrity verification follows the first response.",
             "", "| RAM MiB | Pause | Save | Export total | Import to response | Process import | Additional verification |",
             "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in result["summary"]:
        values = [row[name]["median"] for name in ("pause_ms", "save_ms", "export_ms", "import_ms", "process_import_ms", "response_to_verified_ms")]
        lines.append(f"| {row['memory_mib']} | " + " | ".join(f"{value:.3f}" for value in values) + " |")
    lines += ["", "## Total latency ranges (min–max ms)", "", "| RAM MiB | Export | Import | Process import |", "| ---: | ---: | ---: | ---: |"]
    for row in result["summary"]:
        lines.append(f"| {row['memory_mib']} | " + " | ".join(f"{row[name]['min']:.3f}–{row[name]['max']:.3f}" for name in ("export_ms", "import_ms", "process_import_ms")) + " |")
    for operation in ("pause", "save", "restore", "setup"):
        lines += ["", f"## {operation} phases (median ms)", "", "| Phase | " + " | ".join(str(row["memory_mib"]) for row in result["summary"]) + " |",
                  "| --- | " + " | ".join("---:" for _ in result["summary"]) + " |"]
        for name in result["summary"][0]["phases_ms"]:
            if name.startswith(operation + "."):
                lines.append("| " + name.split(".", 1)[1] + " | " + " | ".join(f"{row['phases_ms'][name]['median']:.3f}" for row in result["summary"]) + " |")
    lines += ["", "Each phase median is computed independently; their sum need not equal the median of total time.",
              "Raw samples and min/max: results.json. Every measured phase: phases.csv. Individual process logs: SIZE-ITERATION/{boot,restore}.log."]
    (work / "report.md").write_text("\n".join(lines) + "\n")
    print(f"REPORT {work / 'report.md'}", flush=True)


if __name__ == "__main__":
    main()
