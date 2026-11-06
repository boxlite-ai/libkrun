#!/usr/bin/env python3
"""Run the shared Linux guest on native macOS HVF using this workspace's library.

Usage: python3 tests/checkpoint/run-hvf.py /directory/containing/libkrunfw.5.dylib
Requires cargo build -p libkrun --features blk,net and the local Linux sysroot.
This verifies cold boot and explicitly verifies that checkpoint APIs are unsupported.
"""
import errno
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

assert platform.system() == "Darwin" and platform.machine() == "arm64"
repo = Path(__file__).resolve().parents[2]
firmware = Path(sys.argv[1]).resolve()
assert (firmware / "libkrunfw.5.dylib").is_file()
work = Path(tempfile.mkdtemp(prefix="hvf-run-", dir=repo / "target"))
root = work / "root"
root.mkdir()
for directory in ("dev", "proc", "sys", "tmp", "run", "etc"):
    (root / directory).mkdir()
sysroot = repo / "linux-sysroot"
gcc = sysroot / "usr/lib/gcc/aarch64-linux-gnu/12"
subprocess.run(["/usr/bin/clang", "-target", "aarch64-linux-gnu",
                "-fuse-ld=/opt/homebrew/opt/lld/bin/ld.lld", f"--sysroot={sysroot}",
                f"-B{gcc}", f"-L{gcc}", "-static", "-O2", "-pthread",
                str(Path(__file__).with_name("guest.c")), "-o", str(root / "checkpoint-guest")], check=True)
library = work / "lib"
library.mkdir()
(library / "libkrun.1.dylib").symlink_to(repo / "target/debug/libkrun.dylib")
host = work / "host"
subprocess.run(["/usr/bin/clang", "-O2", "-pthread", "-I", str(repo / "include"),
                str(Path(__file__).with_name("hvf-host.c")), "-L", str(repo / "target/debug"),
                "-lkrun", "-o", str(host)], check=True)
subprocess.run(["codesign", "--entitlements", str(repo / "hvf-entitlements.plist"),
                "--force", "-s", "-", str(host)], check=True)
disk = work / "disk.raw"
with disk.open("wb") as file:
    file.truncate(8 * 1024 * 1024)
    file.seek(4096)
    file.write(b"\x37" * 512)
env = os.environ.copy()
env["DYLD_LIBRARY_PATH"] = f"{library}:{firmware}"
print(f"Evidence: {work}", flush=True)
with (work / "host.log").open("wb") as log:
    completed = subprocess.run([str(host), str(root), str(work / "console.log"), str(disk)],
                               env=env, stdout=log, stderr=subprocess.STDOUT, timeout=60)
assert completed.returncode == 0, (completed.returncode, (work / "host.log").read_text())
rows = [list(map(int, line.split()[1:])) for line in (root / "progress").read_text().splitlines()
        if line.startswith("TICK ")]
assert len(rows) == 32, len(rows)
assert rows[-1][1] > rows[0][1] and rows[-1][2] > rows[0][2], rows
assert all(row[0] == rows[0][0] and row[4] == 0 and row[5] == 1 for row in rows)
assert all(after[3] >= before[3] for before, after in zip(rows, rows[1:]))
assert int((root / "api-result").read_text()) == -errno.ENOTSUP
assert not (root / "failure").exists()
result = {"status": "passed", "platform": "macOS arm64/HVF", "vcpus": 2,
          "guest_ticks": len(rows), "memory_pattern": True, "virtio_fs_io": True,
          "raw_block_io": True, "monotonic_clock": True, "guest_exit": 0,
          "checkpoint_api_errno": -errno.ENOTSUP, "checkpoint_restore_supported": False,
          "library": str(repo / "target/debug/libkrun.dylib"), "firmware": str(firmware), "work": str(work)}
(work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
