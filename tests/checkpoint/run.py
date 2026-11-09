#!/usr/bin/env python3
"""Linux/KVM process-exit/restore regression using the public C API.

Build libkrun with blk,net first. Set LD_LIBRARY_PATH to a libkrunfw.so.5
directory. Artifacts and logs remain under target/run-* for inspection.
"""
import platform
import errno
import sys
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

repo = Path(__file__).resolve().parents[2]
work = Path(tempfile.mkdtemp(prefix="run-", dir=(repo / "target")))
root = work / "root"
root.mkdir()
for name in ("dev", "proc", "sys", "tmp", "run", "etc"):
    (root / name).mkdir()
if os.environ.get("KRUN_TEST_DAX"):
    (root / "dax-test").touch()
    (root / "dax-share").mkdir()
    (root / "dax-share/readonly").write_bytes(b"R" + bytes(65535))
library = work / "lib"
library.mkdir()
hvf = platform.system() == "Darwin"
host = work / "host"
if hvf:
    firmware = Path(sys.argv[1]).resolve()
    assert (firmware / "libkrunfw.5.dylib").is_file()
    for name in ("libkrun.dylib", "libkrun.1.dylib"):
        (library / name).symlink_to(repo / "target/debug/libkrun.dylib")
    sysroot = repo / "linux-sysroot"
    gcc = sysroot / "usr/lib/gcc/aarch64-linux-gnu/12"
    subprocess.run(["/usr/bin/clang", "-target", "aarch64-linux-gnu", "-fuse-ld=/opt/homebrew/opt/lld/bin/ld.lld", f"--sysroot={sysroot}", f"-B{gcc}", f"-L{gcc}", "-static", "-O2", "-pthread", str(Path(__file__).with_name("guest.c")), "-o", str(root / "checkpoint-guest")], check=True)
    os.environ["DYLD_LIBRARY_PATH"] = f"{library}:{firmware}"
else:
    for name in ("libkrun.so", "libkrun.so.1"):
        (library / name).symlink_to(repo / "target/debug/libkrun.so")
    subprocess.run(["cc", "-O2", "-static", "-pthread", str(Path(__file__).with_name("guest.c")), "-o", str(root / "checkpoint-guest")], check=True)
subprocess.run(["cc", "-O2", "-pthread", "-I", str(repo / "include"), str(Path(__file__).with_name("host.c")), "-L", str(library), "-lkrun", f"-Wl,-rpath,{library}", "-o", str(host)], check=True)
if hvf:
    subprocess.run(["codesign", "--entitlements", str(repo / "hvf-entitlements.plist"), "--force", "-s", "-", str(host)], check=True)
disk = work / "disk.raw"
with disk.open("wb") as file:
    file.truncate((64 if os.environ.get("KRUN_TEST_BLOCK_ROOT") else 8) * 1024 * 1024)
    file.seek(4096)
    file.write(b"\x37" * 512)
base_disk = disk
processes = []
backends = []
saved_disks = {}
live_disks = {}


class EchoBackend:
    def __init__(self, path):
        self.path = path
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(1)
        self.closed = False
        self.frames = 0
        self.connection = None
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        def read_exact(connection, length):
            data = b""
            while len(data) < length:
                part = connection.recv(length - len(data))
                if not part:
                    raise EOFError
                data += part
            return data
        try:
            connection, _ = self.listener.accept()
            self.connection = connection
            with connection:
                while True:
                    length, = struct.unpack("!I", read_exact(connection, 4))
                    assert length <= 65536
                    data = bytearray(read_exact(connection, length))
                    if data[12:14] == b"\x88\xb5":
                        data[:6] = data[6:12]
                        data[6:12] = b"\x02\0\0\0\0\x02"
                        connection.sendall(struct.pack("!I", len(data)) + data)
                        self.frames += 1
        except (EOFError, OSError):
            pass
        finally:
            self.closed = True

    def close(self):
        self.listener.close()
        if self.connection:
            self.connection.close()


class TsiBackend:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", self.port))
        self.connections = []
        threading.Thread(target=self.accept, daemon=True).start()
        threading.Thread(target=self.datagrams, daemon=True).start()

    def accept(self):
        try:
            while True:
                connection, _ = self.listener.accept()
                self.connections.append(connection)
                threading.Thread(target=self.echo, args=(connection,), daemon=True).start()
        except OSError:
            pass

    def echo(self, connection):
        try:
            with connection:
                while data := connection.recv(4096):
                    connection.sendall(data)
        except OSError:
            pass

    def datagrams(self):
        try:
            while True:
                data, address = self.udp.recvfrom(4096)
                self.udp.sendto(data, address)
        except OSError:
            pass

    def close(self):
        self.listener.close()
        self.udp.close()
        for connection in self.connections:
            connection.close()

if os.environ.get("KRUN_TEST_TSI"):
    tsi = TsiBackend()
    backends.append(tsi)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    (root / "tsi-ports").write_text(f"{tsi.port} {port}\n")


def text(path):
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def start(mode, checkpoint, next_checkpoint=None, missing_disk=False):
    number = len(processes)
    log = work / f"host-{number}.log"
    console = work / f"console-{number}.log"
    env = os.environ.copy()
    if next_checkpoint:
        env["KRUN_TEST_NEXT_CHECKPOINT"] = str(next_checkpoint)
    image = disk
    if mode == "restore":
        env.pop("KRUN_TEST_FAIL_EXPORT", None)
        image = work / f"restore-disk-{number}.img"
        shutil.copyfile(saved_disks.get(checkpoint, saved_disks.get(work / "checkpoint-1")), image)
    if missing_disk:
        env["KRUN_TEST_MISSING_DISK"] = "1"
    if env.get("KRUN_TEST_NET"):
        backend = EchoBackend(work / f"net-{number}.sock")
        backends.append(backend)
        env["KRUN_TEST_NET_SOCKET"] = str(backend.path)
    with log.open("wb") as output:
        process = subprocess.Popen([str(host), mode, str(root), str(checkpoint), str(console), str(image)], stdout=output, stderr=subprocess.STDOUT, env=env)
    processes.append(process)
    live_disks[process.pid] = image
    return process, log, console


def wait(predicate, process, logs, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        if process.poll() is not None:
            break
        time.sleep(.05)
    raise AssertionError(f"guest/control did not progress; exit={process.poll()}\n" + "\n".join(text(log)[-6000:] for log in logs) + "\n" + text(root / "failure"))


def checkpoint_state(path):
    with path.open("rb") as file:
        header = file.read(16)
        magic, version, length = struct.unpack("<8sII", header)
        assert magic == b"KRUNVM\0\0" and version == 2
        return json.loads(file.read(length))


def save_paused(process, checkpoint, log, console, expected=0):
    previous = text(log).count("CHECKPOINT ")
    process.send_signal(signal.SIGUSR1)
    wait(lambda: text(log).count("CHECKPOINT ") > previous, process, [log, console])
    assert f"CHECKPOINT {expected}" in text(log).splitlines()[-1], text(log)
    progress = guest_output()
    time.sleep(.2)
    assert guest_output() == progress, "guest progressed while paused"
    if expected == 0:
        assert checkpoint.is_file(), "checkpoint must be a single file"
        image = work / f"{checkpoint.name}.disk"
        if os.environ.get("KRUN_TEST_FLATTEN"):
            subprocess.run([os.environ["KRUN_TEST_FLATTEN"], "flatten", str(live_disks[process.pid]), str(image)], check=True)
        else:
            shutil.copyfile(live_disks[process.pid], image)
        saved_disks[checkpoint] = image
        state = checkpoint_state(checkpoint)
        assert all(d["state"]["kind"] != "Block" or isinstance(d["state"]["state"], dict) for d in state["devices"])
        assert "disk_image_path" not in json.dumps(state)


def resume(process, log, console):
    previous = text(log).count("RESUME ")
    process.send_signal(signal.SIGUSR2)
    wait(lambda: text(log).count("RESUME ") > previous, process, [log, console])
    assert text(log).splitlines()[-1] == "RESUME 0", text(log)


def guest_output():
    if os.environ.get("KRUN_TEST_BLOCK_ROOT"):
        return "".join(text(work / f"console-{n}.log") for n in range(len(processes)))
    return text(root / "progress")


def ticks():
    return [list(map(int, line.split()[1:])) for line in guest_output().splitlines() if line.startswith("TICK ")]


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


try:
    if os.environ.get("KRUN_TEST_BLOCK_ROOT"):
        (root / "block-root").touch()
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(root), str(base_disk)], check=True)
    if os.environ.get("KRUN_TEST_FLATTEN"):
        disk = work / "disk.qcow2"
        subprocess.run([os.environ["KRUN_TEST_FLATTEN"], "overlay", str(base_disk), str(disk)], check=True)
    first = work / "checkpoint-1"
    source, log, console = start("boot", first)
    wait(lambda: len(ticks()) > 5, source, [log, console])
    original = ticks()[-1]
    if os.environ.get("KRUN_TEST_NET"):
        wait(lambda: ticks()[-1][7] > 3, source, [log, console])
    assert original[1] > 0 and original[2] > 0 and original[5] == 1, original
    if os.environ.get("KRUN_TEST_TSI"):
        wait(lambda: ticks()[-1][8] > 3 and ticks()[-1][11] > 3 and (os.environ.get("KRUN_TEST_BLOCK_ROOT") or (root / "accept-ready").exists()), source, [log, console])
    if os.environ.get("KRUN_TEST_FREEZE_FAILURE"):
        # Rename this fixture's share so filesystem capture fails after vCPUs
        # and preceding devices have stopped. The API must return, not deadlock
        # while cleanup reacquires the failing device's mutex.
        hidden = work / "renamed-root"
        root.rename(hidden)
        source.send_signal(signal.SIGUSR1)
        wait(lambda: f"CHECKPOINT {-errno.ESHUTDOWN}" in text(log), source, [log, console], timeout=15)
        stopped = text(hidden / "progress")
        time.sleep(.2)
        assert text(hidden / "progress") == stopped
        assert not first.exists()
        result = {"status": "passed", "freeze_failure_returned": True,
                  "guest_stayed_stopped": True, "work": str(work)}
        (work / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        raise SystemExit(0)
    if os.environ.get("KRUN_TEST_FAIL_EXPORT"):
        save_paused(source, first, log, console, -errno.ENOENT)
        assert not first.exists()
        resume(source, log, console)
        progress = len(ticks())
        wait(lambda: len(ticks()) > progress + 3, source, [log, console])
    save_paused(source, first, log, console)
    if os.environ.get("KRUN_TEST_EXTRA_FS"):
        saved = checkpoint_state(first)
        assert len(saved["devices"]) > 24, "fixture did not exceed the previous device limit"

    if os.environ.get("KRUN_TEST_DAX"):
        saved = checkpoint_state(first)
        fs = next(d["state"]["state"] for d in saved["devices"]
                  if d["state"]["kind"] == "Fs" and d["state"]["state"]["tag"] == "dax-test")
        assert fs["dax_window"]["size"] == 8 * 1024 * 1024
        mappings = fs["worker"]["filesystem"]["mappings"]
        assert any(m["writable"] for m in mappings), "missing writable DAX mapping"
        assert any(not m["writable"] for m in mappings), "missing read-only DAX mapping"
        assert saved["ram_len"] < 257 * 1024 * 1024, "DAX windows entered RAM export"
    save_paused(source, first, log, console, -errno.EEXIST)
    resume(source, log, console)
    at_save = len(ticks())
    wait(lambda: len(ticks()) > at_save + 3, source, [log, console])
    stop(source)  # Source process has exited before any restore starts.
    if os.environ.get("KRUN_TEST_DAX"):
        # The shared directory stays live; restored CPU mappings must observe host edits.
        # Derive the guest's page size from the three-page test file.
        page = (root / "dax-share/mapped").stat().st_size // 3
        with (root / "dax-share/mapped").open("r+b") as file:
            file.seek(2 * page + 32); file.write(b"\x5a")
        with (root / "dax-share/readonly").open("r+b") as file:
            file.seek(1); file.write(b"\x6b")
    before_restore = len(ticks())
    if not os.environ.get("KRUN_TEST_BLOCK_ROOT"):
        (root / "gone").unlink()
        (root / "gone").write_bytes(b"replacement must not receive old handle operations")
    with base_disk.open("r+b") as file:
        file.seek(4096)
        file.write(b"\xee" * 512)
    with disk.open("r+b") as file:
        file.write(b"\xee" * 512)

    if hvf:
        time.sleep(1.1)  # guest virtual time must exclude the offline interval
    second = work / "checkpoint-2"
    target, log, console = start("restore", first, second)
    # Import loads saved RAM before entering the guest. Keep startup separate
    # from the short deadline for an already-running guest.
    wait(lambda: len(ticks()) > before_restore + 5, target, [log, console], timeout=180)
    if os.environ.get("KRUN_TEST_DAX"):
        wait(lambda: (root / "dax-observed").exists(), target, [log, console])
        with (root / "dax-share/readonly").open("r+b") as file:
            file.seek(2); file.write(b"\x7c")
        wait(lambda: (root / "dax-live-observed").exists(), target, [log, console])
    after = ticks()[before_restore:]
    if hvf:
        assert after[0][3] - ticks()[before_restore - 1][3] < 750_000_000, after[0]
    if os.environ.get("KRUN_TEST_HOTPLUG"):
        assert all(row[6] == 1 for row in after), after
    assert all(row[0] == original[0] and row[5] == 1 for row in after), after
    if not os.environ.get("KRUN_TEST_BLOCK_ROOT"):
        assert any(row[4] != 0 for row in after), after
    assert guest_output().count("BOOT ") == 1
    if os.environ.get("KRUN_TEST_NET"):
        wait(lambda: backends[0].closed and backends[1].frames > 3 and ticks()[-1][7] > after[0][7], target, [log, console])
    if os.environ.get("KRUN_TEST_TSI"):
        initial = ticks()[-1]
        wait(lambda: ticks()[-1][8] > initial[8] + 3 and ticks()[-1][11] > initial[11] + 3
             and ticks()[-1][9] > 0 and ticks()[-1][10] > 0, target, [log, console])
    save_paused(target, second, log, console)
    stop(target)
    before_repeat = len(ticks())
    repeated, log, console = start("restore", second)
    wait(lambda: len(ticks()) > before_repeat + 5, repeated, [log, console], timeout=180)
    rows = ticks()[before_repeat:]
    assert rows[-1][1] > rows[0][1] and rows[-1][2] > rows[0][2], rows
    assert all(row[0] == original[0] for row in rows)
    assert guest_output().count("BOOT ") == 1
    if os.environ.get("KRUN_TEST_TSI"):
        initial = ticks()[-1]
        wait(lambda: ticks()[-1][8] > initial[8] + 3 and ticks()[-1][11] > initial[11] + 3
             and ticks()[-1][9] >= 2 and ticks()[-1][10] >= 2, repeated, [log, console])
    stop(repeated)

    # Missing or capacity-mismatched disks must be rejected before execution.
    progress = len(ticks())
    missing, log, console = start("restore", first, missing_disk=True)
    assert missing.wait(timeout=15) != 0
    assert "matching caller-provided disks" in text(log), text(log)
    assert len(ticks()) == progress
    original_disk = saved_disks[first]
    small_disk = work / "small.raw"
    small_disk.write_bytes(bytes(4096))
    if not os.environ.get("KRUN_TEST_FLATTEN"):
        saved_disks[first] = small_disk
        wrong, log, console = start("restore", first)
        assert wrong.wait(timeout=30) != 0
        assert len(ticks()) == progress
        saved_disks[first] = original_disk

    corrupt = work / "corrupt"
    with first.open("rb") as file:
        header = file.read(16)
    corrupt.write_bytes(bytes([header[0] ^ 1]) + header[1:])
    bad, log, console = start("restore", corrupt)
    assert bad.wait(timeout=15) != 0
    assert "invalid checkpoint header" in text(log), text(log)
    corrupt_ram = work / "corrupt-ram"
    with first.open("rb") as file:
        metadata_len = struct.unpack("<I", file.read(16)[12:])[0]
        file.seek(0)
        corrupt_ram.write_bytes(file.read(16 + metadata_len + 4096))
    bad_ram, log, console = start("restore", corrupt_ram)
    assert bad_ram.wait(timeout=15) != 0
    assert "payload length mismatch" in text(log), text(log)
    incompatible = work / "incompatible-cpu"
    state = checkpoint_state(first)
    if hvf:
        state["cpus"][0]["cpu"]["frequency"] += 1
    else:
        state["cpus"][0]["tsc_khz"] += 1
    payload = json.dumps(state, separators=(",", ":")).encode()
    with first.open("rb") as source_file, incompatible.open("wb") as target_file:
        original_header = source_file.read(16)
        length = struct.unpack("<I", original_header[12:])[0]
        source_file.seek(16 + length)
        target_file.write(original_header[:12] + struct.pack("<I", len(payload)) + payload)
        shutil.copyfileobj(source_file, target_file)
    progress = len(ticks())
    bad_cpu, log, console = start("restore", incompatible)
    assert bad_cpu.wait(timeout=180) != 0
    assert ("incompatible HVF CPU state" if hvf else "incompatible TSC frequency") in text(log), text(log)
    assert len(ticks()) == progress
    if os.environ.get("KRUN_TEST_NET"):
        wait(lambda: backends[-1].closed, bad_cpu, [log, console])
    if os.environ.get("KRUN_TEST_DAX"):
        mapped = root / "dax-share/mapped"
        contents = mapped.read_bytes()
        mapped.write_bytes(b"truncated")
        progress = len(ticks())
        bad_dax, log, console = start("restore", first)
        assert bad_dax.wait(timeout=30) != 0
        assert len(ticks()) == progress, "vCPUs resumed with truncated DAX backing"
        mapped.write_bytes(contents)
        mapped.rename(mapped.with_name("original"))
        mapped.write_bytes(contents)
        bad_dax, log, console = start("restore", first)
        assert bad_dax.wait(timeout=30) != 0
        assert len(ticks()) == progress, "vCPUs resumed with replaced DAX backing"

    result = {"status": "passed", "platform": "macos-aarch64-hvf" if hvf else "linux-x86_64-kvm", "source_pid": source.pid, "restore_pid": target.pid, "repeat_pid": repeated.pid,
              "nonce": original[0], "vcpus": 2, "virtio_fs_stale_handle": not bool(os.environ.get("KRUN_TEST_BLOCK_ROOT")), "external_disk": "qcow2-flatten" if os.environ.get("KRUN_TEST_FLATTEN") else "raw",
              "single_file": True, "save_requires_pause": True, "save_preserves_pause": True, "missing_disk_rejected": True,
              "corrupt_metadata_rejected": True, "truncated_ram_rejected": True, "failed_restore_joined": True, "work": str(work)}
    if hvf:
        saved_platform = checkpoint_state(first)["vm"]
        result["gic"] = "native" if saved_platform["native_gic"] else "software"
        result["virtual_clock_excludes_offline"] = True
    result["dax_mapping_restore"] = bool(os.environ.get("KRUN_TEST_DAX"))
    result["ext4_rootfs"] = bool(os.environ.get("KRUN_TEST_BLOCK_ROOT"))
    result["tsi_tcp_accept_udp"] = bool(os.environ.get("KRUN_TEST_TSI"))
    result["hotplug_384_mib"] = bool(os.environ.get("KRUN_TEST_HOTPLUG"))
    result["failed_export_kept_paused_then_resumed"] = bool(os.environ.get("KRUN_TEST_FAIL_EXPORT"))
    result["fresh_net_backend"] = bool(os.environ.get("KRUN_TEST_NET"))
    (work / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
finally:
    for process in processes:
        if process.poll() is None:
            stop(process)
    for backend in backends:
        backend.close()
    print(f"Evidence: {work}", flush=True)
