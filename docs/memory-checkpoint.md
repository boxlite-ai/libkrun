# Memory checkpoints

This workspace adds an experimental version-1 checkpoint container and an online
C API. The implementation is based on `7a897cdf742e0c603b498509eec3a9d8ffeca13b`.
A checkpoint includes RAM, vCPU/VM/clock/interrupt state, the device topology and
state, and independent block images. Restore constructs a stopped VM directly
from that state; it does not run the boot loader over restored memory.

## API

Before starting a source VM:

```c
int ctx = krun_create_ctx();
krun_set_vm_config(ctx, 2, 256);
krun_set_root(ctx, "/path/to/rootfs");
/* Configure execution, disks, consoles, network and optional hotplug normally. */
krun_set_checkpointing(ctx, true);
krun_start_enter(ctx);
```

`krun_start_enter` still consumes the configuration and owns the calling thread.
A separate host thread calls:

```c
int rc = krun_save_checkpoint(ctx, "/path/to/new-checkpoint", flatten, opaque);
```

The context ID remains valid for this request. The call is synchronous, including
all flatten callbacks. Concurrent requests return `-EBUSY`. The destination must
not exist. Successful publication uses an atomic directory rename after syncing
the artifacts. RAM and metadata have checksums; readers reject incompatible,
truncated or changed artifacts before releasing vCPUs.

On success, the original VM resumes. A file/export failure after a confirmed
freeze also resumes it. `-ESHUTDOWN` is reserved for an unusable VM: vCPUs remain
stopped, uncertain workers are stopped/joined, and the embedding process must be
torn down. Later requests cannot resume it. Network streams may be disconnected
by a checkpoint attempt even when the attempt fails.

To restore in a new process:

```c
int ctx = krun_create_ctx();
krun_set_vm_config(ctx, 2, 256);
krun_set_root(ctx, "/path/to/the-same-rootfs");
/* Bind fresh console/network endpoints, and matching hotplug configuration. */
krun_set_checkpoint_restore(ctx, "/path/to/checkpoint");
krun_start_enter(ctx);
```

The configured memory size is an allocation budget for the saved boot RAM.
Hotplug's initial/max sizes must match. CPU count and MMIO/GPA/IRQ topology come
from the checkpoint. Block devices are recreated from the packaged images, not
from source disk paths. A block-root boot's deleted bootstrap virtio-fs root is
recreated internally; the restore caller need not configure that retired root.

## Resources and consistency

- Block workers finish the current request and flush/sync before capture. The
  application must exclude other writers to the disk and its backing chain
  during capture. The
  callback receives `(device_id, source, destination, format, opaque)` and must
  create an independent image of the same format and capacity. Return zero or a
  negative errno. Do not modify the source or reenter VM control in the callback.
  A null callback copies raw images; QCOW2 requires the application's existing
  flatten function. Restore makes a private writable copy, so repeated restores
  cannot mutate checkpoint artifacts. Guest disk IDs stay unchanged.
- BoxLite's existing `Qcow2Helper::flatten` is the intended QCOW2 callback. The
  reviewable patch in `patches/boxlite-flatten-tail-and-zero-clusters.patch` fixes
  short final clusters written by imago and explicit QCOW2 zero clusters. It
  modifies that existing function, not the image format or snapshot mechanism.
  The main BoxLite checkout has not been changed. Apply the patch there before
  using that helper for general QCOW2 checkpoint export.
- Virtio-fs uses the same host directory's live contents. Inodes and handles are
  rebound by path and identity, never by old FD numbers. Deleted/replaced objects
  return guest errors on subsequent FUSE operations. Cached guest pages remain
  part of guest RAM: this is not a transactional directory snapshot, and cached
  reads need not immediately notice host changes. Without inode birth times,
  identity checking conservatively treats changed ctimes as stale. DAX and
  exported guest-memory aliases are excluded; checkpoint-enabled boot does not
  allocate fs DAX windows.
- TSI/vsock closes stream sockets, sends transport reset, and completes pending
  connect/listen/accept/getname control requests with errors. Fresh connections
  can then be established. UDP endpoints are reopened from address configuration;
  queued host datagrams are lost, and an occupied local endpoint fails restore.
  Applications must tolerate UDP loss. Unix IPC listening paths are rebound;
  a conflicting path is an error, not a silently missing listener.
- Virtio-net uses a fresh caller-provided backend with matching identity/features.
  Pending old TX is dropped and queues are rescanned. Existing external sessions
  are not checkpointed; reconnection and packet loss/timeouts belong to the
  application/network backend. The caller must not attach two restored guests
  with the same MAC/IP to a shared network simultaneously.
- Console endpoint kinds and ports must match. Partly transmitted guest output
  resumes at its saved offset; bytes already sent to an external terminal cannot
  be undone. Host input not yet consumed at capture is external state.
- Online hotplug requests share the freeze boundary. Only mapped slots are copied;
  PROT_NONE reservations, KVM slots, plugged bitmap and requested target are
  restored separately. No attempt is made to read an inaccessible reservation.
- KVM guest monotonic time excludes time spent offline. vCPU TSC offsets use a
  common VM clock sample to preserve relative offsets. The destination must have
  compatible CPU/MSR/XSAVE capabilities, equal TSC frequency, and KVM clock/TSC
  offset support. Wall-clock policy of guest applications is still their own.

## Support boundaries

| Configuration | Current status |
| --- | --- |
| Linux x86_64, KVM, ordinary RAM | Implemented; actual SSH/KVM execution tested |
| console, block raw/QCOW2, fs, TSI/vsock, virtio-net, rng, balloon free-page reporting, virtio-mem | Connected to capture/restore |
| nested virtualization, split irqchip, TEE | Unsupported |
| GPU/input/sound and unrecognized devices, exported/shared guest mappings | Rejected; device/resource state is not silently discarded |
| VMDK checkpoint export | Unsupported |
| Linux aarch64 | Whole-VM checkpoint API returns `-ENOTSUP`; cross-compilation is not runtime validation |
| macOS/HVF | Native 2-vCPU cold boot/I/O/exit tested; whole-VM checkpoint API returns `-ENOTSUP` |

Linux ARM still needs register-list/one-reg capture, CPU power/MPIDR state,
architectural timer state, VGIC distributor/redistributor/CPU-interface state,
and an ARM restore builder. HVF still needs acknowledged thread pause across
boot/WFE waits, integer/SIMD/system registers, virtual timer state and GIC state
(including the software GIC fallback), plus its own restore builder. The existing
empty macOS pause/resume paths are not represented as supported checkpointing.

The container is versioned but is not yet a stable cross-release migration ABI.
This does not claim all originally requested platforms/configurations complete.

## Validation

`tests/checkpoint/host.c` calls the public C API. `guest.c` checks memory patterns,
two pinned CPU counters, monotonic time, open-file I/O, direct block I/O or ext4
rootfs I/O, and optional network/hotplug workloads. `run.py` exits the original
process before restore, repeats save/restore, tests a duplicate destination and
corrupt inputs, and retains JSON results and logs under `target/run-*`.

On Linux x86_64 with `/dev/kvm` and a matching `libkrunfw.so.5`:

```sh
cargo build -p libkrun --features blk,net
LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_NET=1 KRUN_TEST_FAIL_EXPORT=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_TSI=1 KRUN_TEST_FREEZE_FAILURE=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
```

For QCOW2, build the adapter around the existing BoxLite source; it applies the
patch only to a copy under this workspace's ignored `target` directory:

```sh
python3 tests/checkpoint/build-flatten.py /path/to/boxlite
export KRUN_TEST_FLATTEN="$PWD/target/checkpoint-flatten/target/release/checkpoint-flatten"
KRUN_TEST_TSI=1 KRUN_TEST_BLOCK_ROOT=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_TSI=1 KRUN_TEST_HOTPLUG=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
```

Hotplug requires guest firmware with `CONFIG_VIRTIO_MEM=y`; the host flag
`plugged_mib` can precede the guest's memory-online work. The test waits until the
guest can allocate and touch 300 MiB before capturing a 256-to-384 MiB VM.
The block-root fixture requires `mkfs.ext4` and tests its own generated rootfs.

The authorized KVM machine is SSH host `eric-kvm-dev`. The isolated test copy is
`/tmp/libkrun-memory-complete.PPL5Uv`. No commit, push, PR or deployment is part of
this work.

### Recorded runs (2026-11-06)

Local review artifacts are under `target/checkpoint-validation/` (ignored by git).
These are actual KVM runs on `eric-kvm-dev`, each using distinct source/restore
process IDs; each normal run also performs a second save/restore.

| Run | Evidence |
| --- | --- |
| ext4 rootfs + existing QCOW2 flatten + TSI TCP/accept/UDP | [result](../target/checkpoint-validation/ext4-rootfs.json) |
| 256-to-384 MiB hotplug + 300 MiB guest pattern + fs + QCOW2 + TSI | [result](../target/checkpoint-validation/hotplug-tsi-qcow2.json) |
| virtio-net fresh backend + failed export/source continuation + incompatible CPU restore cleanup | [result](../target/checkpoint-validation/net-export-failure.json) |
| default TSI + failed export/source continuation | [result](../target/checkpoint-validation/tsi-export-failure.json) |
| failure during device freeze returns `-ESHUTDOWN`, guest stays stopped | [result](../target/checkpoint-validation/freeze-failure.json) |

Linux device tests: 133 passed. Linux VMM tests: 34 passed, one pre-existing test
ignored. Existing flatten tests with the compatibility patch: 5 passed on Linux
and macOS. Native macOS device tests: 103 passed. Linux aarch64 GNU and native
macOS library checks passed; neither provides whole-VM ARM/HVF restore evidence.
`cargo fmt --check`, Python fixture syntax checks and `git diff --check` passed.

### Native HVF execution check

On the local Apple Silicon host (macOS 27.2), the current workspace library and
an existing local ARM firmware booted a real Linux guest with two pinned CPU
threads. It completed 32 iterations of memory-pattern checks, virtio-fs file
read/write/fsync, direct raw-block write/read verification and monotonic-clock
checks, then exited with status zero. This is cold-boot execution evidence, not
snapshot/restore evidence. All three checkpoint API entry points returned
`-ENOTSUP` (`-45` on macOS), including save from a separate host thread while the
guest was running.

Reproduce with the locally built library and the existing Linux sysroot:

```sh
cargo build -p libkrun --features blk,net
python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
```

[HVF result](../target/checkpoint-validation/hvf/result.json),
[host log](../target/checkpoint-validation/hvf/host.log).
The fixture signs its own native host binary with the repository's Hypervisor
entitlement. Firmware and other workspaces are read only.
