# Memory checkpoints

This workspace adds an experimental version-1 checkpoint container and an online
C API. The shared device and RAM container supports Linux x86_64/KVM and macOS ARM64/HVF.
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
the artifacts. Readers validate format, version, artifact lengths, resource
budgets and saved CPU/device topology before releasing vCPUs. The container no longer stores
SHA-256 checksums for metadata, RAM and disk artifacts; same-length content corruption is
not detected by a checksum. Checkpoint contents must remain unchanged during
import.

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
  return guest errors on subsequent FUSE operations. Resource exhaustion, access
  failures and host I/O errors abort restore without installing partial inode or
  handle tables. Cached guest pages remain part of guest RAM: this is not a
  transactional directory snapshot, and cached
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
| macOS ARM64/HVF | Implemented; native and software GIC, 2-vCPU process-exit/repeated restore tested |

Linux ARM still needs register-list/one-reg capture, CPU power/MPIDR state,
architectural timer state, VGIC distributor/redistributor/CPU-interface state,
and an ARM restore builder.

HVF captures integer, SIMD, system and pointer-authentication registers; SME/SME2
streaming vectors, predicates, ZA and ZT0 when exposed; CPU power state; timer
state; native GIC distributor/redistributor/CPU interfaces or software GIC queues;
and PL011/PL031/PL061 legacy devices. CPU state is accessed on its owning thread.
CPU_ON and WFE waits participate in the acknowledged pause barrier. Pending MMIO
completion is applied exactly once before capture. Virtual counter offsets are
rebased together so guest virtual time excludes the stopped interval; physical
timer deadlines are rebased, while the physical counter remains host time.
The destination must match the exposed CPU features, counter frequency, host page
size and GIC layout. Restore keeps the saved GIC backend. Set `KRUN_HVF_GIC=software`
to select the fallback on a new boot for testing. HVF memory hotplug and more than
one legacy serial endpoint are unsupported; virtio console ports remain supported.


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

### Native HVF checkpoint validation (2026-11-06)

The local Apple Silicon host runs the shared C API fixture in distinct boot,
restore and repeat-restore processes. Both native and software GIC runs verify
memory patterns, two pinned CPU counters, virtual monotonic time excluding an
offline delay, virtio-fs open handles, replaced-object errors and independent disk
images. Corrupt metadata, truncated RAM and incompatible CPU state are rejected;
failed restore joins its CPU/device threads. The export-failure case verifies
source continuation, and the freeze-failure case verifies `-ESHUTDOWN` with the
guest stopped and no published checkpoint.

```sh
# Configure CC_LINUX for a static aarch64 Linux compiler/sysroot first.
cargo build -p libkrun --features blk,net
python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_TSI=1 KRUN_TEST_FAIL_EXPORT=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_HVF_GIC=software KRUN_TEST_NET=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_TSI=1 KRUN_TEST_FLATTEN=/path/to/checkpoint-flatten python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_FREEZE_FAILURE=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
cargo test -p krun-hvf -p krun-vmm -p krun-devices --features blk,net
```

The fixture signs its native host binary with the repository's Hypervisor
entitlement and retains logs/results under `target/run-*`. It uses the local
Linux sysroot to compile its guest. Firmware and the BoxLite checkout are read only.
The old cold-boot-only fixture has been replaced by this shared checkpoint runner.

### Export/import baseline before sparse RAM (2026-11-06)

The following measurements were taken at commit `e93ecf6`, before removing
SHA-256 and adding sparse RAM export/import.

`tests/checkpoint/benchmark.py` runs the same public-API workload on both
platforms, with a release `blk,net` build, two vCPUs, and 256/512/1024/2048 MiB
configured RAM. Each size has one excluded warmup followed by five measurements.
The guest fills half its configured RAM with pseudorandom data; the checkpoint
contains all configured RAM, CPU and device state. This workload uses virtio-fs
and has no attached block image or network backend, so it excludes disk-image
copying/flattening. There is no RAM compression or sparse-page optimization.

Export is host monotonic time around `krun_save_checkpoint`, including freeze,
RAM serialization/checksum, file sync, publication and source resume. Import is
host monotonic time from immediately before `krun_start_enter` until a restored
guest writes its response through virtio-fs (100 us host polling interval and
1 ms guest polling interval). Process startup and configuration are excluded.
The original process has exited before import. Snapshot files are explicitly
read into the host file cache before timing import; these are warm-cache results,
not cold-storage restore measurements. A subsequent full scan checks every
filled guest word, outside the import timer. All measured restores must pass it.

```sh
cargo build --release -p libkrun --features blk,net
# HVF: configure CC_LINUX as above before building.
python3 tests/checkpoint/benchmark.py --firmware /path/to/libkrunfw-directory
# KVM:
LD_LIBRARY_PATH=/path/to/libkrunfw-directory python3 tests/checkpoint/benchmark.py
```

The runner retains individual samples, medians/ranges, library hashes and logs
in `target/checkpoint-benchmark-*`; verified snapshot images are removed after
each iteration to bound disk use.

Measured hosts: HVF uses the local Apple M5 Max (128 GiB RAM, macOS 27.2,
native GIC, APFS). KVM uses an Intel Xeon 2.80 GHz host (8 logical CPUs,
31 GiB reported RAM, Ubuntu Linux, GCP Persistent Disk). The KVM host is itself
a virtual machine, so this run uses nested virtualization. Neither host was
reserved exclusively for this benchmark. These are deployment-specific latency
measurements, not an isolated comparison of hypervisor overhead.

Seconds, median of five measurements; parentheses show minimum–maximum:

| Platform | RAM (MiB) | Export (s) | Warm-cache import (s) |
| --- | ---: | ---: | ---: |
| KVM | 256 | 2.514 (2.491–2.519) | 3.076 (3.051–3.209) |
| KVM | 512 | 5.067 (5.053–5.130) | 6.200 (6.106–6.396) |
| KVM | 1024 | 10.146 (10.084–10.360) | 12.606 (12.219–13.028) |
| KVM | 2048 | 19.970 (19.832–20.606) | 25.955 (25.694–27.659) |
| HVF | 256 | 0.507 (0.507–0.509) | 0.984 (0.978–0.986) |
| HVF | 512 | 1.010 (1.000–1.015) | 1.939 (1.932–1.953) |
| HVF | 1024 | 1.944 (1.938–1.956) | 3.870 (3.860–3.884) |
| HVF | 2048 | 3.852 (3.844–3.878) | 7.720 (7.628–7.734) |

All 40 measured restores and eight warmups passed the full guest-pattern scan.

A separate one-second sampling window during the beginning of a 1 GiB HVF
import found 667 of 677 main-thread samples in SHA-256 compression (98.5%).
This diagnostic run is excluded from the table. That build's `sha2 0.10.9`
feature set does not enable `asm`, which selects its software backend on
AArch64. Import also hashes RAM twice: the artifact scan and verification of
the bytes actually read into memory. These identify concrete optimization
opportunities; the measurements above use the unchanged snapshot implementation.

### Sparse anonymous RAM

Whole-VM export streams RAM through a 1 MiB buffer instead of constructing a
RAM-sized `Vec`. It queries page allocation before reading private anonymous
regions: Linux uses `/proc/self/pagemap` and retains present **or swapped** pages;
macOS uses `mach_vm_page_range_query` and retains every nonzero disposition,
including compressed/paged-out pages. Only confirmed unallocated pages are
omitted. Allocated pages containing all zeroes are still written; no zero-page
content scan is performed. These queries do not identify guest-OS free pages.
All guest/device writers stay frozen through the query and copy.

If page-state queries fail, or a mapping is not private anonymous memory, export
copies the region in full. The snapshot is a sparse file with the same logical
RAM byte layout as before; physical disk use depends on filesystem support.
Import reads its `SEEK_DATA`/`SEEK_HOLE` extents into fresh anonymous memory and
leaves holes as zero-filled anonymous pages. Unsupported sparse seeking falls
back to full reads. All saved data is loaded before vCPUs resume: this is eager
restore, with no snapshot-file mapping or userfaultfd. Existing plugged-memory
streaming remains unchanged apart from removal of its checksum.

The standalone in-memory RAM codec still uses version 1 and remains byte-compatible
with the sparse RAM file. The whole-VM container remains experimental version 1: its header is
16 bytes, followed by JSON metadata, and artifacts record names and lengths only.

The benchmark now reports both logical snapshot bytes and `st_blocks * 512`
allocated bytes. Earlier baseline results above retain their original meanings.

Post-change performance uses the same hosts, release build, two vCPUs,
half-filled pseudorandom guest memory and warm-cache import as the baseline.
Each value is the median of five measured iterations. Allocated MiB includes
RAM and state files; logical file size is still approximately configured RAM.

| Platform | RAM (MiB) | Export (ms) | Import (ms) | Allocated (MiB) |
| --- | ---: | ---: | ---: | ---: |
| KVM | 256 | 645.6 | 168.9 | 166.1 |
| KVM | 512 | 1189.2 | 272.8 | 299.2 |
| KVM | 1024 | 2273.7 | 469.7 | 564.5 |
| KVM | 2048 | 4281.6 | 878.5 | 1094.3 |
| HVF | 256 | 61.4 | 21.9 | 171.4 |
| HVF | 512 | 95.4 | 31.4 | 314.2 |
| HVF | 1024 | 165.2 | 54.5 | 585.1 |
| HVF | 2048 | 307.0 | 99.8 | 1102.6 |
