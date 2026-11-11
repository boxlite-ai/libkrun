# Memory checkpoints

The experimental version-2 checkpoint is one file containing RAM,
vCPU/VM/clock/interrupt state, and device topology and state. It supports
Linux x86_64/KVM and macOS ARM64/HVF and is available by default, with no enable
API. Disk image contents are managed entirely by the embedding application.
Restore builds directly from saved state without running boot loaders.

## API

`ctx_id` is the VM handle returned by `krun_create_ctx()`. Configure the VM
normally and call `krun_start_enter(ctx_id)`. That call consumes the configuration
and owns its calling thread. The same handle identifies the running VM for
synchronous control calls from another host thread:

```c
int rc = krun_pause(ctx_id);
if (rc != 0) { /* handle error */ }
else {
    rc = krun_save_checkpoint(ctx_id, "/path/to/state.checkpoint");
    /* While still paused, save matching disks using the application's storage
     * implementation. Assemble state.checkpoint + disk images in the upper layer.
     * Resume only after every required artifact has been captured. */
    int resume_rc = krun_resume(ctx_id);
    /* Check rc and resume_rc. */
}
```

`krun_pause` stops CPUs, freezes device writers and flushes/syncs disks. It also
holds the event-loop barrier until `krun_resume`, so serial and timer events
cannot change captured state. Repeated pause/resume is a no-op. Successful saves
and storage failures both leave the VM paused. Saving a running VM returns
`-EBUSY`; overlapping control requests also return `-EBUSY`. An unstarted VM
returns `-EAGAIN`. Network streams disconnect on pause and UDP packets may be lost.

The destination is a new file; existing paths are refused with `-EEXIST`.
The file is synced and published with an atomic rename without replacement,
then its parent directory is synced. A failed directory sync can return an error
after the complete file has been published. `-ESHUTDOWN` means the VM is unusable
and permanently stopped; the embedding process must be torn down. Later requests
cannot resume it.

To restore in a new process:

```c
int ctx = krun_create_ctx();
krun_set_vm_config(ctx, 2, 256);
krun_set_root(ctx, "/path/to/the-same-rootfs");
krun_add_disk2(ctx, "data", "/path/to/restored-disk.raw",
               KRUN_DISK_FORMAT_RAW, false);
/* Bind fresh console/network endpoints and matching hotplug configuration. */
krun_build_from_checkpoint(ctx, "/path/to/state.checkpoint");
krun_start_enter(ctx);
```

`krun_build_from_checkpoint` selects the checkpoint on an existing configured
context; `krun_start_enter` performs the build and starts execution. Boot RAM
configuration is an allocation budget at least as large as saved boot RAM.
Hotplug's initial/max sizes must match. CPU count and MMIO/GPA/IRQ topology come
from the checkpoint. Bind exactly the saved disk device IDs, capacities and
features using the normal disk APIs. Paths and image formats are supplied by the
application. A block-root boot's retired bootstrap virtio-fs root is recreated
internally and need not be configured by the restore caller.

The file layout is a 16-byte header (magic, version, JSON length), JSON metadata,
a RAM section using the version-1 RAM codec, and optional hotplug RAM bytes.
Metadata records section lengths and disk device state, without disk paths or
image data. Import validates the exact total length, RAM layout, resource budget,
and CPU/device topology before releasing vCPUs. There are no content checksums;
same-length corruption is not detected by a checksum. Keep the file unchanged
during import. Version 1 directory checkpoints are not accepted by this API.

## Resources and consistency

- Disk workers finish the current request and flush/sync at pause. Libkrun
  captures only block device state, including queues and guest-visible disk ID.
  There is no flatten callback or opaque pointer in the C API. The application
  must exclude other writers, capture the disk and any backing chain while the
  VM is paused, and supply corresponding writable images for each restore.
  Libkrun validates device IDs, capacity and features; it cannot verify that
  externally supplied disk contents match saved guest RAM. Repeated restores
  need their own working images if writes must remain isolated.
- Virtio-fs uses the same host directory's live contents. Inodes and handles are
  rebound by path and identity, never by old FD numbers. Deleted/replaced objects
  return guest errors on subsequent FUSE operations. Resource exhaustion, access
  failures and host I/O errors abort restore without installing partial inode or
  handle tables. Cached guest pages remain part of guest RAM: this is not a
  transactional directory snapshot, and cached
  reads need not immediately notice host changes. Without inode birth times,
  identity checking conservatively treats changed ctimes as stale.
  DAX windows keep their configured size. Checkpoints record live mapping ranges,
  file offsets, permissions and backing-file identities, excluding the windows
  from RAM export. Restore reopens the same files and reinstalls the mappings
  before vCPUs run; file contents remain live, including host edits while the VM
  is absent. Missing/replaced files or truncation below the saved mapped extent
  reject restore, because direct memory access cannot return a FUSE error.
  Restore requires matching shares with at least the saved DAX window sizes.
  On macOS, HVF requires shared backing files to be openable for host read/write
  access, including guest read-only mappings. Guest read-only permissions are
  enforced by HVF; inaccessible backing files fail explicitly. Private copies
  are not substituted because they would break shared-file coherence.
  Exported guest-memory aliases remain unsupported.
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
| GPU/input/sound and unrecognized devices, exported guest-memory aliases | Rejected; device/resource state is not silently discarded |
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

## Validation

`tests/checkpoint/host.c` calls the public pause/save/resume/build C API.
`guest.c` checks memory patterns, two pinned CPU counters, monotonic time,
open-file I/O, direct block I/O or ext4 rootfs I/O, and optional network/hotplug
workloads. `run.py` checks that running saves fail, paused saves stay stopped, and explicit
resume restarts execution. It copies disks in the application layer while paused,
exits the original process before restore, and repeats save/restore. Missing or
wrong-capacity disks, duplicate destinations and corrupt inputs are rejected.
JSON results and logs remain under `target/run-*`.

The `blk,net` E2E fixture does not cover every build configuration. Also run
the feature-matrix checks used by Code Quality; checking only `-p libkrun`
with `blk,net` is not a substitute:

```sh
# Linux x86_64
cargo clippy --locked -- -D warnings
cargo clippy --locked --features amd-sev -- -D warnings
cargo clippy --locked --features tdx -- -D warnings

# macOS ARM64
cargo clippy --locked --features gpu -- -D warnings
```

Whole-VM checkpoint capture/restore and its private file helpers are excluded
from TEE builds. These Clippy commands validate compilation, not execution of
SEV/TDX guests or GPU rendering.

On Linux x86_64 with `/dev/kvm` and a matching `libkrunfw.so.5`:

```sh
cargo build -p libkrun --features blk,net
LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_NET=1 KRUN_TEST_FAIL_EXPORT=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_TSI=1 KRUN_TEST_FREEZE_FAILURE=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
KRUN_TEST_DAX=1 KRUN_TEST_FAIL_EXPORT=1 LD_LIBRARY_PATH=/path/to/firmware python3 tests/checkpoint/run.py
```

For optional upper-layer QCOW2 testing, the existing adapter applies the
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

### Native HVF checkpoint validation

The local Apple Silicon host runs the shared C API fixture in distinct boot,
restore and repeat-restore processes. Both native and software GIC runs verify
memory patterns, two pinned CPU counters, virtual monotonic time excluding an
offline delay, virtio-fs open handles, replaced-object errors and independent disk
images supplied by the application. Corrupt metadata, truncated RAM and
incompatible CPU state are rejected; failed restore joins its CPU/device threads.
The export-failure case verifies the source stays paused and continues after
explicit resume. The freeze-failure case verifies `-ESHUTDOWN` with the guest
stopped and no published checkpoint.

```sh
# Configure CC_LINUX for a static aarch64 Linux compiler/sysroot first.
cargo build -p libkrun --features blk,net
python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_TSI=1 KRUN_TEST_FAIL_EXPORT=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_HVF_GIC=software KRUN_TEST_NET=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_TSI=1 KRUN_TEST_FLATTEN=/path/to/checkpoint-flatten python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_FREEZE_FAILURE=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
KRUN_TEST_DAX=1 KRUN_TEST_FAIL_EXPORT=1 python3 tests/checkpoint/run-hvf.py /path/to/libkrunfw-directory
cargo test -p krun-hvf -p krun-vmm -p krun-devices --features blk,net
```

The fixture signs its native host binary with the repository's Hypervisor
entitlement and retains logs/results under `target/run-*`. It uses the local
Linux sysroot to compile its guest. Firmware and the BoxLite checkout are read only.

### Export/import benchmark

`tests/checkpoint/benchmark.py` runs the same public-API workload on both
platforms, with a release `blk,net` build, two vCPUs, and 256/512/1024/2048 MiB
configured RAM. Each size has one excluded warmup followed by five measurements.
The guest fills half its configured RAM with pseudorandom data; the checkpoint
contains all configured RAM, CPU and device state. This workload uses virtio-fs
and has no attached block image or network backend, so it excludes disk-image
copying/flattening. There is no RAM compression.

Export is host monotonic time around `krun_pause` plus `krun_save_checkpoint`,
including freeze, RAM serialization, file sync and publication. The source stays paused. Import is
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

The runner enables `KRUN_CHECKPOINT_TIMINGS` to collect pause, save and restore
phases, including CPU/device barriers, state capture, RAM streaming, file sync,
publication, validation, VM/device construction, and CPU/device resume. Tracing
is disabled during normal library use. Phase records are buffered until each
operation completes; end-to-end times include the cost of emitting those records.
Any remaining control/dispatch/logging and guest-response latency is reported
separately, so each sample's phase durations account for the full API duration.

It also records process launch and context setup before `start_enter`, plus the
additional host-observed wait from guest response to completed integrity
verification. These times include polling/scheduling latency. The runner retains
`results.json` (samples, medians/ranges and environment/library/firmware hashes),
`phases.csv` (every phase of every iteration), `report.md` (summary and phase
tables), and process logs in `target/checkpoint-benchmark-*`. Verified snapshot
files are removed after each iteration to bound disk use.

Measured hosts: HVF uses the local Apple M5 Max (128 GiB RAM, macOS 27.2,
native GIC, APFS). KVM uses an Intel Xeon 2.80 GHz host (8 logical CPUs,
31 GiB reported RAM, Ubuntu Linux, GCP Persistent Disk). The KVM host is itself
a virtual machine, so this run uses nested virtualization. Neither host was
reserved exclusively for this benchmark. These are deployment-specific latency
measurements, not an isolated comparison of hypervisor overhead.

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

The standalone RAM codec still uses version 1. The whole-VM container is version 2;
its RAM section embeds those same codec bytes at the offset following JSON metadata.

The benchmark now reports both logical snapshot bytes and `st_blocks * 512`
allocated bytes.

The following historical measurements used the previous version-1 directory
container and automatic resume after save; they are not measurements of the new API.
They use the hosts and benchmark method described above,
a release build, two vCPUs, half-filled pseudorandom guest memory and warm-cache import.
Each value is the median of five measured iterations. Allocated MiB includes
RAM and state files in that older container; logical file size is still approximately configured RAM.

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
