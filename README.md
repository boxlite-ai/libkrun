<picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/images/libkrun_logo_horizontal_darkmode.png">
   <source media="(prefers-color-scheme: light)" srcset="docs/images/libkrun_logo_horizontal.png">
   <img alt="libkrun logo" src="docs/images/libkrun_logo_horizontal_200.png">
</picture>

# libkrun

```libkrun``` is a dynamic library that allows programs to easily acquire the ability to run processes in a partially isolated environment using [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) Virtualization on Linux and [HVF](https://developer.apple.com/documentation/hypervisor) on macOS/ARM64.

It integrates a VMM (Virtual Machine Monitor, the userspace side of an Hypervisor) with the minimum amount of emulated devices required to its purpose, abstracting most of the complexity that comes from Virtual Machine management, offering users a simple C API.

## Use cases

* [crun](https://github.com/containers/crun/blob/main/krun.1.md): Adding Virtualization-based isolation to container and confidential workloads.
* [krunkit](https://github.com/containers/krunkit): Running GPU-enabled (via [venus](https://docs.mesa3d.org/drivers/venus.html)) lightweight VMs on macOS.
* [muvm](https://github.com/AsahiLinux/muvm): Launching a microVM with GPU acceleration (via [native context](https://www.youtube.com/watch?v=9sFP_yddLLQ)) for running games that require 4k pages.

## Goals and non-goals

### Goals

* Enable other projects to easily gain KVM-based process isolation capabilities.
* Be self-sufficient (no need for calling to an external VMM) and very simple to use.
* Be as small as possible, implementing only the features required to achieve its goals.
* Have the smallest possible footprint in every aspect (RAM consumption, CPU usage and boot time).
* Be compatible with a reasonable amount of workloads.

### Non-goals

* Become a generic VMM.
* Be compatible with all kinds of workloads.

## Variants

This project provides the following variants of the library:

- **libkrun**: Generic variant compatible with all Virtualization-capable systems.
- **libkrun-sev**: Variant including support for AMD SEV (SEV, SEV-ES and SEV-SNP) memory encryption and remote attestation. Requires an SEV-capable CPU.
- **libkrun-tdx**: Variant including support for Intel TDX memory encryption. Requires a TDX-capable CPU.

Each variant generates a dynamic library with a different name (and ```soname```), so both can be installed at the same time in the same system.

## Virtio device support

### All variants

* virtio-console
* virtio-block
* virtio-fs
* virtio-gpu (venus and native-context)
* virtio-net
* virtio-vsock (for TSI and socket redirection)
* virtio-balloon (only free-page reporting)
* virtio-rng
* virtio-snd

## Networking

In ```libkrun```, networking is provided by two different, mutually exclusive techniques: **virtio-vsock + TSI** and **virtio-net + passt/gvproxy**.

### virtio-vsock + TSI

This is a novel technique called **Transparent Socket Impersonation** which allows the VM to have network connectivity without a virtual interface. This technique supports both outgoing and incoming connections. It's possible for userspace applications running in the VM to transparently connect to endpoints outside the VM and receive connections from the outside to ports listening inside the VM.

#### Enabling TSI

TSI for AF_INET and AF_INET6 is automatically enabled when no network interface is added to the VM. TSI for AF_UNIX is enabled when, in addition to the previous condition, `krun_set_root` has been used to set `/` as root filesystem.

#### Known limitations

- Requires a custom kernel (like the one bundled in **libkrunfw**).
- It's limited to SOCK_DGRAM and SOCK_STREAM sockets and AF_INET, AF_INET6 and AF_UNIX address families (for instance, raw sockets aren't supported).
- Listening on SOCK_DGRAM sockets from the guest is not supported.
- When TSI is enabled for AF_UNIX sockets, only absolute path are supported as addresses.

### **virtio-net + passt/gvproxy**

A conventional virtual interface that allows the guest to communicate with the outside through the VMM using a supporting application like [passt](https://passt.top/passt/about/) or [gvproxy](https://github.com/containers/gvisor-tap-vsock).

#### Enabling virtio-net

Use `krun_add_net_unixstream` and/or `krun_add_net_unixdgram` to add a virtio-net interface connected to the userspace network proxy.

## Security model

The libkrun security model is primarily defined by the consideration that both the guest and the VMM pertain to the same security context. For many operations, the VMM acts as a proxy for the guest within the host. Host resources that are accessible to the VMM can potentially be accessed by the guest through it.

While defining the security implementation of your environment, you should think about the guest and the VMM as a single entity. To prevent the guest from accessing host's resources, you need to use the host's OS security features to run the VMM inside an isolated context. On Linux, the primary mechanism to be used for this purpose is namespaces. Single-user systems may have a more relaxed security policy and just ensure the VMM runs with a particular UID/GID.

While most virtio devices allow the guest to access resources from the host, two of them require special consideration when used: virtio-fs and virtio-vsock+TSI.

### virtio-fs

When exposing a directory in a filesystem from the host to the guest through virtio-fs devices configured with `krun_set_root` and/or `krun_add_virtiofs`, libkrun **does not** provide any protection against the guest attempting to access other directories in the same filesystem, or even other filesystems in the host.

A mount point isolation mechanism from the host should be used in combination with virtio-fs.

In addition, when using virtio-fs, a guest may exhaust filesystem resources such as inode limits and disk capacity. Controls should be implemented on the host to mitigate this.

### virtio-vsock + TSI

When TSI is enabled, the VMM acts as a proxy for AF_INET, AF_INET6 and AF_UNIX sockets, for both incoming and outgoing connections. For all that matters, the VMM and the guest should be considered to be running in the network context. As such, you should apply on the VMM whatever restrictions you want to apply on the guest.

## Building and installing

### Linux

#### Requirements

* [libkrunfw](https://github.com/containers/libkrunfw)
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf

#### Optional features

* **GPU=1**: Enables virtio-gpu. Requires virglrenderer-devel.
* **VIRGL_RESOURCE_MAP2=1**: Uses virgl_resource_map2 function. Requires a virglrenderer-devel patched with [1374](https://gitlab.freedesktop.org/virgl/virglrenderer/-/merge_requests/1374)
* **BLK=1**: Enables virtio-block.
* **NET=1**: Enables virtio-net.
* **SND=1**: Enables virtio-snd.

#### Compiling

```
make [FEATURE_OPTIONS]
```

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

### Linux (SEV variant)

#### Requirements

* The SEV variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-sev.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make SEV=1
```

#### Installing

```
sudo make SEV=1 install
```

### Linux (TDX variant)

#### Requirements

* The TDX variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-tdx.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make TDX=1
```

#### Installing

```
sudo make TDX=1 install
```

#### Limitations

The TDX flavor of libkrun only supports guests with 1 vCPU and memory less than or equal to 3072mib.

### macOS

#### Requirements

* A working [Rust](https://www.rust-lang.org/) toolchain
* A host running macOS 14 or newer
* Homebrew packages `lld` and `xz`

#### Compiling

```
make [FEATURE_OPTIONS]
```

The [init](init/init.c) binary is cross-compiled using clang and lld.
A suitable sysroot is automatically generated by the Makefile from Debian repository.

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

## Using the library

Despite being written in Rust, this library provides a simple C API defined in [include/libkrun.h](include/libkrun.h)

## Examples

### chroot_vm

This is a simple example providing ```chroot```-like functionality using ```libkrun```.

#### Building chroot_vm

To be able to ```chroot_vm```, you need need to build libkrun with the `virtio-block` and `virtio-net` optional features:

```
make BLK=1 NET=1
sudo make BLK=1 NET=1 install
cd examples
make
```

#### Running chroot_vm

To be able to ```chroot_vm```, you need first a directory to act as the root filesystem for your isolated program.

Use the ```rootfs``` target to get a rootfs prepared from the Fedora container image (note: you must have [podman](https://podman.io/) installed):

```
make rootfs
```

Now you can use ```chroot_vm``` to run a process within this new root filesystem:

```
./chroot_vm ./rootfs_fedora /bin/sh
```

If the ```libkrun``` and/or ```libkrunfw``` libraries were installed on a path that's not included in your ```/etc/ld.so.conf``` configuration, you may get an error like this one:

```
./chroot_vm: error while loading shared libraries: libkrun.so: cannot open shared object file: No such file or directory
```

To avoid this problem, use the ```LD_LIBRARY_PATH``` environment variable to point to the location where the libraries were installed. For example, if the libraries were installed in ```/usr/local/lib64```, use something like this:

```
LD_LIBRARY_PATH=/usr/local/lib64 ./chroot_vm rootfs_fedora/ /bin/sh
```

## Memory checkpoints (experimental, version 9)

The Linux x86_64/KVM owner saves RAM, CPU/KVM/device state and FUSE sessions
without archiving filesystem contents. A checkpoint pairs `snapshot.mem` with
one standalone `snapshot.qcow2`; the caller retains external share recovery
points, open/unlinked objects and the exact readonly boot disk. Version 7/8 full
images are rejected, never upgraded. RAM-only `KRUNRAM` retains its separate
version-1 meaning; disk-only BoxLite archives are outside this library contract.

### Descriptor API

The authoritative C signatures and JSON schemas are in
[`include/libkrun.h`](include/libkrun.h), under “Version-9 descriptor API”. Rust
embedders use `SnapshotVm` and `snapshot_vm::checkpoint` resource types.

| Operation | Contract |
| --- | --- |
| `krun_snapshot_capabilities` | Memory-v9, capture-reservation and external-FD capability bits; zero on unsupported platforms |
| `begin_capture(CHECKPOINT)` | Reserve an already confirmed Paused owner; never start or implicitly pause |
| `begin_capture(DISK)` | Reserve Running, pause/drain/flush internally; state queries keep reporting Running |
| `prepare_capture` | Return bounded session/object JSON and owned CLOEXEC duplicates of retained object FDs; no tree traversal |
| `export_fd` | Write/seal/sync a new memory FD, binding its paired standalone QCOW2 digest and provider references |
| `end_capture(COMPLETE)` | Retire token; resume an internal disk capture or retain checkpoint Paused |
| `end_capture(CANCEL)` | Stop execution; use on cancellation or unknown outcome |
| `inspect_fd` | Verify version, lengths, checksums and metadata extents without KVM or external-resource creation |
| `import_fd`, then `start_enter` | Verify supplied disk/share dependencies, restore devices/FUSE/DAX, publish Paused; resume is explicit |

Keep the dedicated connected Unix stream's peer open and silent through the
caller’s durable pair publication. EOF or data cancels and stops the owner.
Conflicting mutations return Busy; retired/wrong tokens return ESTALE. Stop
signals cancellation before queueing so memory-copy loops can abort. Never retry
an uncertain operation. The old path-based `krun_snapshot_import` and
`krun_snapshot_export` return ENOTSUP: they cannot express the new dependency
contract. Ordinary non-checkpoint VM starts retain their API.

Prepare JSON describes ordered shares, saved sessions, guest inode/ctime
projection, retained objects, handle flags and DAX mappings. A provider supplies
`resource_id`, `recovery_point`, `object_key` references for external objects,
with retention lasting beyond source destruction. Import JSON maps each required
role to exactly one received descriptor index. O_PATH identity descriptors do not
replace independent access descriptions. Identity descriptors may be reopened
from a pinned handle through `/proc/self/fd` after unlink/forget; these carry
O_PATH without O_NOFOLLOW. Path and boot-recipe lookup still uses O_NOFOLLOW.
Supply each saved handle and every
(object,writable) file-DAX role. No privileged file-handle reopening is used.
The embedding protocol owns SCM_RIGHTS framing, truncation detection, peer
validation, FD limits and leases; the library checks indices, identities, flags,
object types, roots and mount consistency. C binding roots are UTF-8 JSON paths;
use a UTF-8 mount alias for a root whose host path is not UTF-8. Rust bindings
retain native `PathBuf` roots.

Cached readdir names, types, order and index cookies are independent metadata.
Stale listing-only names and `.`/`..` need no object FD. Surviving saved names are
resolved only relative to their retained directory to restore inode projection;
retained entries also validate their object index. Missing retained orphans fail.
File-backed DAX contains references/mapping metadata; only anonymous DAX pages and
init.krun bytes belong in the memory payload. `BoxLiteShared` is external too.

Runtime boot roots use only known directories (`.`, `dev`, `proc`, `sys`,
`newroot`) and synthetic init.krun. Captured references outside that recipe fail.
The caller prepares a private recipe root before sandbox installation and
supplies required role FDs against it. Readonly boot disks are full-content
hashed dependencies, not regenerated substitutes. Writable container disks open
QCOW2 directly and restore saved capacity, identity, features and queues; the
caller must pass a private box-owned copy, never the original checkpoint file.

### Device continuation and compatibility

Import preserves guest CPU registers, stack, SIMD, interrupt controllers and
virtual clocks. It validates the target CPU/KVM capabilities before starting
vCPUs. Offline storage time is excluded from guest timers; pending and one-shot
interrupts continue from the captured cut. Imported vCPUs remain Paused until
explicit resume.

Console restores the control handshake, queued replies and partial TX offset.
Bytes already accepted by the source output are never replayed to new endpoints;
unread host input remains at the source. Resume checks saved queues without a
new guest kick. An inactive console stays inactive until guest activation.

NIC import connects an active device to the supplied new backend. Host partial
RX remains source-local; cut-time TX chains complete once as dropped on import,
with an owed interrupt injected after irqchip restoration. New traffic uses only
the new backend. An inactive NIC connects on later guest activation.

Vsock pause closes old connections. Resume delivers a transport reset before
reopening the backend; without an event buffer, reopen waits while the guest
continues. New paths are supplied at import. Failed backend restart stops guest
execution, and teardown preserves foreign paths. RNG resumes pending requests
without requiring a new kick; UART/CMOS/i8042 state persists, including guest reset.

External roots and disk files remain caller-owned on failed import and teardown.
Device continuation tests cross the full v9 descriptor export/import boundary;
standalone device state tests alone do not establish owner ordering or cleanup.

### Memory format and verification

The 160-byte little-endian header contains `KRUNVM\0\0`, version 9, header length,
exact total/metadata/payload lengths, paired QCOW2 length, SHA-256 hashes for
metadata, payload and QCOW2, and sixteen reserved zero bytes. Metadata is bounded
to 16 MiB and rejects unknown fields. Checked concatenated RAM/init/anonymous-DAX
extents must cover the payload exactly. The valid header is written only after
the payload is synced, then synced again. Hashes detect corruption; they are not
authentication. The library does not publish directories or delete caller files.

The embedder owns private pair staging, sync/no-overwrite publication, external
storage consistency, cancellation cleanup after joining writers, persistent boot
pins and bindings for cold starts. All dependencies must be bound before vCPU
creation/release. The default BoxLite Linux sandbox is bwrap plus production
seccomp; an optional post-mount Landlock test is separate, never applied before
bwrap mounts.

### Development checks

Use the existing Make targets from this directory:

```sh
make snapshot-fmt
make snapshot-check
make snapshot-test
KRUN_SNAPSHOT_TEST_LIBKRUNFW=/path/to/libkrunfw.so.5 make snapshot-capi-test
make snapshot-abi-check
make snapshot-feature-check
```

Tests with `snapshot_v9` cover the memory envelope, external disk integrity and
real KVM owner continuation through a private QCOW2 copy (requires `qemu-img`; the block-I/O fixture also uses `qemu-io`).
Owner channel tests cover reservation, logical Running, Busy, stale token,
cancellation and disconnect. The rootless `rootless_fs_external_received_*`
tests exercise actual received orphan/handle/writable-DAX FDs under bwrap and
the production seccomp filter through BoxLite's `make test:snapshot:rootless`.
Low-level device/session validation tests remain separate from full-image tests.
Device continuation assertions use shared external-QCOW2 fixtures instead of
old RAW-segment/share-archive encodings. C API tests include real KVM capture,
positive Paused import, descriptor borrowing/index checks and ENOBUFS transfer;
the complete 16384-descriptor test temporarily raises its process soft limit,
requiring hard RLIMIT_NOFILE >= 32768. Standalone passthrough archive utilities
are not used by full checkpoints.

The ignored `snapshot_fs_supplied_noatime_survives_capability_drop` regression
needs CAP_FOWNER only for source capture, then drops its effective capability
before opening provider roles and restoring. Run it separately with a test-only
runner; an ordinary skipped/ignored result is not a pass. For example, create an
executable `cap-fowner-test-runner` containing:

```sh
#!/bin/sh
exec sudo -n setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups \
  --inh-caps=-all,+fowner --ambient-caps=-all,+fowner \
  --bounding-set=-all,+fowner --no-new-privs -- "$@" --include-ignored
```

Then run `make snapshot-test SNAPSHOT_PKGS='-p krun-devices --features blk,net'
SNAPSHOT_FILTER=snapshot_fs_supplied_noatime_survives_capability_drop
SNAPSHOT_RUNNER=/absolute/path/cap-fowner-test-runner`. This requires permission
to run `sudo setpriv`; it changes only the test process, without changing host
policy. A bwrap child with AppArmor capability masking does not qualify.

These library checks do not establish BoxLite integration acceptance. Real
container-process PID/heap marker/execution identity, storage recovery lifetime,
cross-process operation framing, publication durability and ordinary/imported
box capability alternation require the later runtime stage.

Known adjacent issue: generic FUSE short reads may return more than the requested
count (`descriptor_utils::DescriptorChainConsumer::consume` retains an unsliced
buffer); the full-page continuation test does not validate short-read length.

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
