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

## Internal minimal VM checkpoints (experimental)

The private Linux x86_64/KVM `RamSnapshotVm` harness supports `save_full`,
`restore_full` and explicit `resume` for ordinary RAM with a kernel irqchip/PIT.
Its base configuration is device-free (no userspace devices; uncontrolled
background RAM writers are rejected); the optional `blk` feature described
below adds internal block devices, and `blk` plus `net` add one internal
network device. The harness supports
1–128 vCPUs, subject to the host KVM capacity and the existing
CPUID package-sizing limit. Saved CPU ordering and topology must match this count.
Restore returns paused; it does not reload a payload, write boot parameters, or
initialize new guest CPUs.
The existing RAM-only image and APIs retain their memory-only meaning.

Device-free full images use independent version 1 magic `KRUNVM\0\0`, a bounded
16 MiB JSON state section, and RAM copied in 64 KiB chunks into independent
anonymous mappings. Files are created exclusively with mode 0600 and become
valid only after all source vCPUs resume successfully. Errors attempt every
source resume; uncertain control disables subsequent checkpoints. Partial
imports stop and join created threads before releasing VM/RAM. External RAM
aliases, TEE, nested virtualization, split irqchips, PMU/SMM and uncovered
extended CPU states are unsupported.

Compatibility is deliberately conservative: the supported CPU vendor/features,
MSR set, XSAVE layout/size and required KVM capabilities must match; actual saved
CPUID must fit the target. Dynamic XSAVE uses the current dependencies without
truncating ioctl buffers. Fixed KVM records require exact serialized byte lengths,
because kvm-bindings 0.12 otherwise zero-pads short records. MSRs use bounded
chunks, check partial transfers, and restore TSC deadline after all other MSRs.

Timer handling follows Firecracker's runtime migration semantics: a saved zero
TSC deadline becomes the saved TSC in the image only, with no per-tick replay.
Clock restore uses `clock_realtime=false` and adds no snapshot storage wall time;
pausing a source vCPU does not stop its hardware clocks. TSC frequency differences
above 250 ppm require successful scaling. Multi-vCPU restore requires successful
vCPU0-based TSC offset synchronization before VM clock restore. The `blk` and
`net` paths below freeze/drain and save their device state before CPU/KVM/RAM
capture; additional device types remain future work.

### Internal block-device checkpoints (stage 3, feature `blk`)

With the `blk` cargo feature, the same private owner additionally supports
`attach_disk` (before vCPUs start) for ordinary RAW/QCOW2/VMDK files through
the existing imago backends, plus disk-bearing version-2 full images. Caller
precondition: the source disk file and every backing file in its chain must
have no writers outside this private owner for the lifetime of the
attachment — the consistent cut assumes sole ownership; no lock or lease is
taken. The internal device topology is fixed: at most eight disks (seven
when the internal NIC below is attached), MMIO slots at 0xd0000000 in 4 KiB
steps, kernel-irqchip GSIs 16–23; GSI 0–15 stay reserved for legacy devices.

Version-2 images keep the same header layout and add an ordered disk table to
the bounded JSON section, followed after the RAM payload by one raw segment
per disk: the frozen guest-visible logical capacity with QCOW2/VMDK backing
chains and readonly disks normalized into plain bytes. `save_full` keeps its
single-file contract; version-1 images stay device-free. `restore_full`
rejects versions 2 and 3 explicitly; `restore_full_with_disks(path, destination)`
imports the segments into a new 0700 destination directory of exclusive 0600
`disk-N.raw` files, never taking paths from metadata, and the owner deletes
the imported directory on partial failure and destruction.

The save order is: configuration checks -> pause/ack all vCPUs -> freeze and
flush every device (controls are checked before popping each descriptor, so a
freeze lands between individual requests after the status write, used-ring
update and interrupt; the single frozen flag and scoped mapping clones
guarantee no ring write — including notification re-enables — after the
confirmation; the disk is flushed and synced regardless of the guest cache
mode, inactive disks included; the bounded command queue is part of the 30 s
control timeout, which is never an I/O cancellation) -> the RAM alias probe
at that quiescent boundary, counting only the clones of the owner's own
devices -> per-device synchronous KVM irqfd deassign (Linux flushes the
injection workqueue before the ioctl returns) and eventfd drain -> device
(active rings validated against guest RAM), CPU, KVM, RAM and disk capture ->
file sync -> irqfd reassign, device resume and CPU resume, each attempted for
every resource and aggregated (any failure poisons the owner and never
publishes) -> valid magic. Restores validate all metadata — including the
exact offered-feature contract and read-only consistency — before creating
anything, then the active rings against the loaded RAM, then import through
an exclusive creation guard: a pre-existing destination directory is an error
and is never touched; on any failure or owner drop, only the files the import
itself created are removed, after every CPU and worker thread joined.
Restored devices rebuild MMIO/ioeventfd/irqfd from the saved address and IRQ
with new eventfds; already-injected interrupts come back with the kernel
irqchip state, and transport interrupt status is restored without
reinjecting. Restored active workers start frozen; explicit `resume` resumes
devices first (actively re-examining their queues so drained notification
counts cannot hang) and then the CPUs; if any device fails to resume, no CPU
is resumed, and an incomplete resume joins all CPUs and workers before
returning the error. Reusable virtio queue/device/
transport state (adapted from Firecracker's virtio persist structures)
preserves every guest-writable selector verbatim and validates ring
alignment/ranges and cursor consistency against guest RAM, including u16
wrapping; inactive partially negotiated queues keep their not-ready
configuration.

### Internal network checkpoints (stage 4, features `blk` + `net`)

With both features, the owner additionally supports one internal virtio-net
device: `attach_net(socket_path, mac, features)` before vCPUs start, at the
fixed MMIO slot 0xd0008000 and GSI 23 (so at most seven disks coexist with
it; without a NIC the eight-disk window is unchanged). The backend is a
UnixStream server speaking libkrun's length-prefixed frames, connected
synchronously when the device activates: an inactive NIC never connects
(also not at restore), while a failed connection fails the activation and
starts no worker. `features` accepts only libkrun's `NET_FEATURE_*`
offload bits.

The backend connection is never checkpointed. A restore attaches a freshly
started compatible backend so new DNS/TCP can work; old TCP/NAT state,
frames buffered in the source worker or backend, and partial frames are not
migrated. The guest driver, device and queue state are kept, so open guest
sockets recover through their own errors and timeouts.

The UnixStream backend never blocks the worker: the socket is nonblocking,
a frame split across reads is reassembled from its partial prefix/body, empty
frames are skipped, frames larger than the 64 KiB buffer are discarded, end
of stream is reported once and dropped partial frames are never delivered,
and each read spends at most 256 KiB or 64 receive calls before handing
control back. TX backpressure keeps the unsent chain in the avail ring
(nothing written) or the remainder of one frame in the worker (partial
write). Guest TX chains that cannot be sent — header-only, device-writable,
oversized, or after the backend failed — complete as used with length 0
instead of stalling the queue. Workers move at most 64 frames per direction
before re-polling and check controls before every descriptor chain. A
confirmed freeze lands at a complete descriptor boundary with every used
entry's interrupt raised; afterwards the worker writes no guest RAM, ring or
interrupt and does no backend I/O until resumed or stopped. A resume
re-examines the backend and both queues itself, so kicks drained while frozen
cannot stall it. A source that saves keeps its backend connection and worker
buffers and continues where it stopped.

Images with a NIC are version 3: the version-2 layout (bounded JSON, RAM,
optional ordered disk segments) plus the NIC's MAC, attach features,
device config, MMIO transport registers, negotiated features and RX/TX queue
cursors in the persist structures above. Worker-private RX/TX buffers are
excluded. NIC-free owners keep writing versions 1 and 2; `restore_full` and
`restore_full_with_disks` reject version 3 explicitly.

`save_full` with a NIC: pause all vCPUs -> freeze every disk, then the NIC ->
one RAM alias probe (every worker is frozen, so no transient mapping clone
exists) -> deassign and drain every irqfd -> capture devices, CPUs, KVM, RAM
and disks -> sync -> reassign irqfds, resume every device and every CPU, each
attempted -> publish the magic only if everything succeeded.

`restore_full_with_net(path, disk_destination, socket_path)` validates all
metadata (fixed slot, disk count, offered features against the attach
features, config bytes against the MAC, transport state machine, queue
structure) before RAM exists, then
both rings and every cut-time TX head against the loaded RAM, before any
directory, socket or thread. It imports disks as above (no destination is
created for a disk-free image), attaches the disks and then the NIC before
the vCPU threads exist, connects the new backend (a failed connection fails
the restore and cleans up), and returns the owner paused. Every TX chain the
source had not consumed at the cut completes as dropped (used length 0)
before the restored worker exists, so no old frame reaches the new backend;
only the validated avail-ring head indexes are used, the old descriptors
are never parsed, and the count is fixed when the discard starts;
chains the source already used are never replayed, and RX buffers stay
available for new frames. The owed TX interrupt is raised after the KVM
irqchip state is restored (loading it would overwrite an earlier injection)
and before any vCPU runs. `resume` resumes the disks and the NIC, then the
CPUs. Teardown joins CPUs, then workers (closing the backend), then removes
owned imports.

This remains an internal closed loop for the minimal VM: no full BoxLite box
restore and no virtio-fs/vsock/console support.

Local contributor checks (no public ABI or SDK entry point is provided):

```sh
make snapshot-fmt
make snapshot-check
make snapshot-build
make snapshot-test SNAPSHOT_CARGO_FLAGS='--offline --no-run'
make snapshot-test
make snapshot-net-host-test
```

The snapshot targets enable the `blk` and `net` features and run the
`krun-devices` virtio tests selected by the `snapshot` name filter alongside
the krun-vmm suite. The default target is `x86_64-unknown-linux-gnu`; use
`SNAPSHOT_TARGET` to override. Cross builds require matching native C
libraries, linker and `CC_LINUX` settings (pass `CC_LINUX` on the make command
line on macOS). One way on macOS: build a Debian amd64 sysroot with the
existing rule (`make ARCH=amd64 ROOTFS_DIR=<dir> <dir>/.sysroot_ready`, adding
`libgcc-s1` through `DEBIAN_PACKAGES` and making its absolute
`lib64/ld-linux-x86-64.so.2` link relative), then point `CC_LINUX`,
`CC_x86_64_unknown_linux_gnu` and `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`
at `clang -target x86_64-linux-gnu -fuse-ld=lld --sysroot <dir>` (plus the
GCC library directory through `-B`/`-L`). `SNAPSHOT_RUNNER` sets the cargo
target runner so `make snapshot-test` executes the cross-built tests, for
example `SNAPSHOT_RUNNER="docker run --rm --platform linux/amd64 -v $PWD:$PWD
-w $PWD rust:1-bookworm"`; add `--device /dev/kvm` on a Linux KVM host.
`make snapshot-net-host-test` runs the virtio-net backend and worker tests
natively (macOS or Linux, no KVM). `snapshot-guest` regenerates the real-mode
timer fixture using GNU `SNAPSHOT_AS`/`SNAPSHOT_OBJCOPY`; the block guest is
emitted by an annotated byte emitter inside the stage-3 tests (a 16-bit-code
unreal-mode segment setup with an exact GDT layout, virtio queue with
header/data/status chains, IOAPIC/x2APIC interrupts, and a barrier that
clears IF before the selected request is submitted and proves the pending
interrupt was delivered after the restore through a dedicated post-STI
marker) and must not be regenerated externally. Worker freeze boundaries are
covered by one-shot, panic-safe request gates keyed per worker queue eventfd,
so unrelated workers and tests never interfere.

The stage-4 tests cover the UnixStream backend (split prefixes and bodies,
EOF, empty/oversized frames, per-call budgets, TX backpressure), the worker
(freeze at descriptor boundaries with unchanged RAM and no interrupt while
frozen, partial and deferred frames kept by a source, backpressure, empty-
frame floods, malformed TX, EOF, frozen start and stop, no-kick resume,
connect-on-activation), device-level restores without KVM (copied RAM,
queues rebuilt from the cut, the production discard, a new backend; with a
partial RX frame and spare RX buffers, and with a deferred RX frame, a
partial TX write, event index and wrapped cursors), the head-only discard,
NIC metadata/ring/version validation, and KVM tests (`nic/kvm_tests.rs`)
that drive the virtio-net registers through the owner's MMIO bus while the
stage-2 counter guest proves CPU continuation: save during active traffic
with a partial frame and unconsumed TX, source continuation on its backend,
restore with a new backend (dropped TX, owed interrupt status, paused CPU),
resume traffic, inactive NIC plus disk, backend failure and legacy-entry
cleanup, save failure recovery, and the shared GSI limit. No test has the
guest itself read the restored NIC or take a pending NIC interrupt after a
restore; that guest-observed check is acceptance work below.

Validation status (stage 3 and 4, checked on macOS arm64 against an
x86_64 Linux target): `make snapshot-fmt`, `snapshot-check`, `snapshot-build`
and `snapshot-test --no-run` pass, and `make snapshot-net-host-test` passes
natively on macOS. The cross-built tests were executed in an x86_64 Linux
container without `/dev/kvm`: every `krun-devices` snapshot test (block and
network workers, UnixStream backend, device-level restore, persist) and
every krun-vmm test that does not open KVM (NIC metadata, ring and discard
checks, image-version dispatch) pass, while every test that needs KVM fails
at opening `/dev/kvm`. All KVM execution — stage-3 block continuation and
every stage-4 KVM test above — is **UNVERIFIED** until run on a Linux KVM
host.

Guest-observed NIC acceptance is **UNVERIFIED**: on a Linux KVM host, a
real-mode guest (like the stage-3 block fixture) should read the NIC
registers through its own MMIO exits after a restore, and, with IF clear
across the cut, take exactly one pending GSI-23 interrupt after `sti` with
no new traffic — once for an RX completion pending at the cut and once for
the restore's TX discard. Real DNS/TCP acceptance is also **UNVERIFIED** and
cannot run in this harness yet: `start_vcpus` starts real-mode fixtures, not a Linux guest. With a
harness extension that boots a Linux guest, the procedure on a Linux x86_64
KVM host is: start a UnixStream backend that speaks the same length-prefixed
framing (for example passt or gvproxy in their QEMU stream-socket mode);
attach the NIC and boot the guest with
`virtio_mmio.device=4K@0xd0008000:23`; configure the network, resolve a name
and keep a TCP connection open; `save_full`; stop the source VM and its
backend; start a new backend at a new socket; `restore_full_with_net` and
`resume`. Expected: the old TCP connection fails or times out, new name
lookups and new TCP connections succeed, interface counters keep moving and
the guest kernel logs no virtio-net ring errors.

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
