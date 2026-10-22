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
below adds internal block devices. The harness supports
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
vCPU0-based TSC offset synchronization before VM clock restore. The `blk` path
below already freezes/drains and saves its device state before CPU/KVM/RAM
capture; additional device types remain future work.

### Internal block-device checkpoints (stage 3, feature `blk`)

With the `blk` cargo feature, the same private owner additionally supports
`attach_disk` (before vCPUs start) for ordinary RAW/QCOW2/VMDK files through
the existing imago backends, plus disk-bearing version-2 full images. Caller
precondition: the source disk file and every backing file in its chain must
have no writers outside this private owner for the lifetime of the
attachment — the consistent cut assumes sole ownership; no lock or lease is
taken. The internal device topology is fixed: at most eight disks, MMIO
slots at 0xd0000000 in 4 KiB steps, kernel-irqchip GSIs 16–23; GSI 0–15 stay
reserved for legacy devices.

Version-2 images keep the same header layout and add an ordered disk table to
the bounded JSON section, followed after the RAM payload by one raw segment
per disk: the frozen guest-visible logical capacity with QCOW2/VMDK backing
chains and readonly disks normalized into plain bytes. `save_full` keeps its
single-file contract; version-1 images stay device-free. `restore_full`
rejects version 2 explicitly; `restore_full_with_disks(path, destination)`
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
counts cannot hang) and then the CPUs; an incomplete resume joins all CPUs
and workers before returning the error. Reusable virtio queue/device/
transport state (adapted from Firecracker's virtio persist structures)
preserves every guest-writable selector verbatim and validates ring
alignment/ranges and cursor consistency against guest RAM, including u16
wrapping; inactive partially negotiated queues keep their not-ready
configuration.

This remains an internal closed loop for the minimal VM: no full BoxLite box
restore, no virtio-fs/net/vsock/console support, and no runtime validation
has been run for the block path.

Local contributor checks (no public ABI or SDK entry point is provided):

```sh
make snapshot-fmt
make snapshot-check
make snapshot-build
make snapshot-test SNAPSHOT_CARGO_FLAGS='--offline --no-run'
make snapshot-test
```

The snapshot targets enable the `blk` feature and run the `krun-devices`
virtio/block tests selected by the `snapshot` name filter alongside the
krun-vmm suite. The default target is `x86_64-unknown-linux-gnu`; use
`SNAPSHOT_TARGET` to override. Cross builds require matching native C
libraries, linker and `CC_LINUX` settings (pass `CC_LINUX` on the make command
line on macOS). `snapshot-guest` regenerates the real-mode timer fixture using
GNU `SNAPSHOT_AS`/`SNAPSHOT_OBJCOPY`; the block guest is emitted by an
annotated byte emitter inside the stage-3 tests (a 16-bit-code unreal-mode
segment setup with an exact GDT layout, virtio queue with header/data/
status chains, IOAPIC/x2APIC interrupts, and a barrier that clears IF
before the selected request is submitted and proves the pending interrupt
was delivered after the restore through a dedicated post-STI marker) and
must not be regenerated externally. Worker freeze boundaries are covered by
one-shot, panic-safe request gates keyed per worker queue eventfd, so
unrelated workers and tests never interfere. All stage-3 checks, builds,
tests and KVM execution are **UNVERIFIED**: only source was written on
macOS without running cargo, make targets, formatters or tests.

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
