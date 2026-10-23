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

The private Linux x86_64/KVM `RamSnapshotVm` harness supports an explicit
`pause` -> `export(path)` -> `import(path, RestoreResources)` -> `resume`
lifecycle (described below) for ordinary RAM with a kernel irqchip/PIT. Its base configuration is device-free (no userspace
devices; uncontrolled background RAM writers are rejected); `attach_rng` and
`attach_balloon` add internal virtio devices, `attach_vsock` adds a Unix
IPC vsock, `attach_console` adds a multiport virtio console, `attach_legacy` adds the x86
UARTs, CMOS and i8042, the optional `blk` feature
described below adds internal block devices, and `blk` plus `net` add one
internal network device. The harness supports
1–128 vCPUs, subject to the host KVM capacity and the existing
CPUID package-sizing limit. Saved CPU ordering and topology must match this count.
Import returns paused; it does not reload a payload, write boot parameters, or
initialize new guest CPUs.
The existing RAM-only image and APIs retain their memory-only meaning: `save`
needs an owner without vCPUs or a confirmed `pause`, never resumes, and is
refused for an owner with any attached device, which needs `export`.

Lifecycle contract:

| Call | Requires | Effect | On failure |
| --- | --- | --- | --- |
| `pause` | running, usable, no guest exit | quiesce the vsock gate, pause/ack every vCPU, then freeze every disk, the NIC and the event thread (RNG, balloon, vsock queues, console control queues, UART input), then every console port worker, stop the vsock backend, then deassign and drain every irqfd; the frozen worker queue cursors and the drained irqfd count stay with the owner | rejected without effect before any control; otherwise the owner is disabled and every thread stopped and joined |
| `export` | paused, usable | capture the same cut into a new image; resumes nothing, so it can repeat | partial image removed, still paused and retryable; a vCPU that never answers its state request disables the owner and stops every thread |
| `import` | an image and matching resources | a new owner in the same paused state as a source after `pause` (devices frozen, cursors retained, irqfds drained), exportable before it ever runs | everything it created is removed after its threads joined |
| `resume` | paused, usable, no guest exit | shared by sources and imports: reattach the drained irqfds, resume every device (the vsock delivers its transport reset before reopening its backend; the console resumes its port workers and processes its control queues before the event thread), then every vCPU last | the owner is disabled and every thread stopped and joined; no vCPU runs unless every device resumed |

For example, a source checkpoints and continues with `pause()`,
`export(a)`, `export(b)`, `resume()`; a target runs with
`import(a, resources)`, `resume()`. Each export captures the KVM clock and
TSC when it runs; both keep running while the owner is paused (see the timer
handling below).

Every full image, with or without devices, uses one format: magic
`KRUNVM\0\0`, version 6, a bounded 16 MiB JSON state section, RAM copied in
64 KiB chunks into independent anonymous mappings, then one raw segment per
disk. The JSON holds CPU, KVM and RAM state, the ordered disk table and the
optional NIC, RNG, balloon, vsock, console and legacy-device (UARTs, CMOS,
i8042) sections. Versions 1–5 (version 4 had no vsock section, version 5 no
console section) are rejected explicitly; the RAM-only `KRUNRAM` image stays
version 1. Images never contain host paths, descriptors or threads:
`RestoreResources` supplies the disk import directory, the NIC backend
socket, the vsock port paths, the fresh console ports and the four serial
endpoints, and each must be present exactly when the image has the
matching device. A mismatch is rejected before any RAM,
directory, socket or thread is created. Files are created exclusively with mode 0600 and become
valid only after the whole image is synced; an export never resumes the
source. Uncertain control disables subsequent checkpoints and stops every
thread. Partial imports stop and join created threads before releasing VM/RAM. External RAM
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
vCPU0-based TSC offset synchronization before VM clock restore. Every
attached device below is frozen, drained and saved before CPU/KVM/RAM
capture. virtio-fs owner checkpoints are in progress: only the device
backend described in "Internal virtio-fs session checkpoints" below exists.

### Internal block-device checkpoints (stage 3, feature `blk`)

With the `blk` cargo feature, the same private owner additionally supports
`attach_disk` (before vCPUs start) for ordinary RAW/QCOW2/VMDK files through
the existing imago backends, saved into the full image. Caller
precondition: the source disk file and every backing file in its chain must
have no writers outside this private owner for the lifetime of the
attachment — the consistent cut assumes sole ownership; no lock or lease is
taken. The internal device topology is fixed: at most eight disks (seven
when the internal NIC below is attached), MMIO slots at 0xd0000000 in 4 KiB
steps, kernel-irqchip GSIs 16–23; GSI 0–15 stay reserved for legacy devices.

The ordered disk table in the JSON section is followed after the RAM payload
by one raw segment per disk: the frozen guest-visible logical capacity with
QCOW2/VMDK backing chains and readonly disks normalized into plain bytes.
`export` keeps its single-file contract. `import` with
`RestoreResources::disk_dir` imports the segments into a new 0700 destination
directory of exclusive 0600 `disk-N.raw` files, never taking paths from
metadata, and the owner deletes the imported directory on partial failure and
destruction.

The pause order is: configuration checks -> pause/ack all vCPUs -> freeze and
flush every device (controls are checked before popping each descriptor, so a
freeze lands between individual requests after the status write, used-ring
update and interrupt; the single frozen flag and scoped mapping clones
guarantee no ring write — including notification re-enables — after the
confirmation; the disk is flushed and synced regardless of the guest cache
mode, inactive disks included; the bounded command queue is part of the 30 s
control timeout, which is never an I/O cancellation) -> per-device
synchronous KVM irqfd deassign (Linux flushes the injection workqueue before
the ioctl returns) and eventfd drain. Each export then runs at that
quiescent boundary: the RAM alias probe, counting only the clones of the
owner's own devices -> device (active rings validated against guest RAM),
CPU, KVM, RAM and disk capture -> file sync -> valid magic, resuming
nothing. Imports validate all metadata — including the
exact offered-feature contract and read-only consistency — before creating
anything, then the active rings against the loaded RAM, then import through
an exclusive creation guard: a pre-existing destination directory is an error
and is never touched; on any failure or owner drop, only the files the import
itself created are removed, after every CPU and worker thread joined.
Restored devices rebuild MMIO/ioeventfd/irqfd from the saved address and IRQ
with new eventfds; already-injected interrupts come back with the kernel
irqchip state, and transport interrupt status is restored without
reinjecting. Imported active workers start frozen and the import drains its
irqfds, so it ends in the paused state of a source. `resume` reattaches the
irqfds, resumes devices (actively re-examining their queues so drained
notification counts cannot hang) and then the CPUs; if any device fails to
resume, no CPU is resumed, and an incomplete resume joins all CPUs and
workers before returning the error. Reusable virtio queue/device/
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
cannot stall it. A paused or exported source keeps its backend connection
and worker buffers and continues where it stopped once resumed.

The image's NIC section holds the MAC, attach features, device config, MMIO
transport registers, negotiated features and RX/TX queue cursors in the
persist structures above. Worker-private RX/TX buffers are excluded.

`pause` with devices: pause all vCPUs -> freeze every disk, the NIC, then
the event thread -> deassign and drain every irqfd. Each `export`: one RAM
alias probe (every device is frozen, so no transient mapping clone exists)
-> capture devices from the retained cursors, CPUs, KVM, RAM and disks ->
sync -> publish the magic. `resume`: reassign irqfds -> resume every device
-> resume every CPU.

`import` with `RestoreResources::nic_socket` validates all
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
and before the import drains its irqfds, so the injection lands in the
irqchip state an immediate re-export captures. `resume` reattaches the
irqfds, resumes the disks, the NIC and the event thread, then the CPUs. Teardown stops the event thread, joins CPUs, then workers
(closing the backend), then removes owned imports.

### Internal RNG and balloon checkpoints (stage 5, no feature)

`attach_rng()` and `attach_balloon()` add a virtio RNG at MMIO 0xd0009000 with
GSI 5 and a virtio balloon (existing free page reporting only) at 0xd000a000
with GSI 6, before vCPUs start. Disk and NIC slots are unchanged. All devices
share one wiring path: fixed-slot checks against guest RAM and against every
attached device's address and GSI, ioeventfd/irqfd registration with
rollback, and the irqfd drain/reassign around a pause.

Both devices run on one event thread. Its `EventManager` is created inside the
thread from the concrete devices, so the public `Subscriber` bounds are
unchanged; the control eventfd only wakes it, and commands arrive on a
channel. A freeze is acknowledged after the whole current callback batch has
returned and released every device lock; a frozen thread dispatches nothing
(no randomness written, no page reclaimed) and leaves queue notifications
pending, so a resumed source continues them. Each callback completes at most
64 descriptor chains and notifies itself for the rest. A restored thread
starts frozen and, on its first resume, notifies every ready queue itself,
independent of the source's notifications. Stop drops the command channel,
wakes and joins the thread, frozen or not. The RAM alias probe counts what the
devices really hold: one mapping clone per transport plus one per activated
device; the event thread holds none.

The image keeps the common virtio/MMIO transport state, activation and queues
of both devices, and the complete 16-byte balloon configuration. Completed
requests are never replayed, and a restored RNG draws fresh randomness. The
balloon's optional queues may stay unready after activation, so only ready
queues are checked against guest RAM.

The RNG writes each request through a 4 KiB buffer, at most 64 KiB per chain,
and completes it with the bytes that actually reached guest RAM; a failing
request completes once and is never rewound (previously it was both rewound
and completed, re-popping the same chain forever). The balloon validates a
whole report — every NEXT link resolves, every range is direct, page aligned
and inside one guest RAM region — before discarding anything; a malformed
report completes without discards (previously a valid prefix was discarded
descriptor by descriptor). Only page-aligned private anonymous RAM owned by
guest memory is discarded; other mappings ignore the hint and complete.

This remains an internal closed loop for the minimal VM: no full BoxLite box
restore and no virtio-fs support.

### Internal legacy UART, CMOS and i8042 checkpoints (stage 6, no feature)

`attach_legacy([COM1, COM2, COM3, COM4])` adds, before vCPUs start, the four
UARTs at ports 0x3f8/0x2f8/0x3e8/0x2e8 (IRQ 4/3/4/3; a port without an
endpoint is a sink), the CMOS at 0x70 and the i8042 at 0x60 (IRQ 1) on the
owner's port-I/O bus. The five interrupt eventfds join the shared irqfd
wiring: one irqfd per eventfd (COM1/COM3 and COM2/COM4 share a GSI), deassigned
and drained with the MMIO devices while paused. An interrupt already
injected lives in the saved KVM irqchip state and is never replayed.

Each endpoint is a `UnixStream` that must already be nonblocking; its file
status flags are checked, never changed. Guest output goes out with
`MSG_NOSIGNAL` (no SIGPIPE) and is never queued: a byte a full or closed peer
cannot take is dropped and counted (`serial_dropped_output_bytes`), but the
guest still sees the transmit complete with its THR interrupt. Input reads
one 256-byte chunk per readiness event into at most 4 KiB of unread input;
excess input is dropped and sets the LSR overrun bit, which an LSR read
clears. On hang-up, EOF or a read error the remaining data is drained up to
one byte past that capacity (a dropped tail still sets overrun) and the input
is unregistered: a closed peer neither spins the event loop nor reports
data-ready. Ordinary VMM UARTs keep unbounded input; only their empty-read
handling changed (an EOF read no longer sets data-ready).

The image keeps every UART register and its unread input, the CMOS index and
all 128 bytes, and the i8042 registers, last command and pending output in
read order (the ring cursors are rebuilt). Validation rejects register values
the emulation cannot reach, more than 4 KiB of input, data-ready flags that
disagree with the buffers, and CMOS memory-capacity bytes that differ from
the image's RAM layout. `RestoreResources::serial` supplies four fresh
endpoints, checked for nonblocking mode before any disk import or target VM
exists; output the source already sent is not replayed and the dropped
counts start at zero.

Every owner with vCPUs (started or full-restored) has one event thread, even
without devices:
it also reads UART input and watches the owner's exit eventfd, which the
i8042 reset, every vCPU exit and a fatal vsock backend failure (see below)
write. After the vCPU threads are created and
before any first runs, the thread receives a stop handle (command sender and
thread ID) per vCPU; the owner keeps the join handles. An exit latches
`exiting` and stops every vCPU. A frozen thread leaves the exit unread, so
`pause` checks the latch and the unread eventfd after the freeze;
`pause`, `save`, `export` and `resume` reject an exiting owner, an exit
found at the freeze boundary disables the owner and stops every thread, and
a latched exit is never saved, so a target never replays a reset. Cleanup always runs vsock
gate quiesce → event thread → vCPUs → disk/NIC/vsock workers → owned
resources, so no stop handle outlives its thread's join and no thread is
joined while a vsock send blocks it.

### Internal vsock checkpoints (stage 7, no feature)

`attach_vsock(cid, ports)` adds, before vCPUs start, one virtio vsock at MMIO
0xd000b000 with GSI 7 (guest kernel: `virtio_mmio.device=4K@0xd000b000:7`).
Only ordinary Unix IPC is supported, never TSI: `ports` maps each vsock port
to a host socket path and a role, `true` for a path the backend binds for
host-initiated connections, `false` for a host listener that guest-initiated
connections reach. The CID must be 3 to 2^32 - 2; paths must fit
`sun_path` and hold no NUL byte, and no two listening ports may share a
path (connecting ports may). `attach_vsock` and import reject a bad path
before any device, guest RAM or other resource exists.

Connections and RPCs do not survive a pause; guest listeners do. The guest
learns it from the transport reset event (virtio 1.2 §5.10.6.7, `le32 id`
0), and Linux guests then reset their established sockets.

| Step | What happens |
| --- | --- |
| pause | the owner quiesces the device's gate, kept since attach and used without the device lock: every live Unix socket is shut down through a duplicate the gate owns, cancelling a send blocked under the device lock (which the event thread or a vCPU's MMIO access could otherwise wait on forever), and the gate is held closed (a backend start racing the pause, such as a guest activation, exits at once). Then the vCPUs pause, the event thread freezes, and the backend stops: muxer and reaper joined, proxies, pending RX packets and backend RAM clones released, only the paths it bound removed. An activated device then completes every TX chain still in its ring with length 0 (head indexes only, never parsed), owes their interrupt and owes the guest a reset |
| export | saves the CID, port roles (never paths), transport, RX/TX/event queues, `reset_pending` and `interrupt_owed`; repeated exports and an export of an import before it runs keep both flags |
| import | `RestoreResources::vsock_ports` must name exactly the image's ports and roles, checked with the rest of the metadata (slot, CID, ordered ports, offered features, transport, activation, reset flags) before RAM exists; the rings and every TX head are checked against the loaded RAM; the device comes back frozen with its backend stopped, so nothing is bound until `resume` |
| resume | source or import: release the hold, write the reset into the next event buffer, complete the TX the guest queued before it could see the reset with length 0, then publish the reset's used entry (so a REQUEST the guest queues once it sees the reset is never dropped), raise the owed interrupt, then bind every original (source) or new (import) path and start the workers. No stale REQUEST or RW reaches a fresh connection. A path that cannot bind fails the resume, which disables the owner |

Without an event buffer the resume still raises the owed interrupt, but the
reset stays pending and the backend closed (TX stays in the ring) until the
guest kicks the event queue; that kick delivers the reset and opens the
backend. The whole event buffer chain is checked before anything is
written: every descriptor device-writable, every NEXT link to a valid
descriptor within the queue's chain limit (no invalid tail or cycle), every
declared range inside guest RAM, at least four bytes in total. A valid
chain may scatter the event (two 2-byte descriptors take it); any other
buffer completes with length 0, never counts as the delivery and keeps the
reset pending. A reopen that fails on such a kick (a listening path that
cannot bind, an interrupt that cannot be raised) has no caller to report
to: the backend is marked failed for good and the device writes the
owner's exit notifier, so the event thread latches the exit and stops
every vCPU at once; `pause`, `save`, `export` and `resume` then reject the
exiting owner, and teardown still joins every thread and releases the
backend. An
inactive device stays inactive and owes no reset; its resume only releases
the hold, so a later activation starts a backend.

A worker panic makes `stop_backend` return `BackendFailed` after joining
every other worker and running the whole cleanup; the failure is never
cleared and the backend never restarts. Dropping any vsock device, TSI
included, stops and joins its workers and removes the paths it bound.
Initial activation keeps the old policy: an occupied listening path is
skipped with a warning and left untouched. Guest driver reset is still
unsupported (the transport marks the device failed).

The device-level tests (`make snapshot-vsock-host-test`) cover blocked
sends cancelled by the gate for both directions, stale TX completed at the
stop and again before a reopen (no host connection, no answer), the event
queue empty then offered, held-gate kicks, malformed event buffers
(read-only, short, outside RAM, a declared range crossing the end of RAM
whose first four bytes fit, an invalid NEXT tail, a cycle, a read-only
tail) and a valid 2 + 2 byte chain, a REQUEST queued right after the reset
is published (a test hook at that point) kept while the older one is
dropped, a copied-RAM restore at fresh paths with the source continuing on
its own, inactive and TSI devices, the sticky deferred-reopen failure and
its notifier, and listener ownership. The owner tests without KVM cover
metadata, port/role (NUL bytes, shared listening paths) and ring
validation, the event thread freezing after the gate cancelled its blocked
send, and a deferred reopen failure on the event thread latching the exit
and stopping fake armed vCPUs. The KVM tests
(`vsock/kvm_tests.rs`) drive the device through the owner's MMIO bus with
the counter guest: two exports of one pause, source resume with the reset
and its interrupt first, import and export before it runs, both images
resumed at fresh paths in both directions with no stale request, a reset
waiting for an event buffer, an inactive device across an import, resource
errors and a failed restart that disables the owner. Real guest-agent
reconnection is not exercised: the harness boots no Linux guest.

Stage-7 validation status (macOS arm64 host, x86_64 Linux target):
`make snapshot-fmt`, `make snapshot-check` (also featureless
`SNAPSHOT_PKGS='-p krun-vmm'`), `make snapshot-build`,
`make snapshot-vsock-host-test` (16/16, native) and
`make snapshot-net-host-test` pass. `make snapshot-test` in the amd64
`rust:1-bookworm` container without `/dev/kvm`: 57/57 `krun-devices`
snapshot tests and 37 `krun-vmm` tests pass; the 37 tests that open KVM,
including the four vsock KVM tests, fail at opening `/dev/kvm` and are
**UNVERIFIED**, as is guest-agent reconnection.

### Internal virtio-console checkpoints (stage 8, no feature)

`attach_console(ports)` adds, before vCPUs start, one multiport virtio
console at MMIO 0xd000c000 with GSI 8 (guest kernel:
`virtio_mmio.device=4K@0xd000c000:8`), through the same slot, GSI and
irqfd/ioeventfd wiring as the other devices. `ports` is the ordered
`Vec<PortDescription>`: at least one port, with no count limit beyond the
32-bit queue index range (two control queues plus two per port). Only
built-in endpoints can be checkpointed: FD, empty and SIGINT input, FD and
log output, FD and fixed-size terminals. That covers the default console
(input, output and terminal) and named log, stdin, stdout and stderr ports.
Snapshot support is per endpoint type: only these built-in types report a
snapshot kind. A custom `PortInput`, `PortOutput` or
`PortTerminalProperties` keeps the trait's default (none), so
`attach_console` and import reject it before any probe, transport or wiring
exists; the ordinary console path, which never snapshots, still accepts it.

| Step | What happens |
| --- | --- |
| pause | after the vCPUs and the event thread (activation and control queues), every opened port's RX and TX worker confirms a freeze through the shared worker control; every worker wait (input, writable output, empty queue) answers it. RX commits the bytes it already read (used) and gives an unfilled buffer back; TX keeps a partly delivered chain popped, with the exact byte offset the host output accepted. Then the irqfds drain. Frozen, the console writes no guest RAM, ring or interrupt and reads or writes no endpoint; a resize request is deferred |
| export | a pure capture of the confirmed cut: transport, features, config space, every queue cursor and, per port, id, name, endpoint kinds, guest handshake (`ready`, `guest_open`), the last terminal size sent, `started`, EOF, the in-flight `{head, delivered}` and a log port's unfinished line, plus the control messages not yet delivered. Repeated exports are equal; a failed export removes its partial image and leaves the source paused, frozen and retryable |
| import | `RestoreResources::console_ports` gives fresh descriptions in the image's port order; names, directions and input, output and terminal kinds must match, checked with the rest of the metadata before RAM exists. Against the loaded RAM: ring checks for every ready queue (a driver may leave a port's queues unready), a strict walk of every available chain (links inside the table, no cycle, only NEXT/WRITE, the queue's direction, ranges inside RAM), ready queues for every worker of an opened port, exactly one popped but unused chain on a queue with an in-flight TX and none elsewhere, and an in-flight head that is the last chain popped with bytes left. The device then comes back without endpoint I/O and without a new guest handshake; opened ports get frozen workers, and the owner stays paused and exportable |
| resume | after the irqfds: the workers resume and re-examine their queue and endpoint, then the console processes its control queues and any deferred resize and raises its interrupt, so nothing waits for a new guest kick; then the event thread and the vCPUs |

Host acceptance is the delivery boundary. Bytes a source's output accepted
are never written again: an in-flight chain's remainder goes to the
source's own output when it resumes, or to the target's fresh output after
an import, and completes once. Input still unread in a source's host
descriptor is not migrated. A port at EOF never reads its fresh input
again. The control backlog, the guest handshake and a log port's half line
survive. The owner registers no SIGWINCH handler, so a restored FD
terminal reports the saved size. Teardown stops and joins every worker,
frozen or blocked on a full output, without waiting. A freeze or resume
that a worker cannot confirm (it is gone or timed out) disables the owner
and stops every thread.

Guest-facing descriptor rules (every console, snapshotted or not, and
independent of the endpoint types above): a control message goes whole into
the first descriptor of one device-writable buffer; a chained control
buffer is not split across descriptors, so a first descriptor too small for
the message stays with the guest and the message stays pending (Linux
drivers post single-descriptor buffers large enough for every message). A control transmit buffer that is shorter
than a message or device-writable completes with length 0 unread. Unready
control queues are never used, unknown port ids are ignored, and a repeated
`VIRTIO_CONSOLE_PORT_OPEN` keeps the running port. A guest reset clears the
pending messages and the handshake.

The device-level tests (`make snapshot-console-host-test`, native) cover:
- multiport RX/TX;
- partial TX under backpressure with exact-remainder resume after a restore with a fresh output, wrapping cursors included;
- freezes while input waits or streams in;
- EOF, control backlog, deferred resize, log half line, SIGINT and empty input;
- stability while frozen and no-kick resume;
- bounded reset and shutdown, frozen or under backpressure;
- custom-endpoint and mismatch rejection, malformed chains, cursors and in-flight offsets, started ports on unready queues;
- the control-queue edge cases above, and a worker that died before a freeze.

The owner tests without KVM (`console/tests.rs`) run the production build, restore, capture and validation code with the real event thread through the MMIO transport:
- export/import with the partial-TX remainder delivered once to a fresh output;
- the source resuming from the same cut;
- RAM alias counts, with no clone taken at capture;
- frozen kicks, inactive and midway-handshake round trips;
- 24 ports;
- resource, metadata and ring rejection;
- aborting a restored device with the production `discard` (the cleanup a failed import runs), with its workers frozen and again after resume with a worker blocked on a full output: every worker stops promptly and releases guest RAM. The test calls `discard` after a successful restore; it does not inject a restore failure.

The KVM tests (`console/kvm_tests.rs`) run the fixture's MMIO entry (0x900): the guest vCPU performs every console register access through a RAM mailbox, and a counter proves CPU continuation. They cover:
- restored I/O on replaced endpoints with no replay and no new handshake;
- a pending GSI-8 interrupt delivered exactly once after the restored guest's `sti`, with the guest reading its own RX data;
- repeated and failed exports, source resume and re-export before resume;
- multi-round no-kick resume;
- inactive and midway-handshake states;
- combinations with the RNG, balloon, vsock and legacy devices, and (with `blk` and `net`) an attached but inactive disk and NIC;
- failure cleanup and a dead worker disabling the owner.

Stage-8 validation status (macOS arm64 host, x86_64 Linux target):
`make snapshot-fmt`, `make snapshot-check` (also featureless
`SNAPSHOT_PKGS='-p krun-vmm'`), `make snapshot-build`, `make snapshot-test
SNAPSHOT_CARGO_FLAGS='--offline --no-run'`, `make snapshot-console-host-test`
(26/26, native), `make snapshot-net-host-test` (20/20) and
`make snapshot-vsock-host-test` (16/16) pass. `make snapshot-test` in the
amd64 `rust:1-bookworm` container without `/dev/kvm`: 83/83 `krun-devices`
snapshot tests and 45 `krun-vmm` tests pass, including the 8 console owner
tests without KVM. The 48 tests that open KVM, the 11 console KVM tests
among them, fail at opening `/dev/kvm` and are **UNVERIFIED**, as is a
Linux guest console driver (the harness boots no Linux guest).

### Internal virtio-fs session checkpoints (stage 12, in progress, Linux)

**Paused at the user's request on 2026-10-23.** Step 1 and its review
fixes are complete; step 2 reached investigation only and has no code changes.
See the [checkpoint and remaining work](docs/phase12-virtio-fs-snapshot.md)
before resuming. This checkpoint is not a complete virtio-fs VM snapshot.

Stage 12 adds virtio-fs to the owner in three steps. Only the first, the
device backend, exists so far: there is no `attach_fs`, no full-image
format change (the image stays version 6), no share archive, no DAX window
handling and no `RestoreResources` entry yet, so the owner still cannot
checkpoint a VM with virtio-fs.

A share opts in with `Fs::enable_snapshot` (`passthrough::Config::snapshot`)
before activation; ordinary shares and macOS keep the unchanged passthrough
behavior apart from the two Linux bounds fixes in the last item. The
backend provides:

- Worker control (`Fs::worker_control`): `freeze` lands between requests,
  after the last request's FUSE reply, used-ring entry and interrupt,
  `fdatasync`s every writable open handle and reports both queue cursors
  (high-priority queue first); a frozen worker serves nothing and writes no
  guest RAM, ring or interrupt. `resume` re-examines both queues itself, so
  notifications drained while frozen cannot stall requests; restored
  workers start frozen (`activate_frozen`). Dropping a device (also one an
  owner activated but never inserted) resets it: the worker is stopped and
  joined while its session and guest memory are still alive, and a reset
  device can be activated again.
- Session capture (`Fs::snapshot_session`, worker frozen): the negotiated
  FUSE options and `PassthroughState` — node IDs with lookup counts, handles
  with their node, open object and exact open flags (creation flags such as
  `O_TRUNC` are never recorded), directory lists, the node/handle/synthetic
  inode counters and the writeback/submount flags — plus, outside the
  serialized state, one descriptor per distinct host object (deduplicated by
  host device and inode) and the init.krun bytes the share serves. The
  capture is pure: it builds no directory list and moves no descriptor.
  It refuses a share that is not in snapshot mode, a handle the guest
  exported to another subsystem (`VIRTIO_IOC_EXPORT_FD`), and any node or
  handle on another host mount than the share root.
- Session restore (`Fs::restore_session` before `activate_frozen`): validates
  the state against this build (reserved init.krun node, handle and inode
  number, ID ranges and counters, duplicate IDs, object references, one
  node per object, handles not on the init.krun node and on the same object
  as their node while the guest still holds it — a handle whose node was
  forgotten stays valid —, no creating, truncating or `O_PATH` flags, entry
  names) and the options against the share before any host side effect, then rebuilds the
  node table from fresh `O_PATH` objects, reopens every handle with its
  saved flags and serves the given init.krun bytes. The guest continues with
  its original node IDs and handles and never sends FUSE_INIT again; the
  umask that FUSE_INIT cleared is cleared again.
- Stable directory streams: reading offset 0 (a new stream or a rewind)
  lists the whole directory through a new open file description, and every
  offset is the index after an entry, never a host `d_off`. A restored
  stream continues from its saved list even after the host directory
  changed; readdirplus skips names that no longer exist and does not look up
  "." and "..". A listed name that now names another object reports that
  object's inode number in both the entry and its attributes, and an entry
  the reply cannot take (full buffer or error) gives its lookup back.
  Directory entry names are bytes: names that are not UTF-8 list, look up
  and survive a restore like any other.
- Inode projection: a share that was never restored reports host inode
  numbers. A restore maps every rebuilt object to the inode number the guest
  saw and reserves every number in a saved directory list; a later object
  whose host number is already taken gets a synthetic number from 2^63 that
  no reservation or live node uses. init.krun's number (2) is always
  reserved, so a host object numbered 2 (an ext4 root, say) gets a
  synthetic number and a restore refuses an object saved with it. Restored
  objects report their saved ctime until their host ctime moves (a real
  modification).
- Bounds on every Linux share: ID counters never wrap. Once the node or
  handle counter is exhausted (`u64::MAX`, a valid saved state) every
  allocation fails with `EOVERFLOW` instead of reissuing 0, a reserved or a
  live ID; an exhausted handle counter fails a create before the file
  exists. Reads of init.krun at or past its end return EOF for any offset.

The device tests (`snapshot_fs` names, Linux, run by `make snapshot-test`)
cover the freeze boundary with a request held after its pop, frozen
re-freezes, resume without a kick, a frozen restored worker holding a
request posted at the cut, a device-level restore on the same host objects
(original node IDs and handles without FUSE_INIT, an `O_APPEND` handle whose
`O_TRUNC` is not replayed, directory continuation across an unlink and a new
file, rewind, fresh IDs after the saved counters, and source continuation),
stable lists and readdirplus skipping, readdirplus on a replaced name with
exact lookup counts after full-buffer and failed replies, non-UTF-8 names,
inode and ctime projection, init.krun's reserved number, restored lookup
counts and init.krun bytes, restored init.krun reads at, past and far past
its end, exhausted counters, a forgotten node's open handle, dropping an
activated restored device and reactivating a reset one, the export and mode
refusals, and malformed state and option rejection.

Stage-12 (step 1) validation status (macOS arm64 host, x86_64 Linux
target): `make snapshot-fmt`, `make snapshot-check` (also featureless
`SNAPSHOT_PKGS='-p krun-vmm'`) and `make snapshot-build` pass, and
`make snapshot-console-host-test` (26/26), `make snapshot-net-host-test`
(20/20) and `make snapshot-vsock-host-test` (16/16) pass natively. `make
snapshot-test` in the amd64 `rust:1-bookworm` container without `/dev/kvm`:
98/98 `krun-devices` snapshot tests pass, the 15 `snapshot_fs` tests among
them; the `krun-vmm` result is unchanged (45 pass, the 48 tests that open
KVM fail at `/dev/kvm`). The owner, image format, share archive, DAX and
every KVM or guest-driver check for virtio-fs are not implemented yet.

Local contributor checks (no public ABI or SDK entry point is provided):

```sh
make snapshot-fmt
make snapshot-check
make snapshot-build
make snapshot-test SNAPSHOT_CARGO_FLAGS='--offline --no-run'
make snapshot-test
make snapshot-net-host-test
make snapshot-vsock-host-test
make snapshot-console-host-test
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
natively (macOS or Linux, no KVM); `make snapshot-vsock-host-test` and
`make snapshot-console-host-test` do the same for the vsock backend
lifecycle and the console port worker tests. `snapshot-guest` regenerates the real-mode
timer, legacy and console MMIO-mailbox fixture using GNU
`SNAPSHOT_AS`/`SNAPSHOT_OBJCOPY` (on macOS, for example, inside the
`rust:1-bookworm` container); the block guest is
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
stage-2 counter guest proves CPU continuation: export during active traffic
with a partial frame and unconsumed TX, source continuation on its backend
after resume, import with a new backend (dropped TX, owed interrupt status,
paused CPU), resume traffic, inactive NIC plus disk, backend failure and
legacy-entry cleanup, a failed export that keeps CPU and NIC paused until
resume, and the shared GSI limit. No test has the
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

The stage-5 tests cover RNG error completion (buffer outside RAM, buffer
crossing the end of RAM, the 64 KiB cap, no second completion), whole-report
balloon validation (malformed NEXT tail, range crossing the end of RAM, then a
valid discard; Linux only), the event thread without KVM (frozen thread
dispatches nothing, the source resumes its pending notification, stop from
frozen, restored thread serves an un-notified request), old-version
rejection, resource matching, and one KVM round trip
(`event_devices/tests.rs`: pending un-notified RNG request and inactive
balloon across export, source continuation after resume, restored completion
and CPU continuation). Stage-5 validation status: `make snapshot-fmt` and
`make snapshot-check` pass; the non-KVM tests above, plus the existing NIC
metadata, ring and discard tests, pass when `make snapshot-test` runs inside
an amd64 `rust:1-bookworm` container (repository mounted at the same path,
host `~/.cargo/registry` and `config.toml` as `CARGO_HOME`, a separate
`CARGO_TARGET_DIR`). The KVM round trip and the existing KVM tests on the
unified full-image path are **UNVERIFIED** (no `/dev/kvm`).

The stage-6 tests cover the UART endpoint (blocking endpoint rejected with
flags unchanged; full and closed peers drop, count and still raise THR; the
4 KiB cap and overrun; EOF with no data, short data, exactly 4 KiB and an
over-capacity tail, each drained and unregistered without spinning), the
ordinary UART's EOF read, UART/CMOS/i8042 state round trips (wrapped i8042
cursors across the `usize` wrap, CMOS capacity mismatch), legacy metadata
and endpoint validation, and the exit watch without KVM (device-free thread
stops armed vCPUs; a frozen thread leaves the exit pending for the owner,
then stops on resume). One KVM test extends the stage-2 fixture
(`full/tests.rs`, entry 0x800): COM1 output and scratch, export, import with a
fresh endpoint and no replayed output, restored continuation, then a guest
i8042 reset; the guest keeps counting after it, so the test waits for the
vCPU thread to finish, checks the counter stays still, and that pause,
export and resume fail. Stage-6
validation status: `make snapshot-fmt`, `make snapshot-check` and the
featureless `krun-vmm` Linux test check pass; the non-KVM tests pass in the
amd64 container described above, and the ordinary-UART EOF test fails on the
unmodified tree (`EOF reported as data`). The KVM test is **UNVERIFIED** (no
`/dev/kvm`). Under `cfg(test)` a vCPU's own exit (HLT, shutdown, error) does
not write its exit eventfd, so vCPU-exit wiring is covered only by the
eventfd-level tests; the guest-driven path is the i8042 reset.

The lifecycle tests cover, without KVM, the vCPU pause/resume transition
(broadcast before waiting, timeout and exit, a late pause acknowledgment
before its resume, a disconnected channel with every vCPU still attempted)
and RAM image publication (mid-copy and magic failures remove the file).
With KVM (`full/tests.rs`, `tests.rs`): export and resume of a running owner
and a second pause are rejected; two exports of one pause hold identical
RAM while the guest stays still; an import is exported again before it runs
and that image continues the guest; a pause timeout, a vCPU exiting on
resume and an unanswered state request each disable the owner and join
every vCPU thread, while a state request answered with an error keeps the
pause retryable; failed exports (existing file, mid-copy write, external
RAM alias) keep the guest paused and a retry publishes; a paused RAM-only
save never resumes. The block, NIC and RNG/balloon continuation tests use
`pause`, `export` and an explicit source `resume`; a failed NIC export also
checks that CPU and NIC stay frozen until `resume`.

Lifecycle validation status (macOS arm64 host, x86_64 Linux target):
`make snapshot-fmt`, `make snapshot-check` (also with
`SNAPSHOT_PKGS='-p krun-vmm'`, featureless), `make snapshot-build` and
`make snapshot-net-host-test` pass. `make snapshot-test` with the amd64
`rust:1-bookworm` runner and no `/dev/kvm`: all 41 `krun-devices` snapshot
tests and 30 `krun-vmm` tests pass, including the non-KVM lifecycle tests;
the 33 tests that open KVM, including every KVM lifecycle and continuation
test above, fail at opening `/dev/kvm` and are **UNVERIFIED**.

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
and keep a TCP connection open; `pause` and `export`; stop the source VM and
its backend; start a new backend at a new socket; `import` with that
`nic_socket` and `resume`. Expected: the old TCP connection fails or times out, new name
lookups and new TCP connections succeed, interface counters keep moving and
the guest kernel logs no virtio-net ring errors.

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).
