# Memory snapshot PR series

## Baseline and scope

Prepared against `e12b9b3780ffa8df9f3e1797b217d13453479167` (main), using
`2294eeafde8777c3d7531763452130360ec0a3dd` (origin/x_features) as reference only.
The checkout is shallow; the investigation uses two-tree diffs, not an assumed
merge base. No merge or whole-commit cherry-pick is needed.
The local first-PR branch is `lfld287/memory-snapshot`. Keep origin's fetch URL
at boxlite-ai/libkrun and push URL at lfld287/libkrun. Publish this first PR from
`lfld287:lfld287/snapshot-01-ram-codec` to `boxlite-ai/libkrun:main`; the fork's existing
`lfld287/memory-snapshot` branch contains the old large implementation and must
not be overwritten or merged into this increment.

There is no repository AGENTS.md, CONTRIBUTING file or production-line counting
rule in this checkout. README.md requires a small VMM and a stable C ABI.
Existing CI requires Rust formatting, Clippy, Linux tests and macOS builds;
see `.github/workflows/{formatting,code-quality,unit_tests,cross-compilation}.yml`.

The first deliverable is an actual RAM-only image codec. It does not pause a VM
or claim that RAM alone can resume one. Its Rust API can be exercised without a
hypervisor on macOS and Linux; it adds no public C ABI or dependencies. The
subsequent runnable checkpoint target is Linux/x86_64/KVM, non-TEE, non-Nitro,
fixed anonymous RAM, initially with an initramfs and a restricted device set.
macOS/HVF, Linux/aarch64 and RISC-V VM restore remain unsupported, as in the old
implementation. Unsupported configurations must fail before resources open.

The initial VM series excludes GPU, sound, input, memory hotplug, shared/DAX
memory, virtio-fs, NICs, vsock/TSI and host socket migration. Block and console
support have their own increments below. This is a deliberately restricted
checkpoint milestone, not parity with all of x_features. Disk contents remain
an external dependency and must match the checkpoint; a RAM snapshot is not a
disk backup. No compatibility promise is made for the old full-image v9 format.

## Byte API and single-file artifact

The codec returns an owned `Vec<u8>` from `save(&GuestMemoryMmap)` and accepts a
borrowed `&[u8]` in `restore`. Neither function takes resource-limit arguments.
It does not open, create, sync or delete files.
The caller can pass the bytes to another component or persist them as one file.
Export currently allocates an additional buffer approximately the size of RAM.

`get_metadata(&[u8])` returns the format version, total RAM payload bytes and
region addresses/lengths without allocating guest RAM. Callers may inspect
`metadata.regions.len()` and `metadata.memory_bytes` to enforce their own limits,
check page alignment or otherwise accept/reject the layout before `restore`.
The codec retains encoding checks (header/version, reserved fields, lengths and
arithmetic) and refuses source mappings without read permission. It imposes no
region-count/memory-budget limits or fixed page alignment; file/shared mappings
can be copied when the caller quiesces every writer. Invalid destination mappings
are reported by GuestMemoryMmap during restore. These bytes capture contents,
not host backing-file identities or sharing relationships.

The final VM checkpoint must also be **one file**: a versioned envelope holds
CPU/VM/device metadata and RAM sections together, without metadata sidecars or
per-region files. A section can be handed to this codec as a borrowed byte
slice. The embedding application owns file publication and storage policy;
C bindings will use buffers and lengths with explicit ownership. External disk
images remain workload dependencies, not extra memory-checkpoint files.

## Findings that determine the boundaries

* `ram_snapshot.rs` combines a v1 RAM codec, mapping checks, file publication,
  vCPU control and a VM owner (904 raw lines). Extract the working codec first;
  do not pull its device, boot or lifecycle imports along with it.
* main's `linux/vstate.rs` already has VmState/VcpuState, save/restore methods
  and Pause/Resume channels. The old `linux/vstate/snapshot.rs` adds 804 lines
  for CPUID/XSAVE/MSR/TSC compatibility and owning-thread requests. Extend the
  existing facilities in separate steps; replacing that entire file is too big.
* `virtio/persist.rs` contains queue cursors that are absent from guest RAM,
  queue validation, common device state and MMIO state. These have separate
  consumers. `virtio/control.rs` supplies bounded worker requests; merely
  stopping vCPUs does not stop disk, console or event-loop writes to RAM.
* `ram_snapshot/{lifecycle,events,boot,full,wiring}.rs` and `snapshot_vm.rs`
  coordinate freeze, import-before-run, boot and resource ownership. Their
  final versions depend on nearly every device extension; importing them
  unchanged would make the first steps uncompilable.
* `libkrun/snapshot{.rs,/control.rs,/descriptor.rs}` separates context setup,
  concurrent commands and FD ownership. Expose C entry points only after
  the corresponding VM operations work; do not add success-returning stubs.
* `virtio/fs/linux/passthrough/{snapshot,dax,archive*}` and the VMM fs adapter
  implement filesystem identity, live handles, DAX and archives, not just RAM.
  `virtio/mem/*` is memory hotplug. Neither belongs in this first series.
* Baseline macOS VMM checking works with the existing init override described
  below. Do not import the old trailing-comma fix speculatively; only include
  it in the device PR that introduces the affected invocation, if needed.

## Ordered PRs

Budgets below count **added plus deleted nonblank, non-comment production
lines**, including module wiring, manifests and headers. They are estimates,
not measurements of unimplemented code. Every row is a separate future PR,
with an absolute gate of 400; aim below 360 to leave integration room. If a
row exceeds its budget, revise its boundary before implementation/landing.
Each step must build and provide the named real operation; serialized types
alone or unused placeholder traits are not a delivery milestone.

`H` = host tests without KVM (macOS and Linux), format and focused Clippy.
`K` = Linux/x86_64 with /dev/kvm, including actual paused-state round trips.
`F` = default and applicable feature checks (blk/net, TEE and unsupported
platform builds); do not conflate cross-compilation with runtime tests.

| PR | Goal and production scope | Prerequisites | Budget | Verification |
|---|---|---|---:|---|
| 01 | RAM v1 byte encode/decode and metadata inspection, caller-owned resource policy; `vmm/ram_snapshot.rs` | main | 330 | H: discontiguous byte round trip, borrowed container section, metadata policy inputs, malformed images |
| 02 | vCPU pause acknowledgements, bounded requests and terminal timeout handling; existing `linux/vstate.rs` channels | 01 | 280 | K: pause/resume, repeated pause, exit/disconnect/late reply |
| 03 | Capture/restore existing CPU state on the owning paused thread; `vstate.rs`, new `vstate/snapshot.rs` | 02 | 340 | K: register continuation, running-state refusal, no missed replies |
| 04 | Dynamic XSAVE sizing, XCRS and partial MSR transfer checks in the existing state methods | 03 | 340 | H: sizes/order; K: extended state, supported MSRs |
| 05 | CPUID/KVM compatibility checks used by CPU capture and restore; serde wiring only as needed | 04 | 350 | H: incompatible layouts/topology; K: actual target capabilities |
| 06 | TSC frequency/deadline ordering and multi-vCPU offset synchronization | 05 | 300 | K: two-vCPU time/interrupt continuation; incompatible target refusal |
| 07 | VM clock/PIT/irqchip state serialization and validation around existing VmState methods | 06 | 280 | H: malformed state; K: timer/interrupt round trip |
| 08 | Minimal owner of fixed anonymous RAM, Vm and vCPU handles, with paused construction and ordered teardown; `snapshot_vm.rs` | 07 | 340 | K: construct, pause/resume and stop a device-free test guest; repeated failure cleanup |
| 09 | Single-buffer versioned CPU/VM metadata + RAM envelope exported from the paused owner | 08 | 350 | H: lengths/version/metadata limits; K: live export refusal, incomplete export |
| 10 | Restore a borrowed envelope byte slice into a new paused owner; validate before RAM allocation or KVM mutation | 09 | 350 | K: guest continuation, multi-vCPU round trip, failure keeps guest stopped |
| 11 | Virtqueue save/restore with ring cursor, range and wrapping validation; `virtio/persist.rs`, `queue.rs` | 10 | 300 | H: real rings, u16 wrap, invalid ranges, inactive queues |
| 12 | Common virtio device and MMIO save/restore, preserving selectors/interrupt status; `persist.rs`, `mmio.rs` | 11 | 320 | H: transport round trip without renegotiation |
| 13 | Bounded worker control plus block worker freeze/flush/resume; `virtio/control.rs`, `block/worker.rs` | 12 | 350 | H: outstanding I/O, flush errors, timeout/late reply, frozen start |
| 14 | Block device state capture and frozen activation; `block/device.rs` | 13 | 300 | H: queues/features/capacity; no I/O until resume |
| 15 | Block owner wiring and external image identity validation; VMM block adapter | 14 | 350 | K + F(blk): buffered disk continuation; reject unsupported disk/backend changes |
| 16 | Freeze/resume the owner's event dispatch between callback batches; VMM events/lifecycle | 15 | 330 | H: callback race/timeout; K: no RAM writers at snapshot boundary |
| 17 | RNG state/frozen activation and owner wiring; `rng`, event-device adapter | 16 | 300 | H/K: pending queue after resume, no entropy writes while paused |
| 18 | Balloon reporting state/frozen activation and owner wiring; `balloon`, event-device adapter | 17 | 300 | H/K: no reclamation during capture, pending notifications |
| 19 | UART, CMOS and i8042 persistence and owner wiring; legacy devices | 18 | 350 | H/K: pending IRQ/input and reboot/exit behavior |
| 20 | Console port worker freeze/resume and shutdown; `console/{port,worker,process_*}` | 19 | 350 | H: blocked host I/O, output completion, timeout, shutdown |
| 21 | Console device/control-queue persistence and frozen activation; `console/{persist,device,event_handler}` | 20 | 350 | H: control messages, port state, inactive/active queues |
| 22 | Console snapshot owner wiring and new output endpoint binding | 21 | 300 | K: guest continues output once; failed import does not overwrite existing output |
| 23 | Restricted Linux payload preparation using existing builder helpers; `builder.rs`, snapshot boot module | 22 | 340 | H: reject excluded devices/TEE/Nitro/nested configs before opening resources; K: initramfs boot |
| 24 | Boot/restore routing and lifecycle facade on the owner; `snapshot_vm.rs` | 23 | 330 | K: boot → pause → export → stop → import → resume, exit status, multi-vCPU |
| 25 | C context opt-in plus working pause/resume/state/stop routing; `libkrun/snapshot/control.rs`, `lib.rs`, header | 24 | 350 | H/K + F: context races, errno, unsupported platforms return ENOTSUP |
| 26 | C buffer/length export with explicit allocation/release and external disk binding; snapshot module and header | 25 | 350 | H/K: buffer lifetime/release, failure ownership, C ABI consumer |
| 27 | C buffer/length import setup and start-enter routing into paused restore; libkrun snapshot module | 26 | 350 | K + F: C boot/export/import/continue, input lifetime, no payload reload during import |

PRs 20–24 need particular care: the old console/boot code includes broader
device support. Preserve the restricted milestone and reuse existing helpers;
do not squeeze the old files into these budgets. If the minimal implementation
still exceeds 400, split by a functioning operation (e.g. port shutdown before
port freezing, or initramfs boot before block boot), then recount both PRs.

NIC/UnixStream reconnect, vsock Unix IPC, virtio-fs session restore, DAX,
filesystem archives and virtio-mem require later separately budgeted series.
They are not hidden dependencies of PRs 01–27 and must remain rejected in the
checkpoint configuration until supported. Before scheduling them, inspect the
relevant worker/backend diffs again and publish their own per-PR plans.

## Branch and counting procedure

Only PR 01 is implemented in this checkout. Subsequent local branches may stack
on their prerequisites, but a branch is ready to target main only after all of
its prerequisites have landed there and it has been rebased onto that main.
Count the **whole PR against its target main**, never individual commits. Do
not open all stacked branches against today's main and report adjacent diffs.

At each boundary record `git diff --numstat BASE HEAD` and `git diff --stat
BASE HEAD`, plus the production added/deleted count. Keep behavioral tests in
`ram_snapshot/tests.rs` (later each corresponding module's tests); these are
test code, while `#[cfg(test)] mod tests;` wiring is conservatively production.
Documentation is counted separately. Cargo/build/header changes are production;
lockfiles or generated changes must be reported separately and never used to
conceal implementation. This PR adds no generated files or lockfile changes.

For PR 01, filtering changed lines in `git diff --unified=0 BASE HEAD --
src/vmm/src/lib.rs src/vmm/src/ram_snapshot.rs` by nonempty content and excluding
lines whose trimmed content starts with `//` gives the production count (these
files add no block comments or multiline strings). Count `+` and `-` separately,
excluding diff headers, then add them. For later mixed-language/mixed-test
patches inspect syntax and classification; this simple filter is not a general
Rust lexer. Reformatting/deletion still counts; do not minify to pass the gate.

## Local validation conditions

Host: macOS arm64. A direct `cargo check --locked -p krun-vmm` on untouched main
fails building Linux init (`sys/statfs.h`, `linux/if.h` absent). Using the
repository-supported `KRUN_INIT_BINARY_PATH=/dev/null` override allows pure
Rust checks/tests without building or running init. This is an empty init
placeholder, not a working guest or evidence of Linux/HVF VM execution.

PR 01 checks: `cargo fmt --all -- --check`, `git diff --check`, and with that
override, `cargo test --locked -p krun-vmm ram_snapshot`,
`cargo check --locked -p libkrun --features blk,net`, and focused Clippy. Record
actual results and pre-existing failures in the delivery report. Linux/KVM checks
must run on a suitable remote host, as recorded below. A real
Linux-init macOS build remains unverified; later K-marked implementation steps
will still need their own runtime validation.

## PR 01 result

Implemented `ram_snapshot::save(&GuestMemoryMmap) -> io::Result<Vec<u8>>`,
`get_metadata(&[u8]) -> io::Result<Metadata>` and
`restore(&[u8]) -> io::Result<GuestMemoryMmap>` using the reference RAM v1 layout.
Metadata exposes version, total RAM bytes and each region's address/length.
Resource and platform policy belongs to callers; the codec checks encoding and
copies readable mappings into independent anonymous guest RAM on restore.
Callers must quiesce all RAM writers during export. No filesystem operations,
payload checksum, production VM lifecycle, device snapshot or C entry point
was added.

Validation on macOS arm64 (2026-11-04):

* PASS: `cargo fmt --all -- --check` and `git diff --check`.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo test --locked -p krun-vmm ram_snapshot`
  — 5 passed; the subsequent full `cargo test --locked -p krun-vmm` also passed
  all 25 tests, with no ignored tests.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo clippy --locked -p krun-vmm --no-deps -- -D warnings`.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo check --locked -p libkrun --features blk,net`.
* The macOS init override supplies an empty placeholder solely for these checks.

Additional validation on a Linux x86_64 host with readable/writable /dev/kvm,
Rust 1.99.1 and a real compiled Linux init (no placeholder):

* PASS: `cargo test --locked -p krun-vmm` — 30 passed, 0 failed, 1 ignored
  (`linux::vstate::tests::test_get_supported_cpuid` already has `#[ignore]` in main).
  Includes existing KVM memory initialization, vCPU configuration and kick tests.
* PASS: `cargo check --locked -p libkrun --features blk,net`.
* Strict `cargo clippy --locked -p krun-vmm --no-deps -- -D warnings` encounters
  main's existing `clippy::byte_char_slices` at `builder.rs:1186`; this PR does not
  change that file. The same command with `-A clippy::byte_char_slices` passes.
* Sources were exported from commit `2982774` into a fresh remote temporary
  directory; the RAM codec and test file SHA-256 hashes matched the local files.
  Subsequent changes only update this validation/branch record.

Not run: full feature/platform CI, a macOS build with a real cross-compiled
Linux init, or VM checkpoint boot/continuation (not implemented by this PR).

Whole-PR count against the baseline above (including this plan):

| Category | Raw additions | Raw deletions | Nonblank, non-comment code additions + deletions |
|---|---:|---:|---:|
| Production (`lib.rs`, `ram_snapshot.rs`) | 162 | 0 | **124 + 0 = 124** |
| Tests (`ram_snapshot/tests.rs`) | 162 | 0 | 149 + 0 |
| Documentation (this file) | 233 | 0 | n/a |
| Total | 557 | 0 | Production gate: **124 <= 400** |

No manifest, lockfile, generated artifact or unrelated platform fix changed.
