# Memory snapshot PR series

## Baseline and scope

Prepared against `e12b9b3780ffa8df9f3e1797b217d13453479167` (main), using
`2294eeafde8777c3d7531763452130360ec0a3dd` (origin/x_features) as reference only.
The checkout is shallow; the investigation uses two-tree diffs, not an assumed
merge base. No merge, whole-commit cherry-pick, push or remote PR is needed.
The local first-PR branch is `lfld287/memory-snapshot`. Keep origin's fetch URL
at boxlite-ai/libkrun and push URL at lfld287/libkrun.

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
| 01 | RAM v1 save/restore, checked layout, exclusive output, bounded allocation; `vmm/ram_snapshot.rs` | main | 330 | H: discontiguous/chunked byte round trip, malformed images, mapping refusal, no overwrite |
| 02 | vCPU pause acknowledgements, bounded requests and terminal timeout handling; existing `linux/vstate.rs` channels | 01 | 280 | K: pause/resume, repeated pause, exit/disconnect/late reply |
| 03 | Capture/restore existing CPU state on the owning paused thread; `vstate.rs`, new `vstate/snapshot.rs` | 02 | 340 | K: register continuation, running-state refusal, no missed replies |
| 04 | Dynamic XSAVE sizing, XCRS and partial MSR transfer checks in the existing state methods | 03 | 340 | H: sizes/order; K: extended state, supported MSRs |
| 05 | CPUID/KVM compatibility checks used by CPU capture and restore; serde wiring only as needed | 04 | 350 | H: incompatible layouts/topology; K: actual target capabilities |
| 06 | TSC frequency/deadline ordering and multi-vCPU offset synchronization | 05 | 300 | K: two-vCPU time/interrupt continuation; incompatible target refusal |
| 07 | VM clock/PIT/irqchip state serialization and validation around existing VmState methods | 06 | 280 | H: malformed state; K: timer/interrupt round trip |
| 08 | Minimal owner of fixed anonymous RAM, Vm and vCPU handles, with paused construction and ordered teardown; `snapshot_vm.rs` | 07 | 340 | K: construct, pause/resume and stop a device-free test guest; repeated failure cleanup |
| 09 | Versioned CPU/VM metadata envelope and checked RAM export from the paused owner | 08 | 350 | H: lengths/version/metadata limits; K: live export refusal, incomplete export |
| 10 | Restore envelope into a new paused owner; validate before RAM allocation or KVM mutation | 09 | 350 | K: guest continuation, multi-vCPU round trip, failure keeps guest stopped |
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
| 26 | C descriptor-based export with explicit external disk binding/ownership; snapshot descriptor module and header | 25 | 350 | H/K: FD lifetime/duplication, failure ownership, C ABI consumer |
| 27 | C import setup and start-enter routing into paused restore; libkrun snapshot module | 26 | 350 | K + F: C boot/export/import/continue, no payload reload during import |

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
actual results and pre-existing failures in the delivery report. Linux/KVM
tests and a real Linux-init macOS build remain necessary on suitable hosts;
later K-marked steps cannot be called runtime-validated on this machine.

## PR 01 result

Implemented `ram_snapshot::save` and `restore` with the reference RAM v1 layout,
64 KiB bounded copying, ordered/nonoverlapping 4 KiB guest regions, checked
arithmetic, exact file length and caller-supplied region/memory limits before
RAM allocation. Save accepts only owned private anonymous mappings, creates a
new 0600 file and writes the completion magic last. Failed writes use best-effort
invalidation/unlink. Callers must quiesce all RAM writers and exclusively own
the output path; restore requires a stable input file. This format has no payload
checksum or directory crash-durability guarantee. No production lifecycle,
kernel mapping exception, device snapshot or C entry point was added.

Validation on macOS arm64 (2026-11-04):

* PASS: `cargo fmt --all -- --check` and `git diff --check`.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo test --locked -p krun-vmm ram_snapshot`
  — 7 passed, 0 failed, 20 unrelated tests filtered out.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo clippy --locked -p krun-vmm --no-deps -- -D warnings`.
* PASS: `KRUN_INIT_BINARY_PATH=/dev/null cargo check --locked -p libkrun --features blk,net`.
* Not run: Linux/KVM tests, VM boot/continuation, full feature/platform CI and a
  macOS build with a real cross-compiled Linux init. The init override above
  supplies an empty placeholder solely for these host checks.

Whole-PR count against the baseline above (including this plan):

| Category | Raw additions | Raw deletions | Nonblank, non-comment code additions + deletions |
|---|---:|---:|---:|
| Production (`lib.rs`, `ram_snapshot.rs`) | 248 | 0 | **211 + 0 = 211** |
| Tests (`ram_snapshot/tests.rs`) | 196 | 0 | 184 + 0 |
| Documentation (this file) | 187 | 0 | n/a |
| Total | 631 | 0 | Production gate: **211 <= 400** |

No manifest, lockfile, generated artifact or unrelated platform fix changed.
