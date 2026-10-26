// SPDX-License-Identifier: Apache-2.0
//
// The checkpoint C API as C callers see it: libkrun.h compiles, each
// declaration has the exact signature and constant the contract names, and
// the built library exports and answers them (no KVM needed). Run by
// `make snapshot-abi-check`.

// libkrun.h uses uid_t and gid_t from <unistd.h>, which strict C11 hides.
#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "libkrun.h"

_Static_assert(KRUN_SNAPSHOT_PAUSE_HOST_WRITERS_STOPPED == 1u, "pause flag");
_Static_assert(KRUN_SNAPSHOT_STATE_CONFIGURED == 0, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_STARTING == 1, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_RUNNING == 2, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_PAUSED == 3, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_EXITED == 4, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_FAILED == 5, "state");
_Static_assert(KRUN_SNAPSHOT_STATE_STOPPED == 6, "state");

// Each assignment fails to compile unless the declaration matches exactly.
static int32_t (*const enable)(uint32_t, uint32_t) = krun_snapshot_enable;
static int32_t (*const import_vm)(uint32_t, const char *, const char *,
                                  const char *) = krun_snapshot_import;
static int32_t (*const pause_vm)(uint32_t, uint32_t) = krun_snapshot_pause;
static int32_t (*const resume_vm)(uint32_t) = krun_snapshot_resume;
static int32_t (*const export_vm)(uint32_t, const char *) = krun_snapshot_export;
static int32_t (*const stop_vm)(uint32_t) = krun_snapshot_stop;
static int32_t (*const get_state)(uint32_t, uint32_t *, int32_t *) =
    krun_snapshot_get_state;
static int32_t (*const restored_share)(uint32_t, const char *, char *, size_t) =
    krun_snapshot_get_restored_share;

static int failures;

static void expect(const char *what, int32_t got, int32_t want) {
    if (got != want) {
        fprintf(stderr, "%s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

int main(void) {
    int32_t ctx = krun_create_ctx();
    if (ctx < 0) {
        fprintf(stderr, "krun_create_ctx: %d\n", ctx);
        return 1;
    }
    uint32_t id = (uint32_t)ctx;
    uint32_t state = 99;
    int32_t code = 99;
    char path[64];

    expect("enable with a reserved flag", enable(id, 1), -EINVAL);
    expect("enable", enable(id, 0), 0);
    expect("get_state", get_state(id, &state, &code), 0);
    expect("state", (int32_t)state, KRUN_SNAPSHOT_STATE_CONFIGURED);
    expect("exit code", code, 0);
    expect("import relative", import_vm(id, "image", NULL, NULL), -EINVAL);
    expect("import", import_vm(id, "/box/image", "/box/disks", NULL), 0);
    expect("pause before start", pause_vm(id, KRUN_SNAPSHOT_PAUSE_HOST_WRITERS_STOPPED), -EAGAIN);
    expect("pause unknown flag", pause_vm(id, 2), -EINVAL);
    expect("resume before start", resume_vm(id), -EAGAIN);
    expect("export before start", export_vm(id, "/box/export"), -EAGAIN);
    expect("stop before start", stop_vm(id), -EAGAIN);
    expect("restored share", restored_share(id, "volume0", path, sizeof path), -ENOENT);
    expect("free", krun_free_ctx(id), 0);
    expect("get_state after free", get_state(id, NULL, NULL), -ENOENT);
    expect("stop after free", stop_vm(id), -ENOENT);

    if (failures) {
        return 1;
    }
    printf("snapshot C ABI: ok\n");
    return 0;
}
