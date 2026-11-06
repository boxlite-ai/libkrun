// SPDX-License-Identifier: Apache-2.0
// Native macOS/HVF execution check, not a checkpoint roundtrip.
#include "libkrun.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static uint32_t context;
static const char *root;
static void check(int result, const char *operation) {
    if (result < 0) { fprintf(stderr, "%s: %d\n", operation, result); exit(1); }
}
static void *online_control(void *unused) {
    (void)unused;
    char path[4096]; struct stat state;
    snprintf(path, sizeof(path), "%s/progress", root);
    for (unsigned i = 0; i < 60000; ++i) {
        if (stat(path, &state) == 0 && state.st_size > 0) {
            int result = krun_save_checkpoint(context, "/unused-hvf-checkpoint", NULL, NULL);
            if (result != -ENOTSUP) abort();
            snprintf(path, sizeof(path), "%s/api-result", root);
            FILE *file = fopen(path, "w");
            if (!file) abort();
            fprintf(file, "%d\n", result);
            if (fflush(file) || fsync(fileno(file)) || fclose(file)) abort();
            return NULL;
        }
        usleep(1000);
    }
    abort();
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    root = argv[1];
    check(krun_set_log_level(3), "logging");
    int ctx = krun_create_ctx(); check(ctx, "create"); context = ctx;
    check(krun_set_vm_config(context, 2, 256), "configuration");
    check(krun_set_root(context, root), "root");
    check(krun_set_console_output(context, argv[2]), "console");
    check(krun_disable_implicit_vsock(context), "vsock");
    check(krun_add_disk(context, "data", argv[3], false), "disk");
    if (krun_set_checkpointing(context, true) != -ENOTSUP) abort();
    if (krun_set_checkpoint_restore(context, "/unused-hvf-checkpoint") != -ENOTSUP) abort();
    const char *args[] = {NULL};
    const char *env[] = {"PATH=/bin:/usr/bin", "KRUN_TEST_TICKS=32", NULL};
    check(krun_set_exec(context, "/checkpoint-guest", args, env), "exec");
    pthread_t thread;
    if (pthread_create(&thread, NULL, online_control, NULL)) abort();
    check(krun_start_enter(context), "enter");
    return 1;
}
