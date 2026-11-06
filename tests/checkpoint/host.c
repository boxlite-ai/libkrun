// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include "libkrun.h"
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

static uint32_t context;
static const char *destination;
static sigset_t signals;
static const char *root;
static int hotplug;
static void check(int result, const char *operation);

static int32_t fail_then_copy(const char *id, const char *source, const char *target, uint32_t format, void *opaque) {
    (void)id; (void)opaque;
    static int first = 1;
    if (first) { first = 0; return -EIO; }
    if (format != 0) return -ENOTSUP;
    FILE *in = fopen(source, "rb"), *out = fopen(target, "wbx");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return -EIO; }
    char bytes[65536]; size_t count;
    while ((count = fread(bytes, 1, sizeof(bytes), in))) if (fwrite(bytes, 1, count, out) != count) break;
    int failed = ferror(in) || ferror(out) || fflush(out) || fsync(fileno(out));
    fclose(in); fclose(out);
    return failed ? -EIO : 0;
}

// Calls the application's existing flatten implementation synchronously.
static int32_t flatten_disk(const char *id, const char *source, const char *target, uint32_t format, void *opaque) {
    (void)id; (void)opaque;
    if (format != KRUN_DISK_FORMAT_QCOW2) return -ENOTSUP;
    char *args[] = {getenv("KRUN_TEST_FLATTEN"), "flatten", (char *)source, (char *)target, NULL};
    pid_t pid; int status;
    int error = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    if (error) return -error;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -errno;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

static void grow_memory(void) {
    int requested = -EAGAIN;
    for (unsigned i = 0; i < 2000 && requested == -EAGAIN; ++i) {
        requested = krun_request_memory(context, 384);
        if (requested == -EAGAIN) usleep(10000);
    }
    check(requested, "request memory");
    struct krun_memory_status status;
    for (unsigned i = 0; i < 2000; ++i) {
        check(krun_get_memory_status(context, &status), "memory status");
        if (status.plugged_mib == 384) break;
        usleep(10000);
    }
    if (status.plugged_mib != 384 || status.mapped_mib != 384) { fprintf(stderr, "MEMORY did not grow: %u %u error=%d\n", status.plugged_mib, status.mapped_mib, status.error); abort(); }
    char path[4096];
    snprintf(path, sizeof(path), "%s/allocate-hotplug", root);
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) abort(); close(fd);
    snprintf(path, sizeof(path), "%s/hotplug-ready", root);
    for (unsigned i = 0; i < 2000 && access(path, F_OK); ++i) usleep(10000);
    if (access(path, F_OK)) abort();
    fprintf(stderr, "MEMORY 384 384\n");
}

static void check(int result, const char *operation) {
    if (result < 0) { fprintf(stderr, "%s: %d\n", operation, result); exit(1); }
}

static void *save(void *unused) {
    (void)unused;
    for (;;) {
        int signal;
        if (sigwait(&signals, &signal)) abort();
        if (hotplug) grow_memory();
        int result = krun_save_checkpoint(context, destination, getenv("KRUN_TEST_FLATTEN") ? flatten_disk : (getenv("KRUN_TEST_FAIL_EXPORT") ? fail_then_copy : NULL), NULL);
        fprintf(stderr, "CHECKPOINT %d\n", result);
        fflush(stderr);
    }
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s boot|restore rootfs checkpoint console [raw-disk]\n", argv[0]); return 2; }
    root = argv[2]; hotplug = getenv("KRUN_TEST_HOTPLUG") != NULL;
    sigemptyset(&signals); sigaddset(&signals, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &signals, NULL)) abort();
    check(krun_set_log_level(3), "log");
    int ctx = krun_create_ctx(); check(ctx, "create"); context = ctx;
    check(krun_set_vm_config(context, 2, 256), "vm config");
    if (hotplug) {
        check(krun_set_memory_hotplug(context, 384), "hotplug config");
        check(krun_add_kernel_cmdline(context, "memhp_default_state=online_movable"), "auto-online memory");
    }
    int block_root = getenv("KRUN_TEST_BLOCK_ROOT") != NULL;
    if (!block_root) check(krun_set_root(context, argv[2]), "root");
    check(krun_set_console_output(context, argv[4]), "console");
    // Network lifecycle is tested separately; this fixture isolates the CPU,
    // virtio-fs, console and disk continuation boundary.
    if (!getenv("KRUN_TEST_TSI")) check(krun_disable_implicit_vsock(context), "disable implicit vsock");
    const char *net_path = getenv("KRUN_TEST_NET_SOCKET");
    if (net_path) {
        uint8_t mac[6] = {2, 0, 0, 0, 0, 1};
        check(krun_add_net_unixstream(context, net_path, -1, mac, 0, 0), "net backend");
    }
    const char *args[] = {NULL};
    const char *env[] = {"PATH=/bin:/usr/bin", NULL};
    check(krun_set_exec(context, "/checkpoint-guest", args, env), "exec");
    if (strcmp(argv[1], "restore") == 0) {
        check(krun_set_checkpoint_restore(context, argv[3]), "restore configuration");
    } else {
        if (argc == 6) check(krun_add_disk2(context, "data", argv[5], getenv("KRUN_TEST_FLATTEN") ? KRUN_DISK_FORMAT_QCOW2 : KRUN_DISK_FORMAT_RAW, false), "disk");
        if (block_root) check(krun_set_root_disk_remount(context, "/dev/vda", "ext4", NULL), "block rootfs");
        check(krun_set_checkpointing(context, true), "checkpoint configuration");
    }
    destination = getenv("KRUN_TEST_NEXT_CHECKPOINT");
    if (!destination) destination = argv[3];
    pthread_t thread;
    if (pthread_create(&thread, NULL, save, NULL)) abort();
    check(krun_start_enter(context), "enter");
    return 1;
}
