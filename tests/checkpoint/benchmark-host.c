// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include "libkrun.h"
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint32_t context;
static const char *destination;
static char response[4096], verified[4096];
static uint64_t process_launch, main_entry, create_ctx_ns, configure_ctx_ns, select_checkpoint_ns;
static sigset_t signals;
static _Atomic uint64_t import_start;

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void check(int result, const char *operation) {
    if (result < 0) { fprintf(stderr, "%s: %d\n", operation, result); exit(1); }
}

static void *save(void *unused) {
    (void)unused;
    int signal;
    if (sigwait(&signals, &signal)) abort();
    uint64_t start = now_ns();
    int result = krun_pause(context);
    uint64_t paused = now_ns();
    if (!result) result = krun_save_checkpoint(context, destination);
    uint64_t done = now_ns();
    fprintf(stderr, "EXPORT_NS %llu RESULT %d\nPAUSE_NS %llu\nSAVE_NS %llu\n",
            (unsigned long long)(done - start), result,
            (unsigned long long)(paused - start), (unsigned long long)(done - paused));
    fflush(stderr);
    return NULL;
}

static void *watch_restore(void *unused) {
    (void)unused;
    uint64_t start;
    while (!(start = atomic_load(&import_start))) usleep(100);
    struct stat info;
    while (stat(response, &info) || info.st_size != 1) usleep(100);
    uint64_t responded = now_ns();
    fprintf(stderr, "IMPORT_NS %llu\nIMPORT_SETUP_NS %llu\nIMPORT_LAUNCH_NS %llu\nIMPORT_PROCESS_NS %llu\n"
                    "SETUP_PHASE create_ctx %llu\nSETUP_PHASE configure_ctx %llu\nSETUP_PHASE select_checkpoint %llu\n",
            (unsigned long long)(responded - start),
            (unsigned long long)(start - main_entry),
            (unsigned long long)(main_entry - process_launch),
            (unsigned long long)(responded - process_launch),
            (unsigned long long)create_ctx_ns, (unsigned long long)configure_ctx_ns,
            (unsigned long long)select_checkpoint_ns);
    fflush(stderr);
    while (stat(verified, &info) || info.st_size != 1) usleep(100);
    fprintf(stderr, "RESPONSE_TO_VERIFIED_NS %llu\n", (unsigned long long)(now_ns() - responded));
    fflush(stderr);
    return NULL;
}

int main(int argc, char **argv) {
    main_entry = now_ns();
    const char *launch = getenv("KRUN_BENCH_PROCESS_LAUNCH_NS");
    process_launch = launch ? strtoull(launch, NULL, 10) : main_entry;
    if (argc != 6) {
        fprintf(stderr, "usage: %s boot|restore root checkpoint console memory-mib\n", argv[0]);
        return 2;
    }
    unsigned memory_mib = strtoul(argv[5], NULL, 10);
    sigemptyset(&signals); sigaddset(&signals, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &signals, NULL)) abort();
    check(krun_set_log_level(2), "log");
    uint64_t phase_start = now_ns();
    int ctx = krun_create_ctx(); check(ctx, "create"); context = ctx;
    create_ctx_ns = now_ns() - phase_start;
    phase_start = now_ns();
    check(krun_set_vm_config(context, 2, memory_mib), "config");
    check(krun_set_root(context, argv[2]), "root");
    check(krun_set_console_output(context, argv[4]), "console");
    check(krun_disable_implicit_vsock(context), "vsock");
    char fill[32]; snprintf(fill, sizeof(fill), "%u", memory_mib / 2);
    const char *args[] = {fill, NULL};
    const char *env[] = {"PATH=/bin:/usr/bin", NULL};
    check(krun_set_exec(context, "/benchmark-guest", args, env), "exec");
    configure_ctx_ns = now_ns() - phase_start;
    int restoring = strcmp(argv[1], "restore") == 0;
    phase_start = now_ns();
    if (restoring) check(krun_build_from_checkpoint(context, argv[3]), "restore");
    select_checkpoint_ns = now_ns() - phase_start;
    destination = argv[3];
    snprintf(response, sizeof(response), "%s/response", argv[2]);
    snprintf(verified, sizeof(verified), "%s/verified", argv[2]);
    pthread_t thread;
    if (pthread_create(&thread, NULL, restoring ? watch_restore : save, NULL)) abort();
    if (restoring) atomic_store(&import_start, now_ns());
    check(krun_start_enter(context), "enter");
    return 1;
}
