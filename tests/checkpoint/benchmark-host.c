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
static char response[4096];
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
    int result = krun_save_checkpoint(context, destination, NULL, NULL);
    uint64_t elapsed = now_ns() - start;
    fprintf(stderr, "EXPORT_NS %llu RESULT %d\n", (unsigned long long)elapsed, result);
    fflush(stderr);
    return NULL;
}

static void *watch_restore(void *unused) {
    (void)unused;
    uint64_t start;
    while (!(start = atomic_load(&import_start))) usleep(100);
    struct stat info;
    while (stat(response, &info) || info.st_size != 1) usleep(100);
    fprintf(stderr, "IMPORT_NS %llu\n", (unsigned long long)(now_ns() - start));
    fflush(stderr);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s boot|restore root checkpoint console memory-mib\n", argv[0]);
        return 2;
    }
    unsigned memory_mib = strtoul(argv[5], NULL, 10);
    sigemptyset(&signals); sigaddset(&signals, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &signals, NULL)) abort();
    check(krun_set_log_level(2), "log");
    int ctx = krun_create_ctx(); check(ctx, "create"); context = ctx;
    check(krun_set_vm_config(context, 2, memory_mib), "config");
    check(krun_set_root(context, argv[2]), "root");
    check(krun_set_console_output(context, argv[4]), "console");
    check(krun_disable_implicit_vsock(context), "vsock");
    char fill[32]; snprintf(fill, sizeof(fill), "%u", memory_mib / 2);
    const char *args[] = {fill, NULL};
    const char *env[] = {"PATH=/bin:/usr/bin", NULL};
    check(krun_set_exec(context, "/benchmark-guest", args, env), "exec");
    int restoring = strcmp(argv[1], "restore") == 0;
    if (restoring) check(krun_set_checkpoint_restore(context, argv[3]), "restore");
    else check(krun_set_checkpointing(context, true), "checkpoint");
    destination = argv[3];
    snprintf(response, sizeof(response), "%s/response", argv[2]);
    pthread_t thread;
    if (pthread_create(&thread, NULL, restoring ? watch_restore : save, NULL)) abort();
    if (restoring) atomic_store(&import_start, now_ns());
    check(krun_start_enter(context), "enter");
    return 1;
}
