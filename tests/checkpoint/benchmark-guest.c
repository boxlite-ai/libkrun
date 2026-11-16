// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static uint64_t pattern(uint64_t x) {
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static void mark(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "1", 1) != 1 || close(fd)) exit(1);
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    size_t bytes = strtoull(argv[1], NULL, 10) * 1024 * 1024;
    size_t count = bytes / sizeof(uint64_t);
    volatile uint64_t *memory = malloc(bytes);
    if (!memory) return 1;
    for (size_t i = 0; i < count; ++i) memory[i] = pattern(i);
    mark("/ready");
    while (access("/request", F_OK)) usleep(1000);
    // Report live guest execution before the full integrity scan, so the scan
    // does not inflate import latency. The runner still requires it to pass.
    mark("/response");
    for (size_t i = 0; i < count; ++i) {
        if (memory[i] != pattern(i)) {
            mark("/corrupt");
            return 1;
        }
    }
    mark("/verified");
    for (;;) pause();
}
