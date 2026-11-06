// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>

static void test_abort(int line) {
    int saved_errno = errno;
    int fd = open("/failure", O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd >= 0) {
        dprintf(fd, "guest.c:%d errno=%d\n", line, saved_errno);
        int info = open("/proc/meminfo", O_RDONLY); char buffer[4096]; ssize_t n;
        if (info >= 0) { while ((n = read(info, buffer, sizeof(buffer))) > 0) if (write(fd, buffer, n) != n) break; close(info); }
        fsync(fd); close(fd);
    }
    _exit(134);
}
#define abort() test_abort(__LINE__)

static _Atomic uint64_t counters[2];
static unsigned char memory[128 * 1024];
static unsigned char *hot_memory;
static const size_t hot_bytes = 300 * 1024 * 1024;

static void *count(void *argument) {
    unsigned id = (uintptr_t)argument;
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(id, &set);
    if (sched_setaffinity(0, sizeof(set), &set)) abort();
    uint64_t previous = 0;
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
        uint64_t current = (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
        if (current < previous) abort();
        previous = current;
        atomic_fetch_add(&counters[id], 1);
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}

static _Atomic uint64_t tcp_echoes, tcp_drops, accept_errors, udp_echoes;
static unsigned tsi_port, tsi_listen_port;

static void *tcp_echo(void *unused) {
    (void)unused;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(tsi_port)};
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) abort();
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            char reply;
            while (send(fd, "e", 1, MSG_NOSIGNAL) == 1 && recv(fd, &reply, 1, MSG_WAITALL) == 1 && reply == 'e') {
                atomic_fetch_add(&tcp_echoes, 1);
                usleep(10000);
            }
            atomic_fetch_add(&tcp_drops, 1);
        }
        close(fd); usleep(10000);
    }
}

static void *blocked_accept(void *unused) {
    (void)unused;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(tsi_listen_port)};
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        if (fd < 0) abort();
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 4)) abort();
        int ready = open("/accept-ready", O_CREAT | O_WRONLY, 0600);
        if (ready < 0) abort(); close(ready);
        int accepted = accept(fd, NULL, NULL);
        if (accepted < 0) atomic_fetch_add(&accept_errors, 1);
        else close(accepted);
        close(fd); usleep(10000);
    }
}

static void *udp_echo(void *unused) {
    (void)unused;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(tsi_port)};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) abort();
    for (;;) {
        char reply;
        if (sendto(fd, "u", 1, 0, (struct sockaddr *)&address, sizeof(address)) != 1) abort();
        // UDP packets in host buffers may be lost at the checkpoint boundary.
        // Keep issuing requests instead of depending on one in-flight reply.
        while (recv(fd, &reply, 1, MSG_DONTWAIT) == 1) {
            if (reply == 'u') atomic_fetch_add(&udp_echoes, 1);
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) abort();
        usleep(10000);
    }
}

int main(void) {
    const char *limit_env = getenv("KRUN_TEST_TICKS");
    unsigned limit = limit_env ? strtoul(limit_env, NULL, 10) : 0;
    unsigned iterations = 0;
    uint64_t nonce;
    if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) abort();
    for (size_t i = 0; i < sizeof(memory); ++i) memory[i] = (unsigned char)(i ^ nonce);
    int log = open("/progress", O_CREAT | O_WRONLY | O_APPEND, 0600);
    int kept = open("/kept", O_CREAT | O_RDWR, 0600);
    int gone = open("/gone", O_CREAT | O_RDWR, 0600);
    if (log < 0 || kept < 0 || gone < 0) abort();
    if (pwrite(kept, "persistent", 10, 0) != 10 || pwrite(gone, "old", 3, 0) != 3) abort();
    fsync(kept); fsync(gone);
    void *sector;
    if (posix_memalign(&sector, 4096, 512)) abort();
    int block_root = access("/block-root", F_OK) == 0;
    int disk = block_root ? -1 : open("/dev/vda", O_RDWR | O_DIRECT);
    if (disk >= 0) {
        for (unsigned i = 0; i < 512; ++i) ((unsigned char *)sector)[i] = (unsigned char)(i ^ nonce);
        if (pwrite(disk, sector, 512, 0) != 512 || fsync(disk)) abort();
    }
    dprintf(log, "BOOT %llu\n", (unsigned long long)nonce);
    if (block_root) dprintf(STDOUT_FILENO, "BOOT %llu\n", (unsigned long long)nonce);
    int net = -1;
    uint64_t echoes = 0;
    unsigned ifindex = if_nametoindex("eth0");
    if (ifindex) {
        net = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(0x88b5));
        if (net < 0) abort();
        struct ifreq request = {0}; strcpy(request.ifr_name, "eth0");
        if (ioctl(net, SIOCGIFFLAGS, &request)) abort();
        request.ifr_flags |= IFF_UP;
        if (ioctl(net, SIOCSIFFLAGS, &request)) abort();
        struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(0x88b5), .sll_ifindex = ifindex};
        if (bind(net, (struct sockaddr *)&address, sizeof(address))) abort();
    }
    FILE *tsi = fopen("/tsi-ports", "r");
    if (tsi) {
        if (fscanf(tsi, "%u %u", &tsi_port, &tsi_listen_port) != 2) abort();
        fclose(tsi);
        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_echo, NULL) || pthread_create(&thread, NULL, blocked_accept, NULL)
            || pthread_create(&thread, NULL, udp_echo, NULL)) abort();
    }
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i) if (pthread_create(&threads[i], NULL, count, (void *)i)) abort();
    for (;;) {
        if (!hot_memory && access("/allocate-hotplug", F_OK) == 0) {
            // Host plugged accounting can precede the guest's memory-online
            // work. Wait for the guest allocator to see the new capacity.
            for (unsigned attempt = 0; attempt < 1000 && !hot_memory; ++attempt) {
                hot_memory = malloc(hot_bytes);
                if (!hot_memory) usleep(10000);
            }
            if (!hot_memory) abort();
            for (size_t i = 0; i < hot_bytes; i += 4096) hot_memory[i] = (unsigned char)(i / 4096 ^ nonce);
            int ready = open("/hotplug-ready", O_CREAT | O_WRONLY, 0600);
            if (ready < 0) abort(); close(ready);
        }
        if (hot_memory) for (size_t i = 0; i < hot_bytes; i += 4096) if (hot_memory[i] != (unsigned char)(i / 4096 ^ nonce)) abort();
        for (size_t i = 0; i < sizeof(memory); ++i) if (memory[i] != (unsigned char)(i ^ nonce)) abort();
        char data[10];
        if (pread(kept, data, sizeof(data), 0) != sizeof(data)) abort();
        for (unsigned i = 0; i < sizeof(data); ++i) if (data[i] != "persistent"[i]) abort();
        if (disk >= 0) {
            if (pread(disk, sector, 512, 0) != 512) abort();
            for (unsigned i = 0; i < 512; ++i) if (((unsigned char *)sector)[i] != (unsigned char)(i ^ nonce)) abort();
        }
        if (disk >= 0) {
            if (pread(disk, sector, 512, 4096) != 512) abort();
            for (unsigned i = 0; i < 512; ++i) if (((unsigned char *)sector)[i] != 0x37) abort();
        }
        int status = fsync(gone);
        int stale = status < 0 ? errno : 0;
        if (net >= 0) {
            unsigned char frame[64] = {2,0,0,0,0,2, 2,0,0,0,0,1, 0x88,0xb5};
            memcpy(frame + 14, &nonce, sizeof(nonce));
            if (send(net, frame, sizeof(frame), MSG_DONTWAIT) < 0 && errno != EAGAIN) abort();
            unsigned char reply[2048]; ssize_t length;
            while ((length = recv(net, reply, sizeof(reply), MSG_DONTWAIT)) >= 0) {
                if (length >= 22 && reply[11] == 2 && memcmp(reply + 14, &nonce, sizeof(nonce)) == 0) echoes++;
            }
            if (errno != EAGAIN) abort();
        }
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
        char line[512];
        int length = snprintf(line, sizeof(line), "TICK %llu %llu %llu %lld %d %d %d %llu %llu %llu %llu %llu\n", (unsigned long long)nonce,
            (unsigned long long)atomic_load(&counters[0]), (unsigned long long)atomic_load(&counters[1]),
            (long long)now.tv_sec * 1000000000 + now.tv_nsec, stale, disk >= 0 || block_root, hot_memory != NULL, (unsigned long long)echoes, (unsigned long long)atomic_load(&tcp_echoes),
            (unsigned long long)atomic_load(&tcp_drops), (unsigned long long)atomic_load(&accept_errors),
            (unsigned long long)atomic_load(&udp_echoes));
        if (write(log, line, length) != length) abort();
        if (block_root && write(STDOUT_FILENO, line, length) != length) abort();
        fsync(log);
        if (limit && ++iterations == limit) return 0;
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
}
