// Test-only syscall refusal, inherited by the isolated supervisor fixture.
#ifdef __linux__
#define _GNU_SOURCE
#include <dlfcn.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static int refuse_term(pid_t pid, int signal) {
    if (signal == SIGKILL && getenv("SUPERVISE_TEST_REFUSE_KILL")) {
        // Let the child exit only once emergency kill has been attempted. This
        // prevents try_wait from observing its exit before the intended failure.
        const char *path = getenv("SUPERVISE_TEST_EXIT_TRIGGER");
        if (!path) _exit(42);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || write(fd, "exit", 4) != 4 || close(fd) != 0) _exit(42);
        errno = EPERM;
        return -1;
    }
    if (signal == SIGTERM) {
        errno = EPERM;
        return -1;
    }
#ifdef __linux__
    int (*original)(pid_t, int) = dlsym(RTLD_NEXT, "kill");
    if (!original) _exit(42);
    return original(pid, signal);
#else
    return kill(pid, signal);
#endif
}
#ifdef __linux__
int kill(pid_t pid, int signal) {
    return refuse_term(pid, signal);
}
#else
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose __attribute__((section("__DATA,__interpose"))) = {refuse_term, kill};
#endif
