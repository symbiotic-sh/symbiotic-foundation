// Test-only syscall refusal, inherited by the isolated supervisor fixture.
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

static int refuse_term(pid_t pid, int signal) {
    if (signal == SIGTERM) {
        errno = EPERM;
        return -1;
    }
    return kill(pid, signal);
}
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose __attribute__((section("__DATA,__interpose"))) = {refuse_term, kill};
