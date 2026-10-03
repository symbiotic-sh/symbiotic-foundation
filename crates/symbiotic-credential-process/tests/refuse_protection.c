// Test-only refusal and read observation for real macOS startup paths.
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int refuse_core_limit(int resource, const struct rlimit *limit) {
    if (resource == RLIMIT_CORE) {
        errno = EPERM;
        return -1;
    }
    return setrlimit(resource, limit);
}
static ssize_t observe_read(int fd, void *buffer, size_t length) {
    char path[1024];
    const char *root = getenv("PROTECTED_READ_ROOT");
    if (root && fcntl(fd, F_GETPATH, path) == 0 &&
        strncmp(path, root, strlen(root)) == 0) {
        const char marker[] = "protected read\n";
        (void)write(STDERR_FILENO, marker, sizeof(marker) - 1);
    }
    return read(fd, buffer, length);
}
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose[] __attribute__((section("__DATA,__interpose"))) = {
    {refuse_core_limit, setrlimit}, {observe_read, read}
};
