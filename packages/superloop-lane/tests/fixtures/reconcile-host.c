/* Hermetic systemctl and cgroup boundary for the production command fixture.
 * No production environment switch or test dispatch is added to the lane. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <sys/vfs.h>
#include <unistd.h>

static const char *mapped(const char *path) {
    if (!strcmp(path, "/sys/fs/cgroup")) {
        const char *root = getenv("LANE_FIXTURE_CGROUP");
        if (root) return root;
    }
    if (!strcmp(path, "/usr/bin/systemctl")) {
        const char *program = getenv("LANE_FIXTURE_SYSTEMCTL");
        if (program) return program;
    }
    return path;
}

#define OPEN_WRAPPER(name) \
int name(const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if (flags & O_CREAT) { \
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); \
    } \
    int (*next)(const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
    return next(mapped(path), flags, mode); \
}
OPEN_WRAPPER(open)
OPEN_WRAPPER(open64)

int fstatfs(int fd, struct statfs *info) {
    int (*next)(int, struct statfs *) = dlsym(RTLD_NEXT, "fstatfs");
    int result = next(fd, info);
    char descriptor[64], target[4096];
    snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
    ssize_t length = readlink(descriptor, target, sizeof target - 1);
    const char *root = getenv("LANE_FIXTURE_CGROUP");
    if (result == 0 && length >= 0 && root) {
        target[length] = 0;
        if (!strcmp(target, root)) info->f_type = 0x63677270;
    }
    return result;
}

#define SPAWN_WRAPPER(name) \
int name(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions, \
         const posix_spawnattr_t *attr, char *const argv[], char *const env[]) { \
    int (*next)(pid_t *, const char *, const posix_spawn_file_actions_t *, \
                const posix_spawnattr_t *, char *const[], char *const[]) = dlsym(RTLD_NEXT, #name); \
    return next(pid, mapped(path), actions, attr, argv, env); \
}
SPAWN_WRAPPER(posix_spawn)
SPAWN_WRAPPER(posix_spawnp)

int execve(const char *path, char *const argv[], char *const env[]) {
    int (*next)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    return next(mapped(path), argv, env);
}

int execvp(const char *path, char *const argv[]) {
    int (*next)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execvp");
    return next(mapped(path), argv);
}
