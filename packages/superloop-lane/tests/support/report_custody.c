/* Model two namespace identities at the OS boundary, without production hooks.
 * Public path reads of loop custody fail; the descriptor-bound private entry
 * sees namespace root and loop uid 41001. The /tmp ancestry is rewritten as
 * protected (mode 0755 and a root-owned fixture parent). Neither modeled fact
 * establishes kernel uid separation. All report bytes come from real files. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>

static int private_step(void) { return getenv("REPORT_FIXTURE_PRIVATE") != NULL; }
static int custody(const char *path) {
    const char *root = getenv("REPORT_FIXTURE_RUN");
    return root && !strncmp(path, root, strlen(root)) &&
        (path[strlen(root)] == 0 || path[strlen(root)] == '/');
}
static void absolute_path(int fd, const char *path, char *out, size_t size) {
    if (path && path[0] == '/') { snprintf(out, size, "%s", path); return; }
    char link[64], base[4096];
    if (fd == AT_FDCWD) {
        if (!getcwd(base, sizeof base)) { out[0] = 0; return; }
        snprintf(out, size, "%s%s%s", base, path && *path ? "/" : "", path ? path : "");
        return;
    }
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, base, sizeof base - 1);
    if (n < 0) { out[0] = 0; return; }
    base[n] = 0;
    snprintf(out, size, "%s%s%s", base, path && *path ? "/" : "", path ? path : "");
}
static int denied(const char *path) {
    if (custody(path) && ((!private_step() && !getenv("REPORT_FIXTURE_READABLE")) ||
        (private_step() && getenv("REPORT_FIXTURE_UNREADABLE")))) {
        errno = EACCES;
        return 1;
    }
    return 0;
}
static int path_stat_denied(const char *path) {
    const char *root = getenv("REPORT_FIXTURE_RUN");
    /* A directory's own metadata is visible through its searchable parent. */
    return root && strcmp(path, root) && denied(path);
}
static uid_t mapped_uid(const char *path, uid_t original) {
    const char *run = getenv("REPORT_FIXTURE_RUN");
    const char *home = run ? strstr(run, "/home/.var/loops/") : NULL;
    /* The temporary fixture parent stands for a protected host-home ancestor. */
    if (home && strlen(path) == (size_t)(home - run) && !strncmp(path, run, home - run)) return 0;
    if (custody(path)) {
        if (getenv("REPORT_FIXTURE_WRONG_OWNER") && strstr(path, "/run-report.txt")) return 3000;
        return 41001;
    }
    uid_t (*real_uid)(void) = dlsym(RTLD_NEXT, "geteuid");
    return private_step() && original == real_uid() ? 0 : original;
}
uid_t geteuid(void) {
    uid_t (*next)(void) = dlsym(RTLD_NEXT, "geteuid");
    return private_step() ? 0 : next();
}
uid_t getuid(void) {
    uid_t (*next)(void) = dlsym(RTLD_NEXT, "getuid");
    return private_step() ? 0 : next();
}
#define OPEN(name) \
int name(const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); } \
    char absolute[8192]; absolute_path(AT_FDCWD, path, absolute, sizeof absolute); \
    if (denied(absolute)) return -1; \
    int (*next)(const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
    return next(path, flags, mode); \
}
OPEN(open)
OPEN(open64)

#define OPENAT(name) \
int name(int fd, const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); } \
    char absolute[8192]; absolute_path(fd, path, absolute, sizeof absolute); \
    if (denied(absolute)) return -1; \
    int (*next)(int, const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
    return next(fd, path, flags, mode); \
}
OPENAT(openat)
OPENAT(openat64)

DIR *opendir(const char *path) {
    char absolute[8192]; absolute_path(AT_FDCWD, path, absolute, sizeof absolute);
    if (denied(absolute)) return NULL;
    DIR *(*next)(const char *) = dlsym(RTLD_NEXT, "opendir");
    return next(path);
}

#define FSTATAT(name, type) \
int name(int fd, const char *path, struct type *info, int flags) { \
    char absolute[8192]; absolute_path(fd, path, absolute, sizeof absolute); \
    if (path && *path && path_stat_denied(absolute)) return -1; \
    int (*next)(int, const char *, struct type *, int) = dlsym(RTLD_NEXT, #name); \
    int result = next(fd, path, info, flags); \
    if (!result) info->st_uid = mapped_uid(absolute, info->st_uid); \
    return result; \
}
FSTATAT(fstatat, stat)
FSTATAT(fstatat64, stat64)

int statx(int fd, const char *path, int flags, unsigned mask, struct statx *info) {
    int (*next)(int, const char *, int, unsigned, struct statx *) = dlsym(RTLD_NEXT, "statx");
    char absolute[8192]; absolute_path(fd, path, absolute, sizeof absolute);
    if (path && *path && path_stat_denied(absolute)) return -1;
    int result = next(fd, path, flags, mask, info);
    if (!result) info->stx_uid = mapped_uid(absolute, info->stx_uid);
    if (!result && !strcmp(absolute, "/tmp")) info->stx_mode = S_IFDIR | 0755;
    return result;
}
#define FSTAT(name, type) \
int name(int fd, struct type *info) { \
    int (*next)(int, struct type *) = dlsym(RTLD_NEXT, #name); \
    int result = next(fd, info); \
    char path[8192]; absolute_path(fd, "", path, sizeof path); \
    if (!result) info->st_uid = mapped_uid(path, info->st_uid); \
    if (!result && !strcmp(path, "/tmp")) info->st_mode = S_IFDIR | 0755; \
    return result; \
}
FSTAT(fstat, stat)
FSTAT(fstat64, stat64)

long syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    unsigned long a[6];
    for (int i = 0; i < 6; ++i) a[i] = va_arg(ap, unsigned long);
    va_end(ap);
    long (*next)(long, ...) = dlsym(RTLD_NEXT, "syscall");
    if (number == SYS_openat2) {
        char path[8192]; absolute_path((int)a[0], (const char *)a[1], path, sizeof path);
        if (denied(path)) return -1;
    }
    return next(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}
