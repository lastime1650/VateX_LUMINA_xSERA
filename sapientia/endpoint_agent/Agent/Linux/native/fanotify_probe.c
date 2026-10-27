/* Runtime prerequisite/ABI probe, not an enforcement daemon.
 * cc -std=c11 -O2 -Wall -Wextra -Werror fanotify_probe.c -o fanotify-probe
 * ./fanotify-probe /opt/lumina-owned-qualification-directory
 * It opens and immediately closes one directory permission mark. Never marks
 * a mount, filesystem or an operating-system directory. No privileged install.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int forbidden(const char *path) {
    const char *roots[] = {"/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/proc", "/sys", "/dev", "/boot", "/run"};
    if (!strcmp(path, "/") || strstr(path, "/../") || strstr(path, "/./") || strstr(path, "//")) return 1;
    for (unsigned int i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        size_t n = strlen(roots[i]);
        if (!strncmp(path, roots[i], n) && (path[n] == '\0' || path[n] == '/')) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/' || forbidden(argv[1])) {
        fprintf(stderr, "Usage: fanotify-probe ABSOLUTE_OWNED_ORDINARY_DIRECTORY\n");
        return 2;
    }
    struct stat info;
    if (lstat(argv[1], &info) || !S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0022)) {
        fprintf(stderr, "Directory must be ordinary, service-owned and not externally writable\n");
        return 3;
    }
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        perror("open ordinary directory");
        return 3;
    }
    struct stat opened;
    if (fstat(directory, &opened) || opened.st_dev != info.st_dev || opened.st_ino != info.st_ino) {
        close(directory);
        fprintf(stderr, "Directory identity changed\n");
        return 3;
    }
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) {
        close(directory);
        perror("fanotify_init (CAP_SYS_ADMIN and CONFIG_FANOTIFY required)");
        return 4;
    }
    int result = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN_EXEC_PERM | FAN_EVENT_ON_CHILD, directory, NULL);
    int saved_errno = errno;
    close(fd); /* Linux allows any outstanding requests: the probe is now gone. */
    close(directory);
    if (result) {
        errno = saved_errno;
        perror("fanotify_mark (CONFIG_FANOTIFY_ACCESS_PERMISSIONS required)");
        return 5;
    }
    printf("{\"permission_support\":true,\"metadata_version\":%d,\"metadata_size\":%zu,\"response_size\":%zu,\"mark_closed\":true}\n",
           FANOTIFY_METADATA_VERSION, sizeof(struct fanotify_event_metadata), sizeof(struct fanotify_response));
    return 0;
}
