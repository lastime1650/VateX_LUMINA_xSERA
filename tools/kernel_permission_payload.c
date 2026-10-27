/* Harmless qualification fixture: prove an executed main() created its own marker.
 * Compile only inside the dedicated Linux qualification root, never install.
 * Usage: ./owned-payload ABSOLUTE_OWNED_MARKER
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/' || strlen(argv[1]) > 4000) return 2;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("create owned qualification marker");
        return 3;
    }
    const char body[] = "main-executed\n";
    ssize_t length = write(fd, body, sizeof(body) - 1);
    int result = length == (ssize_t)(sizeof(body) - 1) && fsync(fd) == 0 ? 0 : 4;
    close(fd);
    return result;
}
