/*
 * th-fpscan: drive libfprint's virtual fingerprint device (FP_VIRTUAL_DEVICE)
 * from tests. The device only listens while fprintd has it open (during a
 * verify or enroll), so this keeps retrying until the socket accepts.
 *
 *   th-fpscan SOCKET COUNT TIMEOUT_S COMMAND...
 *
 * Sends "COMMAND..." COUNT times (one connection each, e.g. "SCAN print-1"),
 * waiting for the socket to accept each time. Exits 0 when all were sent,
 * 1 on timeout. Build: cc -o th-fpscan th-fpscan.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "usage: %s SOCKET COUNT TIMEOUT_S COMMAND...\n", argv[0]);
		return 2;
	}
	const char *path = argv[1];
	int count = atoi(argv[2]);
	double deadline = now() + atof(argv[3]);

	char cmd[512] = "";
	for (int i = 4; i < argc; i++) {
		if (i > 4)
			strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
		strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
	}

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	for (int sent = 0; sent < count;) {
		if (now() > deadline) {
			fprintf(stderr, "th-fpscan: timed out after %d of %d\n", sent, count);
			return 1;
		}
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd >= 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
		    write(fd, cmd, strlen(cmd)) == (ssize_t)strlen(cmd)) {
			close(fd);
			sent++;
			/* Give the driver time to consume it before the next one. */
			usleep(300 * 1000);
			continue;
		}
		if (fd >= 0)
			close(fd);
		usleep(100 * 1000);
	}
	return 0;
}
