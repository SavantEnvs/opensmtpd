/*
 * Shared helpers for the OpenSMTPD libFuzzer harnesses (mayhem/harnesses).
 *
 * The harnesses link the same objects smtpd(8) is built from (smtpd.c with its
 * main() renamed), so the daemon's globals (env, smtpd_process, p_lka, ...) are
 * the real ones.  harness_init() sets up what smtpd's main() sets up before any
 * parsing happens: logging and the default configuration (config_default()).
 */
#ifndef MAYHEM_HARNESS_H
#define MAYHEM_HARNESS_H

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static inline void
harness_init(void)
{
	if (env != NULL)
		return;
	log_init(1, LOG_MAIL);
	log_setverbose(0);
	tracing = 0;
	/* every smtpd process ignores SIGPIPE (smtpd.c, smtp.c, ...) */
	signal(SIGPIPE, SIG_IGN);
	if ((env = config_default()) == NULL)
		abort();
}

/* NUL-terminated heap copy of the input. */
static inline char *
harness_cstr(const uint8_t *data, size_t size)
{
	char *s = malloc(size + 1);

	if (s == NULL)
		abort();
	memcpy(s, data, size);
	s[size] = '\0';
	return s;
}

/*
 * Write the input to a fresh file under $TMPDIR (default /tmp) and return an
 * fd opened for reading at offset 0; the path is unlinked unless `path` is
 * given, in which case the caller unlinks it.
 */
static inline int
harness_tmpfile(const uint8_t *data, size_t size, char *path, size_t pathlen)
{
	char	 buf[PATH_MAX];
	const char *dir = getenv("TMPDIR");
	int	 fd;
	size_t	 off = 0;
	ssize_t	 n;

	if (dir == NULL || *dir == '\0')
		dir = "/tmp";
	snprintf(buf, sizeof buf, "%s/opensmtpd-fuzz-XXXXXX", dir);
	if ((fd = mkstemp(buf)) == -1)
		abort();
	while (off < size) {
		n = write(fd, data + off, size - off);
		if (n <= 0)
			abort();
		off += n;
	}
	if (lseek(fd, 0, SEEK_SET) == -1)
		abort();
	if (path != NULL)
		strlcpy(path, buf, pathlen);
	else
		unlink(buf);
	return fd;
}

/*
 * Peer side of a socketpair: write as much of the input as the socket takes
 * without blocking, and shut the write side down once everything is sent.
 * Returns 1 once the whole input has been sent.
 */
static inline int
harness_feed(int fd, const uint8_t *data, size_t size, size_t *off)
{
	ssize_t n;

	while (*off < size) {
		n = write(fd, data + *off, size - *off);
		if (n == -1 && (errno == EAGAIN || errno == EINTR))
			return 0;
		if (n <= 0)
			break;	/* peer gone */
		*off += n;
	}
	if (*off != (size_t)-1) {
		shutdown(fd, SHUT_WR);
		*off = (size_t)-1;
	}
	return 1;
}

static inline void
harness_socketpair(int sp[2])
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		abort();
	if (fcntl(sp[1], F_SETFL, fcntl(sp[1], F_GETFL) | O_NONBLOCK) == -1)
		abort();
}

#endif
