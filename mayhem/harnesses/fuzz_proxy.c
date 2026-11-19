/*
 * PROXY protocol v2 header (proxy.c): what a `listen on ... proxy-v2`
 * listener reads from a freshly accepted connection before the SMTP session
 * starts.  The input is written to the peer end of a socketpair, the session
 * is driven with libevent until proxy.c hands the connection on (accepted)
 * or drops it.
 */
#include "harness.h"

#include <sys/time.h>
#include <event.h>

/* exported by proxy.c, which declares it itself (no header) */
int proxy_session(struct listener *, int, const struct sockaddr_storage *,
    void (*)(struct listener *, int, const struct sockaddr_storage *,
	struct io *),
    void (*)(struct listener *, int, const struct sockaddr_storage *));

static int done;

static void
accepted(struct listener *l, int fd, const struct sockaddr_storage *ss,
    struct io *io)
{
	io_free(io);	/* closes fd */
	done = 1;
}

static void
dropped(struct listener *l, int fd, const struct sockaddr_storage *ss)
{
	close(fd);
	done = 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct listener	 listener;
	struct sockaddr_storage	 ss;
	struct sockaddr_in	*sin = (struct sockaddr_in *)&ss;
	static int		 initialized;
	int			 sp[2];
	size_t			 off = 0;

	harness_init();
	if (!initialized) {
		initialized = 1;
		event_init();
		strlcpy(listener.hostname, "fuzz.example.org",
		    sizeof(listener.hostname));
		listener.flags = F_PROXY;
	}

	memset(&ss, 0, sizeof(ss));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(25);
	sin->sin_addr.s_addr = htonl(0x7f000001);

	harness_socketpair(sp);
	done = 0;
	if (proxy_session(&listener, sp[0], &ss, accepted, dropped) == -1)
		abort();
	while (!done) {
		harness_feed(sp[1], data, size, &off);
		if (event_loop(EVLOOP_ONCE) == 1)
			break;
	}
	close(sp[1]);
	return 0;
}
