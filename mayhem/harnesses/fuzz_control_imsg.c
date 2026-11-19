/*
 * Local control socket framing (mproc.c + the imsg library in
 * openbsd-compat): any local user may connect to smtpd's control socket
 * (smtpctl, sendmail enqueue).  The control process wraps each connection in
 * an mproc with proc = PROC_CLIENT and reads it with mproc_dispatch(); this
 * harness sets up the same mproc and dispatches whatever the client sent.
 * Before upstream 653abf00 (CVE-2025-62875) a malformed imsg here was fatal()
 * for the whole daemon.
 */
#include "harness.h"

#include <sys/time.h>
#include <event.h>
#include <imsg.h>

static int done;
static size_t total;

static void
client_handler(struct mproc *p, struct imsg *imsg)
{
	if (imsg == NULL) {
		/* as control_close() */
		mproc_clear(p);
		done = 1;
		return;
	}
	/* control_dispatch_ext() first checks the client's version and type */
	if (imsg->hdr.peerid != IMSG_VERSION)
		return;
	total += imsg->hdr.type + imsg_get_len(imsg);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int	initialized;
	struct mproc	p;
	int		sp[2];
	size_t		off = 0;

	harness_init();
	if (!initialized) {
		initialized = 1;
		event_init();
		smtpd_process = PROC_CONTROL;
	}

	harness_socketpair(sp);
	io_set_nonblocking(sp[0]);

	memset(&p, 0, sizeof(p));
	p.proc = PROC_CLIENT;
	p.name = "client";
	p.handler = client_handler;
	mproc_init(&p, sp[0]);
	mproc_enable(&p);

	done = 0;
	while (!done) {
		harness_feed(sp[1], data, size, &off);
		if (event_loop(EVLOOP_ONCE) == 1)
			break;
	}
	if (!done)
		mproc_clear(&p);
	close(sp[1]);
	return 0;
}
