/*
 * SMTP client side of the daemon, the MTA (mta.c, mta_session.c, util.c's
 * parse_smtp_response(), ioev.c, libtls): what smtpd does when it relays a
 * queued message to a remote MX.  The input is that remote server's side of
 * the conversation (banner, EHLO extensions, replies to STARTTLS, MAIL, RCPT,
 * DATA, the end of the message, RSET and QUIT).
 *
 * The queue hands the dispatcher two envelopes of one message over the real
 * IMSG_QUEUE_TRANSFER path (dispatcher_imsg -> mta_imsg), for a "relay"
 * dispatcher with a smarthost.  The lookup (lka) and queue processes are
 * mprocs on socketpairs whose far ends answer like a healthy daemon: the
 * smarthost is smtp://<loopback address>:<port>, the host resolves to that
 * address and has no reverse DNS, and the message content is a small fixed
 * file.  mta.c then picks the route and mta_session() connects with
 * io_connect() to a loopback listener of this harness, which serves the
 * input as the server's replies.
 *
 * The server is a well-behaved SMTP server that says what the input says:
 * a reply is the input's lines up to the first one that is not a "NNN-"
 * continuation, and it sends the next reply only once the client has sent
 * its next command line (after a 2xx/3xx to DATA: the "." line ending the
 * message), because mta_session.c fails on any byte buffered after a reply
 * ("Remote host sent too much data").  After a 2xx to STARTTLS, the next
 * reply is sent as soon as the TLS client hello arrives and the connection
 * is then shut down for writing, so the handshake fails and the MTA takes
 * its downgrade-to-plain-text path and connects again.  Every new
 * connection continues with the rest of the input; once the input is used
 * up, the server shuts its side down.
 */
#include "harness.h"

#include <sys/time.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <poll.h>
#include <sys/syscall.h>
#include <time.h>
#include <tls.h>

void dispatcher_imsg(struct mproc *, struct imsg *);

#define NENVELOPES	2

/* the dispatcher's p_lka/p_queue/p_control/p_parent, and their stand-ins */
static struct mproc	 lka_side, queue_side, control_side, parent_side;
static struct mproc	 lka_peer, queue_peer, control_peer, parent_peer;
static struct event	 ev_accept, ev_srd, ev_swr;
static const uint8_t	*in_data;
static size_t		 in_size, in_off, unit_end;
static int		 lst_fd = -1, srv_fd = -1;
static int		 outcomes;
static char		 smarthost[64];
static struct sockaddr_in mx_addr;

/* the message the queue hands out (IMSG_MTA_OPEN_MESSAGE) */
static const char message[] =
    "From: Sender <sender@example.org>\n"
    "To: rcpt1@example.net, rcpt2@example.net\n"
    "Subject: relay\n"
    "Message-ID: <fuzz@example.org>\n"
    "\n"
    "body line\n"
    ".line starting with a dot\n"
    "\n";

/*
 * A virtual clock.  mta.c paces its retries with timers of whole seconds:
 * after a failed first connection the relay checks its source again after
 * 1 s and gives up 10 s later.  When the MTA has nothing left to do but
 * wait for such a timer (see mta_idle()), the harness moves time() and the
 * monotonic clock libevent schedules timers with forward by a second
 * instead of sleeping.  The wall clock (CLOCK_REALTIME, which libFuzzer
 * measures with) is left alone.
 */
static time_t	 vskew;

time_t
time(time_t *tp)
{
	struct timespec	ts;
	time_t		t;

	if (syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts) == -1)
		abort();
	t = ts.tv_sec + vskew;
	if (tp)
		*tp = t;
	return t;
}

int
clock_gettime(clockid_t id, struct timespec *ts)
{
	if (syscall(SYS_clock_gettime, id, ts) == -1)
		return -1;
	if (id == CLOCK_MONOTONIC || id == CLOCK_MONOTONIC_COARSE ||
	    id == CLOCK_MONOTONIC_RAW || id == CLOCK_BOOTTIME)
		ts->tv_sec += vskew;
	return 0;
}

/* stand-in for the lka and queue processes */
static void
peer_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg	 m;
	uint64_t	 reqid;
	int		 fd;

	if (imsg == NULL)
		return;

	switch (imsg->hdr.type) {
	case IMSG_GETNAMEINFO:
		m_create(p, IMSG_GETNAMEINFO, imsg->hdr.peerid, 0, -1);
		m_add_int(p, EAI_NONAME);
		m_add_int(p, 0);
		m_add_string(p, NULL);
		m_add_string(p, NULL);
		m_close(p);
		return;
	case IMSG_MTA_LOOKUP_SMARTHOST:
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		m_create(p, IMSG_MTA_LOOKUP_SMARTHOST, 0, 0, -1);
		m_add_id(p, reqid);
		m_add_int(p, LKA_OK);
		m_add_string(p, smarthost);
		m_close(p);
		return;
	case IMSG_MTA_DNS_HOST:
		/* the smarthost's name is its address */
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		m_create(p, IMSG_MTA_DNS_HOST, 0, 0, -1);
		m_add_id(p, reqid);
		m_add_string(p, "mx.example.net");
		m_add_sockaddr(p, (struct sockaddr *)&mx_addr);
		m_add_int(p, -1);
		m_close(p);
		m_create(p, IMSG_MTA_DNS_HOST_END, 0, 0, -1);
		m_add_id(p, reqid);
		m_add_int(p, DNS_OK);
		m_close(p);
		return;
	case IMSG_MTA_OPEN_MESSAGE:
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		fd = harness_tmpfile((const uint8_t *)message,
		    sizeof(message) - 1, NULL, 0);
		m_create(p, IMSG_MTA_OPEN_MESSAGE, 0, 0, fd);
		m_add_id(p, reqid);
		m_close(p);
		return;
	case IMSG_MTA_DELIVERY_OK:
	case IMSG_MTA_DELIVERY_TEMPFAIL:
	case IMSG_MTA_DELIVERY_PERMFAIL:
	case IMSG_MTA_DELIVERY_LOOP:
		/* the final status of one envelope */
		outcomes++;
		return;
	default:
		/* stats, rescheduling hints: no answer */
		return;
	}
}

static void
pair(struct mproc *side, struct mproc *peer, int proc, const char *name)
{
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		abort();
	io_set_nonblocking(sp[0]);
	io_set_nonblocking(sp[1]);

	side->proc = proc;
	side->name = (char *)name;
	side->handler = dispatcher_imsg;
	mproc_init(side, sp[0]);
	mproc_enable(side);

	peer->proc = PROC_DISPATCHER;
	peer->name = "dispatcher";
	peer->handler = peer_imsg;
	mproc_init(peer, sp[1]);
	mproc_enable(peer);
}

/* 1 while an imsg is still queued in an mproc or unread on its socket */
static int
imsg_in_flight(void)
{
	struct mproc	*all[] = { &lka_side, &queue_side, &control_side,
			    &parent_side, &lka_peer, &queue_peer, &control_peer,
			    &parent_peer };
	struct pollfd	 pfd[8];
	size_t		 i;

	for (i = 0; i < 8; i++) {
		if (imsgbuf_queuelen(&all[i]->imsgbuf) > 0)
			return 1;
		pfd[i].fd = all[i]->imsgbuf.fd;
		pfd[i].events = POLLIN;
		pfd[i].revents = 0;
	}
	return poll(pfd, 8, 0) > 0;
}

/*
 * The server.
 */
enum { S_LINE, S_BODY, S_TLS };
static int	 mode, writing, shut_after, tls_answered;
static char	 cmd[16];		/* start of the client's line */
static size_t	 cmdlen;
static char	 lastcmd[16];

static void
srv_close(void)
{
	if (srv_fd == -1)
		return;
	event_del(&ev_srd);
	event_del(&ev_swr);
	close(srv_fd);
	srv_fd = -1;
}

/* send the next reply, or end the conversation when the input is used up */
static void
send_unit(void)
{
	const uint8_t	*p, *nl;
	size_t		 l;

	if (in_off >= in_size) {
		shutdown(srv_fd, SHUT_WR);
		return;
	}
	p = in_data + in_off;
	for (;;) {
		nl = memchr(p, '\n', in_data + in_size - p);
		if (nl == NULL) {
			unit_end = in_size;
			break;
		}
		unit_end = nl + 1 - in_data;
		l = nl - p;
		if (l && p[l - 1] == '\r')
			l--;
		/* "NNN-text" continues a reply, anything else ends it */
		if (l < 4 || p[3] != '-')
			break;
		p = nl + 1;
	}

	/* what the client sends next */
	shut_after = mode == S_TLS;
	if (strcasecmp(lastcmd, "DATA") == 0 &&
	    (in_data[in_off] == '2' || in_data[in_off] == '3'))
		mode = S_BODY;
	else if (strcasecmp(lastcmd, "STARTTLS") == 0 &&
	    in_data[in_off] == '2')
		mode = S_TLS;
	lastcmd[0] = '\0';

	writing = 1;
	event_add(&ev_swr, NULL);
}

static void
srv_write(int fd, short ev, void *arg)
{
	ssize_t n;

	n = write(fd, in_data + in_off, unit_end - in_off);
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		/* the client is gone */
		in_off = unit_end;
		srv_close();
		return;
	}
	in_off += n;
	if (in_off < unit_end)
		return;
	event_del(&ev_swr);
	writing = 0;
	if (shut_after || in_off == in_size)
		shutdown(fd, SHUT_WR);
}

static void
client_line(void)
{
	size_t l = cmdlen < sizeof(cmd) ? cmdlen : sizeof(cmd) - 1;

	cmd[l] = '\0';
	if (l && cmd[l - 1] == '\r')
		cmd[l - 1] = '\0';
	if (mode == S_BODY) {
		if (strcmp(cmd, ".") != 0)
			return;
		mode = S_LINE;
	}
	if (writing)
		return;
	strlcpy(lastcmd, cmd, sizeof(lastcmd));
	send_unit();
}

static void
srv_read(int fd, short ev, void *arg)
{
	char	buf[4096];
	ssize_t	n, i;

	n = read(fd, buf, sizeof(buf));
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		srv_close();
		return;
	}
	if (mode == S_TLS) {
		/* the TLS client hello: answer it once with the next reply */
		if (!tls_answered && !writing) {
			tls_answered = 1;
			lastcmd[0] = '\0';
			send_unit();
		}
		return;
	}
	for (i = 0; i < n; i++) {
		if (buf[i] == '\n') {
			client_line();
			cmdlen = 0;
			continue;
		}
		if (cmdlen < sizeof(cmd))
			cmd[cmdlen] = buf[i];
		cmdlen++;
	}
}

static void
srv_accept(int fd, short ev, void *arg)
{
	int c;

	if ((c = accept(fd, NULL, NULL)) == -1)
		return;
	/* the MTA has given up on the previous connection */
	srv_close();
	srv_fd = c;
	io_set_nonblocking(c);
	mode = S_LINE;
	writing = 0;
	shut_after = 0;
	tls_answered = 0;
	cmdlen = 0;
	lastcmd[0] = '\0';
	event_set(&ev_srd, c, EV_READ | EV_PERSIST, srv_read, NULL);
	event_add(&ev_srd, NULL);
	event_set(&ev_swr, c, EV_WRITE | EV_PERSIST, srv_write, NULL);
	/* the banner */
	send_unit();
}

static void
setup(void)
{
	struct dispatcher	*dsp;
	struct mta_limits	*limits;
	struct tls_config	*tls;

	event_init();
	smtpd_process = PROC_DISPATCHER;
	pair(&lka_side, &lka_peer, PROC_LKA, "lka");
	pair(&queue_side, &queue_peer, PROC_QUEUE, "queue");
	pair(&control_side, &control_peer, PROC_CONTROL, "control");
	pair(&parent_side, &parent_peer, PROC_PARENT, "parent");
	p_lka = &lka_side;
	p_queue = &queue_side;
	p_control = &control_side;
	p_parent = &parent_side;

	/*
	 * smtpd.conf:  action "relay" relay host <smarthost table>
	 * with the client TLS configuration mta_setup_dispatcher() makes when
	 * no certificate check is asked for ("tls no-verify"), minus the CA
	 * file, which an unverified handshake does not read.
	 */
	dsp = xcalloc(1, sizeof(*dsp));
	dsp->type = DISPATCHER_REMOTE;
	dsp->u.remote.smarthost = "smarthost";
	if ((tls = tls_config_new()) == NULL)
		abort();
	tls_config_insecure_noverifycert(tls);
	tls_config_insecure_noverifyname(tls);
	tls_config_insecure_noverifytime(tls);
	dsp->u.remote.tls_config = tls;
	dict_set(env->sc_dispatchers, "relay", dsp);

	/*
	 * smtpd.conf:  limit mta session-keepalive 0
	 * so that a session with no more work quits instead of idling for
	 * 10 seconds in case another message comes.
	 */
	limits = dict_xget(env->sc_limits_dict, "default");
	if (!limit_mta_set(limits, "session-keepalive", 0))
		abort();

	mta_postprivdrop();
}

/*
 * Every input gets its own loopback address (127.0.0.2, 127.0.0.3, ...).
 * mta.c remembers hosts and routes (a route that failed its first
 * connection stays disabled for a while), so a fresh address is a fresh
 * route and nothing an earlier input did changes how this one is handled.
 */
static void
listen_next(void)
{
	static uint32_t		 n;
	struct sockaddr_in	 sin;
	socklen_t		 len = sizeof(sin);
	int			 one = 1;

	n = n % 0xfffffd + 1;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001 + n);
	if ((lst_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		abort();
	setsockopt(lst_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(lst_fd, (struct sockaddr *)&sin, sizeof(sin)) == -1 ||
	    listen(lst_fd, 8) == -1 ||
	    getsockname(lst_fd, (struct sockaddr *)&sin, &len) == -1)
		abort();
	io_set_nonblocking(lst_fd);
	snprintf(smarthost, sizeof(smarthost), "smtp://%s:%d",
	    inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
	mx_addr = sin;
	mx_addr.sin_port = 0;
	event_set(&ev_accept, lst_fd, EV_READ | EV_PERSIST, srv_accept, NULL);
	event_add(&ev_accept, NULL);
}

/*
 * 1 when the envelopes are not done yet but the MTA has no connection to the
 * server, none waiting to be accepted and no request out to the stand-ins:
 * then it waits for one of its timers.
 */
static int
mta_idle(void)
{
	struct pollfd pfd;

	if (outcomes >= NENVELOPES || srv_fd != -1 || imsg_in_flight())
		return 0;
	pfd.fd = lst_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	return poll(&pfd, 1, 0) == 0;
}

static void
transfer(uint32_t msgid, int i)
{
	struct envelope evp;
	struct sockaddr_in *sin = (struct sockaddr_in *)&evp.ss;

	memset(&evp, 0, sizeof(evp));
	evp.version = SMTPD_ENVELOPE_VERSION;
	evp.id = ((uint64_t)msgid << 32) | (uint32_t)(i + 1);
	evp.type = D_MTA;
	strlcpy(evp.dispatcher, "relay", sizeof(evp.dispatcher));
	strlcpy(evp.tag, "fuzz", sizeof(evp.tag));
	strlcpy(evp.smtpname, "mx.example.org", sizeof(evp.smtpname));
	strlcpy(evp.helo, "client.example.org", sizeof(evp.helo));
	strlcpy(evp.hostname, "client.example.org", sizeof(evp.hostname));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xc0000201);	/* 192.0.2.1 */
	strlcpy(evp.sender.user, "sender", sizeof(evp.sender.user));
	strlcpy(evp.sender.domain, "example.org", sizeof(evp.sender.domain));
	snprintf(evp.rcpt.user, sizeof(evp.rcpt.user), "rcpt%d", i + 1);
	strlcpy(evp.rcpt.domain, "example.net", sizeof(evp.rcpt.domain));
	evp.dest = evp.rcpt;
	evp.creation = time(NULL);
	evp.ttl = 3600;
	evp.dsn_notify = DSN_SUCCESS | DSN_FAILURE;
	evp.dsn_ret = DSN_RETHDRS;
	strlcpy(evp.dsn_envid, "fuzz-envid", sizeof(evp.dsn_envid));
	snprintf(evp.dsn_orcpt, sizeof(evp.dsn_orcpt),
	    "rfc822;rcpt%d@example.net", i + 1);

	m_create(&queue_peer, IMSG_QUEUE_TRANSFER, 0, 0, -1);
	m_add_envelope(&queue_peer, &evp);
	m_close(&queue_peer);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int	 initialized;
	static uint32_t	 msgid;
	int		 i;

	harness_init();
	if (!initialized) {
		initialized = 1;
		setup();
	}

	in_data = data;
	in_size = size;
	in_off = 0;
	outcomes = 0;
	listen_next();

	msgid = msgid % 0xfffffffe + 1;
	for (i = 0; i < NENVELOPES; i++)
		transfer(msgid, i);

	/*
	 * Run until both envelopes have their final status, the server
	 * connection is closed and the stand-ins and the dispatcher have
	 * nothing left to say to each other.
	 */
	while (outcomes < NENVELOPES || srv_fd != -1 || imsg_in_flight()) {
		if (mta_idle()) {
			event_loop(EVLOOP_ONCE | EVLOOP_NONBLOCK);
			if (mta_idle()) {
				vskew++;
				event_loop(EVLOOP_ONCE | EVLOOP_NONBLOCK);
			}
			continue;
		}
		if (event_loop(EVLOOP_ONCE) == 1)
			break;
	}

	event_del(&ev_accept);
	close(lst_fd);
	lst_fd = -1;
	return 0;
}
