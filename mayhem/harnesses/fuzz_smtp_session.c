/*
 * SMTP server session (smtp_session.c, ioev.c, rfc5322.c, to.c, util.c):
 * what a remote client talks to on port 25.  The input is the client's side
 * of the conversation (EHLO, MAIL FROM, RCPT TO, DATA, AUTH, BDAT, ...),
 * written to the peer end of a socketpair; smtp_session() serves the other
 * end in the real dispatcher handler (dispatcher_imsg) until it closes.
 *
 * The session talks to the lookup (lka) and queue processes over imsg; here
 * those are mprocs on socketpairs whose far ends a small stand-in answers the
 * way a healthy lka/queue does: reverse DNS has no name, the sender and every
 * recipient are accepted, the message is created, spooled to /dev/null and
 * committed, and authentication succeeds.  Nothing else is mocked.
 */
#include "harness.h"

#include <sys/time.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <poll.h>

void dispatcher_imsg(struct mproc *, struct imsg *);

/* the session's p_lka/p_queue/p_control/p_parent, and their stand-ins */
static struct mproc	 lka_side, queue_side, control_side, parent_side;
static struct mproc	 lka_peer, queue_peer, control_peer, parent_peer;
static struct listener	 listener;
static struct event	 ev_rd, ev_wr;
static const uint8_t	*in_data;
static size_t		 in_size, in_off;
static int		 peer_fd, done;
static uint32_t		 msgid;

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
	case IMSG_SMTP_CHECK_SENDER:
	case IMSG_SMTP_MESSAGE_COMMIT:
	case IMSG_SMTP_AUTHENTICATE:
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		m_create(p, imsg->hdr.type, 0, 0, -1);
		m_add_id(p, reqid);
		m_add_int(p, imsg->hdr.type == IMSG_SMTP_MESSAGE_COMMIT ?
		    1 : LKA_OK);
		m_close(p);
		return;
	case IMSG_SMTP_MESSAGE_CREATE:
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		m_create(p, IMSG_SMTP_MESSAGE_CREATE, 0, 0, -1);
		m_add_id(p, reqid);
		m_add_int(p, 1);
		m_add_msgid(p, ++msgid);
		m_close(p);
		return;
	case IMSG_SMTP_MESSAGE_OPEN:
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		if ((fd = open("/dev/null", O_WRONLY)) == -1)
			abort();
		m_create(p, IMSG_SMTP_MESSAGE_OPEN, 0, 0, fd);
		m_add_id(p, reqid);
		m_add_int(p, 1);
		m_close(p);
		return;
	case IMSG_SMTP_EXPAND_RCPT:
		/* lka expands to one envelope, the queue stores it */
		m_msg(&m, imsg);
		m_get_id(&m, &reqid);
		m_create(&queue_peer, IMSG_QUEUE_ENVELOPE_SUBMIT, 0, 0, -1);
		m_add_id(&queue_peer, reqid);
		m_add_int(&queue_peer, 1);
		m_add_evpid(&queue_peer, ((uint64_t)msgid << 32) | 1);
		m_close(&queue_peer);
		m_create(&queue_peer, IMSG_QUEUE_ENVELOPE_COMMIT, 0, 0, -1);
		m_add_id(&queue_peer, reqid);
		m_add_int(&queue_peer, 1);
		m_close(&queue_peer);
		return;
	default:
		/* reports, rollbacks: no answer */
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

/*
 * 1 while an imsg is still queued in an mproc or unread on its socket: then
 * the stand-ins and the session have not finished talking about this input.
 */
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
 * The client.  smtpd does not offer PIPELINING, so like a real client it
 * waits for the banner and then for the reply to each command before
 * sending the next line; after a 354 it sends the message body up to and
 * including the "." line in one go.  Server replies are otherwise dropped.
 */
static int	 waiting = 1, body;
static size_t	 unit_end;
static char	 rline[8];
static size_t	 rlen;

static void
next_unit(void)
{
	const uint8_t	*p, *nl;
	size_t		 l;

	if (in_off >= in_size) {
		shutdown(peer_fd, SHUT_WR);
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
		if (!body || (l == 1 && p[0] == '.'))
			break;
		p = nl + 1;
	}
	body = 0;
	waiting = 0;
	event_add(&ev_wr, NULL);
}

static void
client_write(int fd, short ev, void *arg)
{
	ssize_t n;

	n = write(fd, in_data + in_off, unit_end - in_off);
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		event_del(&ev_wr);
		in_off = in_size;
		shutdown(fd, SHUT_WR);
		return;
	}
	in_off += n;
	if (in_off == unit_end) {
		event_del(&ev_wr);
		waiting = 1;
		if (in_off == in_size)
			shutdown(fd, SHUT_WR);
	}
}

static void
client_read(int fd, short ev, void *arg)
{
	char	buf[4096];
	ssize_t	n, i;

	n = read(fd, buf, sizeof(buf));
	if (n == -1 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		/* the server closed the connection */
		event_del(&ev_rd);
		event_del(&ev_wr);
		done = 1;
		return;
	}
	for (i = 0; i < n; i++) {
		if (buf[i] != '\n') {
			if (rlen < sizeof(rline))
				rline[rlen++] = buf[i];
			continue;
		}
		/* "NNN text" ends a reply, "NNN-text" continues it */
		if (rlen >= 4 && rline[3] == ' ' && waiting) {
			body = strncmp(rline, "354", 3) == 0;
			next_unit();
		}
		rlen = 0;
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int		 initialized;
	struct sockaddr_storage	 ss;
	struct sockaddr_in	*sin = (struct sockaddr_in *)&ss;
	int			 sp[2];

	harness_init();
	if (!initialized) {
		initialized = 1;
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

		strlcpy(listener.hostname, "mx.example.org",
		    sizeof(listener.hostname));
		strlcpy(listener.tag, "fuzz", sizeof(listener.tag));
		listener.port = htons(25);
		listener.flags = F_EXT_DSN;
		listener.ss.ss_family = AF_INET;
	}

	memset(&ss, 0, sizeof(ss));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(40000);
	sin->sin_addr.s_addr = htonl(0xc0000201);	/* 192.0.2.1 */

	harness_socketpair(sp);
	io_set_nonblocking(sp[0]);
	in_data = data;
	in_size = size;
	in_off = 0;
	peer_fd = sp[1];
	done = 0;
	waiting = 1;	/* for the banner */
	body = 0;
	rlen = 0;
	msgid = 0;
	event_set(&ev_rd, sp[1], EV_READ | EV_PERSIST, client_read, NULL);
	event_add(&ev_rd, NULL);
	event_set(&ev_wr, sp[1], EV_WRITE | EV_PERSIST, client_write, NULL);

	if (smtp_session(&listener, sp[0], &ss, NULL, NULL) == -1)
		abort();
	while (!done)
		if (event_loop(EVLOOP_ONCE) == 1)
			break;
	/*
	 * The session is closed, but replies to it may still be on their way
	 * between the stand-ins and the dispatcher: deliver them now, so that
	 * nothing from this input is handled during the next one.
	 */
	while (imsg_in_flight())
		if (event_loop(EVLOOP_ONCE | EVLOOP_NONBLOCK) == 1)
			break;
	close(sp[1]);
	return 0;
}
