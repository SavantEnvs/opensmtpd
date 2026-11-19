/*
 * DNS answers, as the mta's lka process handles them (dns.c).
 *
 * dns.c's resolver callbacks are static, so this file includes dns.c itself
 * (its one external symbol, dns_imsg, is renamed so it does not clash with the
 * dns.o linked from smtpd's objects).  Each input is a raw resolver answer,
 * handed in an asr_result to dns_dispatch_mx_preference(), which unpacks the
 * header, question and every answer RR (unpack_dns.c) and prints MX exchange
 * names with print_dname().  dns_dispatch_mx() is not driven: it starts a real
 * asynchronous host lookup for each MX it finds.
 *
 * The reply the callback composes for the mta goes into an mproc on a fresh
 * socketpair; it is discarded and the pair closed after every input, so
 * nothing carries over (only the libevent base is created once).
 *
 * The answer is then walked once more over every RR type (CNAME, NS, PTR, SOA,
 * A, AAAA), which unpack_rr() decodes for all of smtpd's DNS users.
 */
#define dns_imsg fuzz_dns_imsg_unused
#include "dns.c"	/* usr.sbin/smtpd/dns.c, via -I$SRC/usr.sbin/smtpd */
#undef dns_imsg

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

static struct mproc	 mta_side;

static void
walk_answer(const uint8_t *data, size_t size)
{
	struct unpack		 pack;
	struct dns_header	 h;
	struct dns_query	 q;
	struct dns_rr		 rr;
	char			 buf[512];
	uint16_t		 n;

	memset(&h, 0, sizeof(h));
	unpack_init(&pack, (const char *)data, size);
	unpack_header(&pack, &h);

	for (n = h.qdcount; n; n--) {
		if (unpack_query(&pack, &q) == -1)
			return;
		print_dname(q.q_dname, buf, sizeof(buf));
	}
	for (n = h.ancount + h.nscount + h.arcount; n; n--) {
		if (unpack_rr(&pack, &rr) == -1)
			return;
		print_dname(rr.rr_dname, buf, sizeof(buf));
		switch (rr.rr_type) {
		case T_CNAME:
			print_dname(rr.rr.cname.cname, buf, sizeof(buf));
			break;
		case T_NS:
			print_dname(rr.rr.ns.nsname, buf, sizeof(buf));
			break;
		case T_PTR:
			print_dname(rr.rr.ptr.ptrname, buf, sizeof(buf));
			break;
		case T_SOA:
			print_dname(rr.rr.soa.mname, buf, sizeof(buf));
			print_dname(rr.rr.soa.rname, buf, sizeof(buf));
			break;
		case T_A:
			inet_ntop(AF_INET, &rr.rr.in_a.addr, buf, sizeof(buf));
			break;
		case T_AAAA:
			inet_ntop(AF_INET6, &rr.rr.in_aaaa.addr6, buf,
			    sizeof(buf));
			break;
		default:
			break;
		}
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int		 initialized;
	struct dns_session	*s;
	struct asr_result	 ar;
	int			 sp[2];

	if (!initialized) {
		initialized = 1;
		log_init(1, LOG_MAIL);
		log_setverbose(0);
		event_init();
	}

	/* lka -> dispatcher (where the mta runs): a fresh mproc for every input */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
		abort();
	memset(&mta_side, 0, sizeof(mta_side));
	mta_side.proc = PROC_DISPATCHER;
	mta_side.name = "dispatcher";
	mproc_init(&mta_side, sp[0]);

	/* the session dns_imsg() would create for IMSG_MTA_DNS_MX_PREFERENCE */
	if ((s = calloc(1, sizeof(*s))) == NULL)
		abort();
	s->p = &mta_side;
	s->reqid = 1;
	s->type = IMSG_MTA_DNS_MX_PREFERENCE;
	strlcpy(s->name, "mx.example.org", sizeof(s->name));

	/* a successful answer: asr hands over a malloc'd copy of the packet */
	memset(&ar, 0, sizeof(ar));
	ar.ar_datalen = size;
	if ((ar.ar_data = malloc(size ? size : 1)) == NULL)
		abort();
	memcpy(ar.ar_data, data, size);

	dns_dispatch_mx_preference(&ar, s);	/* frees s and ar.ar_data */

	/* drop the reply composed for the mta, never flushed */
	if (mta_side.events)
		event_del(&mta_side.ev);
	imsgbuf_clear(&mta_side.imsgbuf);
	free(mta_side.m_buf);
	close(sp[0]);
	close(sp[1]);

	walk_answer(data, size);
	return 0;
}
