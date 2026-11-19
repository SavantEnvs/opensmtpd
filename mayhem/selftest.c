/*
 * Known-answer tests for OpenSMTPD's parsers, linked against the objects
 * smtpd(8) is built from (normal flags, no sanitizers).  Run by mayhem/test.sh;
 * prints one TAP-style "ok N - name" / "not ok N - name" line per check.
 */
#include "harnesses/harness.h"

#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include "rfc5322.h"
#include "unpack_dns.h"

static int n, failed;

static void
check(int cond, const char *name)
{
	n++;
	if (!cond)
		failed++;
	printf("%sok %d - %s\n", cond ? "" : "not ", n, name);
}

static void
t_to(void)
{
	struct netaddr		 na;
	struct relayhost	 rh;
	struct mailaddr		 ma;
	struct sockaddr_in	*sin = (struct sockaddr_in *)&na.ss;

	memset(&na, 0, sizeof na);
	check(text_to_netaddr(&na, "192.168.1.0/24") &&
	    na.ss.ss_family == AF_INET && na.bits == 24 &&
	    ntohl(sin->sin_addr.s_addr) == 0xc0a80100,
	    "text_to_netaddr ipv4/24");
	memset(&na, 0, sizeof na);
	check(text_to_netaddr(&na, "2001:db8::/32") &&
	    na.ss.ss_family == AF_INET6 && na.bits == 32,
	    "text_to_netaddr ipv6/32");
	check(!text_to_netaddr(&na, "300.1.1.1"), "text_to_netaddr rejects 300.1.1.1");

	memset(&rh, 0, sizeof rh);
	check(text_to_relayhost(&rh, "smtps://label@mx.example.org:465") &&
	    rh.tls == RELAY_TLS_SMTPS && rh.port == 465 &&
	    strcmp(rh.hostname, "mx.example.org") == 0 &&
	    strcmp(rh.authlabel, "label") == 0 && (rh.flags & RELAY_AUTH),
	    "text_to_relayhost smtps://label@host:465");
	memset(&rh, 0, sizeof rh);
	check(text_to_relayhost(&rh, "lmtp://localhost:24") &&
	    (rh.flags & RELAY_LMTP) && rh.port == 24,
	    "text_to_relayhost lmtp");

	memset(&ma, 0, sizeof ma);
	check(text_to_mailaddr(&ma, "John.Doe@Example.ORG") &&
	    strcmp(ma.user, "John.Doe") == 0 &&
	    strcmp(ma.domain, "Example.ORG") == 0,
	    "text_to_mailaddr splits user and domain");
	memset(&ma, 0, sizeof ma);
	check(text_to_mailaddr(&ma, "postmaster") &&
	    strcmp(ma.user, "postmaster") == 0 && ma.domain[0] == '\0',
	    "text_to_mailaddr without a domain");
	check(text_to_evpid("0123456789abcdef") == 0x0123456789abcdefULL,
	    "text_to_evpid");
}

static void
t_expand(void)
{
	struct expand		 e;
	struct expandnode	*xn;
	int			 types = 0, count = 0;

	memset(&e, 0, sizeof e);
	RB_INIT(&e.tree);
	if (expand_line(&e, "user@example.org, |/usr/bin/procmail, /var/mail/box, :include:/etc/list, bob", 0)) {
		RB_FOREACH(xn, expandtree, &e.tree) {
			count++;
			types |= 1 << xn->type;
		}
	}
	/* :include: is not expanded with do_includes == 0 (forward files) */
	check(count == 4 && types == ((1 << EXPAND_ADDRESS) |
	    (1 << EXPAND_FILTER) | (1 << EXPAND_FILENAME) |
	    (1 << EXPAND_USERNAME)),
	    "expand_line classifies address/filter/file/user");
	expand_clear(&e);
}

static void
t_envelope(void)
{
	static struct envelope	 a, b;
	static char		 buf[sizeof(struct envelope)];
	const char *text =
	    "version: 3\n"
	    "dispatcher: local\n"
	    "tag: fuzz\n"
	    "type: mda\n"
	    "smtpname: mx.example.org\n"
	    "helo: client.example.net\n"
	    "hostname: client.example.net\n"
	    "sockaddr: 192.0.2.1\n"
	    "sender: alice@example.net\n"
	    "rcpt: bob@example.org\n"
	    "dest: bob@example.org\n"
	    "ctime: 1700000000\n"
	    "last-try: 0\n"
	    "last-bounce: 0\n"
	    "ttl: 345600\n"
	    "retry: 0\n"
	    "flags: authenticated\n"
	    "mda-user: bob\n";
	char *copy = strdup(text);

	check(envelope_load_buffer(&a, copy, strlen(copy)) &&
	    strcmp(a.sender.user, "alice") == 0 &&
	    strcmp(a.rcpt.domain, "example.org") == 0 &&
	    a.creation == 1700000000 && a.type == D_MDA &&
	    (a.flags & EF_AUTHENTICATED) &&
	    strcmp(a.mda_user, "bob") == 0,
	    "envelope_load_buffer fields");
	check(envelope_dump_buffer(&a, buf, sizeof buf) > 0 &&
	    strstr(buf, "rcpt: bob@example.org\n") != NULL &&
	    envelope_load_buffer(&b, buf, strlen(buf)) &&
	    strcmp(b.helo, a.helo) == 0 && b.ttl == a.ttl && a.ttl == 345600 &&
	    strcmp(b.dest.user, "bob") == 0,
	    "envelope dump/load round trip");
	free(copy);
	copy = strdup("version: 1\nsender: a@b\n");
	check(!envelope_load_buffer(&b, copy, strlen(copy)),
	    "envelope_load_buffer rejects old version");
	free(copy);
}

static void
t_crypto(void)
{
	static const char key[] = "0123456789abcdef0123456789abcdef";
	const char	 msg[] = "Subject: hello\n\nsecret body\n";
	char		 enc[256], dec[256];
	size_t		 elen, dlen;

	crypto_setup(key, sizeof(key) - 1);
	elen = crypto_encrypt_buffer(msg, sizeof msg, enc, sizeof enc);
	dlen = elen ? crypto_decrypt_buffer(enc, elen, dec, sizeof dec) : 0;
	check(elen > sizeof msg && dlen == sizeof msg &&
	    memcmp(dec, msg, sizeof msg) == 0,
	    "crypto buffer round trip");
	enc[elen - 1] ^= 1;
	check(crypto_decrypt_buffer(enc, elen, dec, sizeof dec) == 0,
	    "crypto rejects a tampered buffer");
}

static void
t_rfc5322(void)
{
	struct rfc5322_parser	*p = rfc5322_parser_new();
	struct rfc5322_result	 r;
	char			 got[512] = "", tmp[128];
	const char *lines[] = { "From: alice@example.net", " (Alice)",
	    "Subject: hi", "", "body line", NULL };
	int i, ev;

	for (i = 0; lines[i]; i++) {
		rfc5322_push(p, lines[i]);
		while ((ev = rfc5322_next(p, &r)) > 0) {
			snprintf(tmp, sizeof tmp, "%d[%s]", ev,
			    ev == RFC5322_HEADER_START || ev == RFC5322_HEADER_END ? r.hdr :
			    ev == RFC5322_BODY || ev == RFC5322_HEADER_CONT ? r.value : "");
			strlcat(got, tmp, sizeof got);
		}
	}
	rfc5322_push(p, NULL);
	while ((ev = rfc5322_next(p, &r)) > 0) {
		snprintf(tmp, sizeof tmp, "%d", ev);
		strlcat(got, tmp, sizeof got);
	}
	rfc5322_free(p);
	check(strcmp(got, "1[From]2[ (Alice)]3[From]1[Subject]3[Subject]4[]5[]6[body line]7") == 0,
	    "rfc5322 event sequence");
	if (strcmp(got, "1[From]2[ (Alice)]3[From]1[Subject]3[Subject]4[]5[]6[body line]7"))
		printf("# got %s\n", got);
}

static void
t_dns(void)
{
	static const unsigned char pkt[] = {
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		/* question: example.org MX IN */
		7, 'e','x','a','m','p','l','e', 3, 'o','r','g', 0, 0, 15, 0, 1,
		/* answer: <ptr 12> MX IN ttl 3600, pref 10, mx.<ptr 12> */
		0xc0, 12, 0, 15, 0, 1, 0, 0, 0x0e, 0x10, 0, 7, 0, 10,
		2, 'm','x', 0xc0, 12,
	};
	struct unpack		 u;
	struct dns_header	 h;
	struct dns_query	 q;
	struct dns_rr		 rr;
	char			 buf[256];

	unpack_init(&u, (const char *)pkt, sizeof pkt);
	check(unpack_header(&u, &h) == 0 &&
	    h.qdcount == 1 && h.ancount == 1 &&
	    unpack_query(&u, &q) == 0 && q.q_type == T_MX &&
	    unpack_rr(&u, &rr) == 0 && rr.rr_type == T_MX &&
	    rr.rr_ttl == 3600 && rr.rr.mx.preference == 10 &&
	    strcmp(print_dname(rr.rr.mx.exchange, buf, sizeof buf),
	    "mx.example.org.") == 0,
	    "unpack_dns MX answer with compression");
	unpack_init(&u, (const char *)pkt, 20);
	unpack_header(&u, &h);
	check(unpack_query(&u, &q) == -1, "unpack_dns rejects a truncated question");
}

static void
t_srs(void)
{
	const char	*enc, *dec;
	char		 copy[256];

	env->sc_srs_key = "selftest-key";
	enc = srs_encode("alice@example.net", "example.org");
	check(enc != NULL && strncmp(enc, "SRS0=", 5) == 0 &&
	    strstr(enc, "=example.net=alice@example.org") != NULL,
	    "srs_encode SRS0 form");
	if (enc == NULL)
		return;
	strlcpy(copy, enc, sizeof copy);
	dec = srs_decode(copy);
	check(dec != NULL && strcmp(dec, "alice@example.net") == 0,
	    "srs_decode round trip");
	copy[5] = copy[5] == 'A' ? 'B' : 'A';	/* corrupt the hash */
	check(srs_decode(copy) == NULL, "srs_decode rejects a bad hash");
}

static void
t_util(void)
{
	check(valid_localpart("first.last+tag") && !valid_localpart("a b"),
	    "valid_localpart");
	check(valid_domainpart("mx.example.org") &&
	    valid_domainpart("[192.0.2.1]") && !valid_domainpart("a..b"),
	    "valid_domainpart");
}

int
main(void)
{
	harness_init();
	t_to();
	t_expand();
	t_envelope();
	t_crypto();
	t_rfc5322();
	t_dns();
	t_srs();
	t_util();
	printf("# %d tests, %d failed\n", n, failed);
	return failed != 0;
}
