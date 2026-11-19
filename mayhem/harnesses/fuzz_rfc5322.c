/*
 * RFC 5322 message parser (rfc5322.c): every line of a message received in an
 * SMTP DATA phase is pushed through it, exactly as smtp_session.c's
 * smtp_tx_dataline() does (headers unfolded for To/Cc/From).
 */
#include "includes.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "rfc5322.h"

static void
drain(struct rfc5322_parser *p)
{
	struct rfc5322_result res;
	volatile size_t sink = 0;

	for (;;) {
		switch (rfc5322_next(p, &res)) {
		case -1:
		case RFC5322_NONE:
			return;
		case RFC5322_HEADER_START:
			if (!strcasecmp("To", res.hdr) ||
			    !strcasecmp("Cc", res.hdr) ||
			    !strcasecmp("From", res.hdr)) {
				rfc5322_unfold_header(p);
				continue;
			}
			sink += strlen(res.hdr) + strlen(res.value);
			break;
		case RFC5322_HEADER_CONT:
		case RFC5322_BODY:
			sink += strlen(res.value);
			break;
		case RFC5322_HEADER_END:
			if (!strcasecmp("To", res.hdr) ||
			    !strcasecmp("Cc", res.hdr) ||
			    !strcasecmp("From", res.hdr))
				sink += strlen(res.hdr) + strlen(res.value);
			break;
		case RFC5322_END_OF_MESSAGE:
			return;
		default:
			break;
		}
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rfc5322_parser	*p;
	char			*buf, *line, *nl;

	if ((p = rfc5322_parser_new()) == NULL)
		return 0;
	if ((buf = malloc(size + 1)) == NULL)
		abort();
	memcpy(buf, data, size);
	buf[size] = '\0';

	line = buf;
	while (line < buf + size) {
		if ((nl = strchr(line, '\n')) != NULL)
			*nl = '\0';
		if (rfc5322_push(p, line) == -1)
			goto done;
		drain(p);
		if (nl == NULL)
			break;
		line = nl + 1;
	}
	/* end of message */
	if (rfc5322_push(p, NULL) != -1)
		drain(p);
done:
	rfc5322_free(p);
	free(buf);
	return 0;
}
