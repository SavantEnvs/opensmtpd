/*
 * Queue envelope parser (envelope.c): what the queue process and
 * `smtpctl show queue` run over an on-disk envelope file
 * (queue_envelope_load_buffer -> envelope_load_buffer), then the dump the
 * queue writes back (envelope_dump_buffer).
 */
#include "harness.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct envelope	 evp;
	static char		 out[sizeof(struct envelope)];
	char			*buf;

	harness_init();
	buf = harness_cstr(data, size);
	if (envelope_load_buffer(&evp, buf, size))
		envelope_dump_buffer(&evp, out, sizeof(out));
	free(buf);
	return 0;
}
