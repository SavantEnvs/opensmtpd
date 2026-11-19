/*
 * Encrypted queue (crypto.c): the queue process decrypts envelopes with
 * crypto_decrypt_buffer() and message files with crypto_decrypt_file()
 * (queue_backend.c), smtpctl does the latter for `smtpctl encrypt -d`.
 * The key is fixed: crypto_setup() is what smtpd runs once at startup.
 */
#include "harness.h"

static const char key[] = "0123456789abcdef0123456789abcdef";

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static char	 out[sizeof(struct envelope)];
	FILE		*in, *ofp;
	char		*obuf = NULL;
	size_t		 olen = 0;

	harness_init();
	if (!crypto_setup(key, sizeof(key) - 1))
		abort();

	/* as queue_envelope_load_buffer() */
	crypto_decrypt_buffer((const char *)data, size, out, sizeof(out));

	/* as queue_message_fd_r() */
	if (size == 0)
		return 0;
	if ((in = fmemopen((void *)data, size, "r")) == NULL)
		abort();
	if ((ofp = open_memstream(&obuf, &olen)) == NULL)
		abort();
	crypto_decrypt_file(in, ofp);
	fclose(in);
	fclose(ofp);
	free(obuf);
	return 0;
}
