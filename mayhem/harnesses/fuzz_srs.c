/*
 * Sender Rewriting Scheme (srs.c): a bounce to an SRS0=/SRS1= address is
 * decoded with srs_decode() (lka_session.c); a forwarded sender is encoded with
 * srs_encode(). The key is fixed, as `srs key` in smtpd.conf sets it.
 */
#include "harness.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct mailaddr	 maddr;
	const char	*dec;
	char		*addr;

	harness_init();
	env->sc_srs_key = "fuzz-srs-key";
	env->sc_srs_key_backup = "fuzz-srs-backup-key";

	addr = harness_cstr(data, size);
	/* as lka_session.c */
	if ((dec = srs_decode(addr)) != NULL)
		text_to_mailaddr(&maddr, dec);
	srs_encode(addr, "example.org");
	free(addr);
	return 0;
}
