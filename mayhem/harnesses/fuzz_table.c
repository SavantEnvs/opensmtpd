/*
 * Static/file tables (table_static.c, table.c, to.c, expand.c, mailaddr.c):
 * a `table <name> file:<path>` from smtpd.conf, i.e. an aliases, credentials,
 * relayhost, netaddr, ... map, loaded with the file backend and queried with
 * table_lookup() for one key the way lka.c / ruleset.c query it, which
 * hands the stored value to the per-service text parsers
 * (text_to_netaddr, text_to_relayhost, text_to_userinfo, expand_line, ...).
 *
 * Input: byte 0 selects the service, the first line is the lookup key, the
 * rest is the table file.
 */
#include "harness.h"

static const enum table_service services[] = {
	K_ALIAS, K_DOMAIN, K_CREDENTIALS, K_NETADDR, K_USERINFO, K_SOURCE,
	K_MAILADDR, K_ADDRNAME, K_MAILADDRMAP, K_RELAYHOST,
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	enum table_service	 kind;
	struct table		*t;
	union lookup		 lk;
	char			 path[PATH_MAX];
	const uint8_t		*nl;
	char			*key;
	int			 fd, r;

	if (size < 2)
		return -1;
	harness_init();

	kind = services[data[0] % (sizeof(services) / sizeof(services[0]))];
	data++;
	size--;
	if ((nl = memchr(data, '\n', size)) == NULL)
		return -1;
	key = harness_cstr(data, nl - data);
	fd = harness_tmpfile(nl + 1, size - (nl + 1 - data), path, sizeof(path));
	close(fd);

	t = table_create(env, "file", "<fuzz>", path);
	if (table_config(t) && table_open(t)) {
		memset(&lk, 0, sizeof(lk));
		r = table_lookup(t, kind, key, &lk);
		if (r == 1 && kind == K_ALIAS)
			expand_free(lk.expand);
		else if (r == 1 && kind == K_MAILADDRMAP)
			maddrmap_free(lk.maddrmap);
		table_match(t, kind, key);
	}
	table_close(t);
	table_destroy(env, t);
	unlink(path);
	free(key);
	return 0;
}
