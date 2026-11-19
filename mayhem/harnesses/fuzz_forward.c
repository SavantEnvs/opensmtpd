/*
 * ~/.forward files (forward.c, expand.c, to.c): read by the lookup process
 * for local deliveries with forwards_get(), every line parsed by expand_line()
 * into address / filename / |command / :include: / error nodes.
 */
#include "harness.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct expand	 expand;
	int		 fd;

	harness_init();
	memset(&expand, 0, sizeof(expand));
	RB_INIT(&expand.tree);

	fd = harness_tmpfile(data, size, NULL, 0);
	forwards_get(fd, &expand);	/* closes fd */
	expand_clear(&expand);
	return 0;
}
