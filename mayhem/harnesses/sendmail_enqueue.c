/*
 * sendmail(8) compatibility mode of smtpctl (enqueue.c): what any local
 * user, cron job or MUA runs to submit a message.  The input file is the
 * message on stdin; `sendmail -t` reads the RFC 5322 headers, takes the
 * sender from From: and the recipients from To:/Cc:/Bcc: (parse_message ->
 * parse_addr / parse_addr_terminal), and rewrites the message for the
 * server.
 *
 * This is smtpctl's own sendmail_compat() path with smtpctl.c's main()
 * renamed: with no smtpd running, enqueue() spools the message to the
 * offline file, here a scratch file under $TMPDIR (offline_file() would use
 * /var/spool/smtpd/offline, which needs the setgid smtpctl).  enqueue()
 * exit()s on a malformed address, so this is a whole-process (AFL) target:
 *   sendmail-enqueue <message file>
 */
#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

extern int	 sendmail;

int
main(int argc, char **argv)
{
	char		*args[] = { "sendmail", "-t", NULL };
	char		 path[PATH_MAX];
	const char	*dir = getenv("TMPDIR");
	FILE		*ofp;
	int		 fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <message>\n", argv[0]);
		return 2;
	}
	if (freopen(argv[1], "r", stdin) == NULL) {
		perror(argv[1]);
		return 2;
	}
	if (dir == NULL || *dir == '\0')
		dir = "/tmp";
	snprintf(path, sizeof(path), "%s/sendmail-offline-XXXXXX", dir);
	if ((fd = mkstemp(path)) == -1 || (ofp = fdopen(fd, "w+")) == NULL) {
		perror(path);
		return 2;
	}
	unlink(path);

	/* as smtpctl's main() and sendmail_compat() */
	log_init(1, LOG_MAIL);
	sendmail = 1;
	return enqueue(2, args, ofp);
}
