/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009, 2010 by Tomasz bla Fortuna <bla@thera.be>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with otpasswd. If not, see <http://www.gnu.org/licenses/>.
 *
 **********************************************************************/

/* On systems without setres* use setre* to drop pernamently.
 * And sete* to drop temporarily. But make sure it works */
#if OS_LINUX
/* for setresuid, setresgid */
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

/* signal */
#include <signal.h>

/* isdigit */
#include <ctype.h>

/* umask */
#include <sys/types.h>
#include <sys/stat.h>
/* pwd */
#include <pwd.h>
/* open */
#include <fcntl.h>

#include "security.h"

/* Initial remembered values */
static uid_t real_uid=-1, set_uid=-1;
static uid_t real_gid=-1, set_gid=-1;
static int is_suid = 0, has_tty = 0;

extern char **environ;

void security_init(void)
{
	int ret;

	/* Don't use stderr or any other pipe. */
	for (ret=2; ret < 20; ret++)
		(void) close(ret);

	/* We generally shouldn't have any terminal connected,
	 * but we want to tell this user nicely. */
	if (isatty(0) == 1 && isatty(1) == 1) {
		has_tty = 1;
	} else {
		has_tty = 0;
	}

	ret = chdir("/");
	if (ret != 0) {
		if (has_tty)
			printf("FATAL: Unable to change directory.\n");
		exit(EXIT_FAILURE);
	}

	/* Set umask to 700 so others/group won't read our files */
	umask(S_IWOTH | S_IROTH | S_IXOTH | S_IWGRP | S_IRGRP | S_IXGRP);

	/* Store initial UIDs/GIDs */
	real_uid = getuid();
	set_uid = geteuid();

	real_gid = getgid();
	set_gid = getegid();
	
	/* Just check if everything is all right... */
	if (real_gid != set_gid) {
		if (has_tty)
			printf("FATAL: otpagent is not supposed to work as "
			       "SGID program. SUID root or nothing.\n");
		exit(EXIT_FAILURE);
	}

	if (real_uid != set_uid) {
		is_suid = 1;

		if (set_uid != 0) {
			if (has_tty) {
				printf("FATAL: otpagent should be either "
				       "SUID-root or non-SUID at all.\n"
				       "       Agent will drop permissions "
				       "itself to configured user after start.\n");
			}
			exit(EXIT_FAILURE);
		}
	}


	/* Clear the environment. */
#if OS_FREEBSD
	environ = NULL;
#else
	ret = clearenv();
	if (ret != 0) {
		if (has_tty)
			printf("FATAL: Unable to clear environment\n");
		exit(EXIT_FAILURE);
	}
#endif
	if (environ != NULL || (environ && *environ != NULL)) {
		if (has_tty)
			printf("FATAL: Environment not clear!\n");
		exit(EXIT_FAILURE);
	}
	
	/* Re-set some basic environment variables. 
	 * Most probably it's completely unnecesary in this app. */
	putenv("PATH=/bin:/usr/bin");
	putenv("IFS= \t\n");

	if (is_suid) {
		/* Disable signals */
		ret = 0;
		if (signal(SIGTERM, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGINT, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGQUIT, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGTSTP, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGALRM, SIG_IGN) == SIG_ERR)
			ret++;
		if (signal(SIGTTOU, SIG_IGN) == SIG_ERR)
			ret++;

		if (ret) {
			if (has_tty)
				printf("FATAL: Unable to disable signals."
				       " Quitting before we touch state files.\n");
			exit(EXIT_FAILURE);
		}

		/* We are suid-root. TODO: Drop capabilities. */
	}
}

static void _ensure_no_privileges()
{
	if ((real_gid != set_gid) && (setgid(set_gid) == 0))
		goto error;

	if ((real_uid != set_uid) && (setuid(set_uid) == 0))
		goto error;


	return;
error:
	if (has_tty)
		printf("Privilege ensurance check failed. Dying.\n");
	exit(EXIT_FAILURE);
}

void security_permanent_switch(uid_t uid, uid_t gid)
{
	assert(real_gid != -1);

	/* Draft of setre version:
	 * setreuid(real_uid, set_uid); - copy euid to suid
	 * seteuid(drop_to); - drop
	 * ensure correctness
	 */
	if (setresgid(gid, gid, gid) != 0) {
		goto error;
	}


	if (setresuid(uid, uid, uid) != 0) {
		goto error;
	}

	/* Paranoid check */
	if (geteuid() != uid) {
		goto error;
	}
	
	return;
error:
	if (has_tty)
		printf("Permanent user switch failed. Dying.\n");
	exit(EXIT_FAILURE);
}


void security_permanent_drop(void)
{
	assert(real_gid != -1);

	/* Draft of setre version:
	 * setreuid(drop_to, drop_to);
	 * Ensure somehow the saved-UID is correct (/proc)
	 */

	if (setresgid(real_gid, real_gid, real_gid) != 0)
		goto error;
	if (setresuid(real_uid, real_uid, real_uid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != getuid() || getegid() != getgid()) {
		goto error;
	}

	/* We ensure this only if not root, as "dropping" SUID/SGID
	 * permission while being root will still allow us to SUID
	 * back to set_uid user */
	if (real_uid != 0)
		_ensure_no_privileges();

	return;
error:
	if (has_tty)
		printf("Permanent privilege drop failed. Dying.\n");
	exit(EXIT_FAILURE);
}

int security_is_privileged()
{
	if (real_uid == 0) 
		return 1;
	else
		return 0;
}

int security_is_suid()
{
	if (is_suid) 
		return 1;
	else
		return 0;
}

char *security_get_calling_user(void)
{
	const struct passwd *pwdata;
	const uid_t uid = real_uid;

	pwdata = getpwuid(uid);

	if (pwdata) {
		return strdup(pwdata->pw_name);
	} else {
		/* Unable to locate home directory */
		return NULL;
	}
}

char *security_parse_user(const char *spec)
{
	uid_t uid;
	struct passwd *pwdata;

	assert(spec);

	if (isdigit(spec[0])) {
		/* Parse UID */
		if (sscanf(spec, "%d", &uid) != 1) {
			return NULL;
		}

		pwdata = getpwuid(uid);
		if (!pwdata) {
			return NULL;
		}

		return strdup(pwdata->pw_name);
	} else {
		/* Ensure name exists */
		pwdata = getpwnam(spec);
		if (!pwdata)
			return NULL; /* Doesn't exists */
		else
			return strdup(spec);
	}
}
