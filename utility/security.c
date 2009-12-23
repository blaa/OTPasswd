/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
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
 **********************************************************************/

/* On systems without setres* use setre* to drop pernamently.
 * And sete* to drop temporarily. But make sure it works */
#if OS_LINUX
/* for setresuid, setresgid */
#define _GNU_SOURCE 
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

/* umask */
#include <sys/types.h>
#include <sys/stat.h>

#include "security.h"

/* Initial remembered values */
static uid_t real_uid=-1, set_uid=-1;
static uid_t real_gid=-1, set_gid=-1;

/* When dropping drop to this user */
static const uid_t drop_to = -1;

extern char **environ;

void security_init(void)
{
	int ret;

	/* Store initial UIDs/GIDs */
	real_uid = getuid();
	set_uid = geteuid();
                     
	real_gid = getgid();
	set_gid = getegid();

	/* As we might be SUID/SGID binary. Clear the environment. */
	ret = clearenv();
	if (ret != 0) {
		printf("Unable to clear environment\n");
		exit(EXIT_FAILURE);
	}

	ret = chdir("/");
	if (ret != 0) {
		printf("Unable to change directory to /\n");
		exit(EXIT_FAILURE);
	}

	if (environ != NULL || (environ && *environ != NULL)) {
		printf("Environment not clear!\n");
		exit(EXIT_FAILURE);
	}

	putenv("PATH=/bin:/usr/bin");

	/* Set umask so others won't read our files */
	if (real_gid != set_gid) {
		/* We are SGID. Don't remove bits from group... */
		umask(S_IWOTH | S_IROTH | S_IXOTH);
	}
	else {
		/* Normal or SUID */
		umask(S_IWOTH | S_IROTH | S_IXOTH | S_IWGRP | S_IRGRP | S_IXGRP);
	}
}

static void _ensure_no_privileges()
{
	if ((real_gid != set_gid) && (setuid(set_gid) == 0))
		goto error;

	if ((real_uid != set_uid) && (setuid(set_uid) == 0))
		goto error;


	return;
error:
	printf("Privilege check failed. Dying.\n");
	exit(EXIT_FAILURE);
}

void security_temporal_drop(void)
{
	assert(real_gid != -1);

	/* Draft of setre version:
	 * setreuid(real_uid, set_uid); - copy euid to suid
	 * seteuid(drop_to); - drop
	 * ensure correctness
	 */

	if (setresgid(real_gid, drop_to, set_gid) != 0)
		goto error;
	if (setresuid(real_uid, drop_to, set_uid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != drop_to || getegid() != drop_to) {
		printf("d_t: fun\n");
		goto error;
	}

	return;
error:
	printf("Temporal privilege drop failed. Dying.\n");
	exit(EXIT_FAILURE);
}

void security_permanent_drop(void)
{
	assert(real_gid != -1);

	/* Draft of setre version:
	 * setreuid(drop_to, drop_to);
	 * Ensure somehow the saved-UID is correct (/proc)
	 */

	if (setresgid(drop_to, drop_to, drop_to) != 0)
		goto error;
	if (setresuid(drop_to, drop_to,  drop_to) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != getuid() || getegid() != getgid()) {
		goto error;
	}

	_ensure_no_privileges();

	return;
error:
	printf("Permanent privilege drop failed. Dying.\n");
	exit(EXIT_FAILURE);
}

void security_restore(void)
{
	assert(real_gid != -1);

	if (setresuid(real_uid, set_uid, set_uid) != 0)
		goto error;
	if (setresgid(real_gid, set_gid, set_gid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != set_uid || getegid() != set_gid) {
		goto error;
	}

	return;
error:
	printf("Privilege restore failed. Dying.\n");
	exit(EXIT_FAILURE);
}

