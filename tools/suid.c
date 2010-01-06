
#define _GNU_SOURCE /* For setres* */

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

static int real_uid;
static int set_uid;

static int real_gid;
static int set_gid;

void init()
{
	real_uid = getuid();
	set_uid = geteuid();
                     
	real_gid = getgid();
	set_gid = getegid();
}

void print(void)
{
	int uid, euid;
	int gid, egid;

	uid = getuid();
	euid = geteuid();

	gid = getgid();
	egid = getegid();

	printf("UID/eUID: %d/%d GID/eGID: %d/%d\n", uid, euid, gid, egid);
}


void check_perms(void)
{
	printf("Checking root perms! ");
	print();

	FILE *f = fopen("/etc/shadow", "r");
	if (!f) {
		printf("We do not have root access permissions\n");
	} else {
		fclose(f);
		printf("Root permissions\n");
	}
}

void drop_temporarily(void)
{
	/* On systems without setres* use setre*. But make sure it works */
	const int gid = getgid(), uid = getuid();
	const int egid = getegid(), euid = geteuid();

	if (setresuid(uid, uid, euid) != 0)
		goto error;
	if (setresgid(gid, gid, egid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != getuid() || getegid() != getgid()) {
		printf("d_t: fun\n");
		goto error;
	}
	return;
error:
	printf("d_t: failure\n");
	exit(EXIT_FAILURE);
}

void drop_pernamently(void)
{
	/* On systems without setres* use setre*. But make sure it works */
	const int gid = getgid(), uid = getuid();

	if (setresuid(uid, uid, uid) != 0)
		goto error;
	if (setresgid(gid, gid, gid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != getuid() || getegid() != getgid()) {
		printf("d_t: fun\n");
		goto error;
	}

	return;
error:
	printf("d_p: failure\n");
	exit(EXIT_FAILURE);
}

void restore(void)
{
	/* On systems without setres* use setre*. But make sure it works */

	/* 0 should be remembered before! */
	if (setresuid(real_uid, set_uid, set_uid) != 0)
		goto error;
	if (setresgid(real_gid, set_gid, set_gid) != 0)
		goto error;

	/* Paranoid check */
	if (geteuid() != set_uid || getegid() != set_gid) {
		printf("d_t: fun\n");
		goto error;
	}

	return;
error:
	printf("d_p: failure\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	clearenv();

	init();

	printf("Initial: ");
	print();

	check_perms();

	printf("* TEMPORARY DROP \n");
	drop_temporarily();

	check_perms();

	printf("* RESTORE \n");
	restore();

	check_perms();

	printf("* PERNAMENT DROP \n");
	drop_pernamently();

	check_perms();


	printf("* RESTORE (we should fail now) \n");
	restore();

	check_perms();
		

	return 0;
}
