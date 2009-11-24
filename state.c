#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include "print.h"
#include "state.h"
#include "num.h"

/********************************************
 * Helper functions for managing state files 
 * 
 ********************************************/

/* Returns name to user state file */
static char *_state_file()
{
	static struct passwd *pwdata = NULL;
	const char *home;

	home = getenv("HOME");

	if (!home) {
		/* No env? Get home dir for current UID */
		uid_t uid = geteuid();
		pwdata = getpwuid(uid);

		if (pwdata) {
			home = pwdata->pw_dir;
		} else 
			return NULL; /* Unable to locate home directory */
	}

	/* Append filename */
	char *name;
	int length;

	length = strlen(home);
	length += strlen(STATE_FILENAME);
	length += 2;

	name = malloc(length);
	if (!name)
		return NULL;

	int ret = snprintf(name, length, "%s/%s", home, STATE_FILENAME);

	assert( ret == length - 1 );

	if (ret != length -1) {
		free(name);
		return NULL;
	}

	return name;
}

/* Check if file exists, and if 
 * it does - enforce it's permissions */
static int _state_file_permissions(const char *state_file)
{
	struct stat st;
	if (stat(state_file, &st) != 0) {
		/* Does not exists */
		return 1;
	}

	/* It should be a file or a link to file */
	if (!S_ISREG(st.st_mode)) {
		/* Error, not a file */
		print(PRINT_ERROR, "ERROR: %s is not a regular file\n", state_file);
		return 2;
	}

	if (chmod(state_file, S_IRUSR|S_IWUSR) != 0) {
		print(PRINT_ERROR, "Unable to enforce " STATE_FILENAME " permissions");
		print_perror(PRINT_ERROR, "chmod");
		return 1;
	}
	return 0;
}


static int _state_lock(int *lock_fd) 
{
        char *filename = _state_file();
        struct flock fl;
        int ret;
        int cnt;

        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = fl.l_len = 0;

        *lock_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	free(filename);
        if (*lock_fd == -1) {
                return 1; /* Unable to create file, therefore unable to obtain lock */
        } /* FIXME: DO NOT CREATE */

        /*
	 * Trying to lock the file 20 times.
	 * Any working otpasswd session shouldn't lock it for so long.
	 *
	 * Therefore we have to options. Fail each login if we can't get the lock
	 * or ignore locking (we can get a race condition then) but try to
	 * authenticate the user nevertheless.
	 *
	 * I'll stick to the second option for now.
	 *
	 */
        for (cnt = 0; cnt < 20; cnt++) {
                ret = fcntl(*lock_fd, F_SETLK, &fl);
                if (ret == 0)
                        break;
                usleep(700);
        }

        if (ret != 0) {
                /* Unable to lock for 10 times */
                close(*lock_fd), *lock_fd = -1;
                return 1;
        }

        return 0; /* Got lock */
}

static int _state_unlock(int *lock_fd) 
{
        struct flock fl;

        if (lock_fd < 0)
                return 1; /* No lock to release */

        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = fl.l_len = 0;

        if (fcntl(*lock_fd, F_SETLK, &fl) != 0) {
                /* Strange error while releasing the lock */
                close(*lock_fd), *lock_fd = -1;
                return 2;
        }

        close(*lock_fd), *lock_fd = -1;

        return 0;
}

/**********************************************
 * Interface functions for managing state files
 * 
 **********************************************/

/* Load state file.
 * if lock = 1 then the lock persists 
 * until state_store is called. Otherwise
 * we lock file only for reading */
int state_load(state *s, int lock)
{
	if (s->filename == NULL) {
		print(PRINT_CRITICAL, "State data not initialized?\n");
		return 1;
	}

	/*
	 * Lock file
	 * Read data
	 * Unlock / leave locked?
	 */

	return 1;
}

int state_store(const state *s)
{
	return 1;
}



/******************************************
 * Functions for managing state information
 ******************************************/

/* Initializes state structure. Must be called first */
int state_init(state *s)
{
	mpz_init(s->counter);
	mpz_init(s->sequence_key);
	s->fd = -1;
	s->locked = 0;
	s->filename = _state_file();
	if (s->filename == NULL) {
		print(PRINT_CRITICAL, "Unable to locate user home directory\n");
		return 1;
	}
	return 0;
}

/* Deinitializes state struct; should clear any secure-relevant data */
void state_fini(state *s)
{
	num_dispose(s->counter);
	num_dispose(s->sequence_key);
	free(s->filename);
}


void state_key_generate(state *s)
{
	mpz_set_d(s->counter, 1);

	unsigned char tmp[32] = {0x00};
	tmp[3] = 0xAB;
//	assert( crypto_rng(tmp, 32, 0) == 0 ); /* TODO: Change to secure */

	num_from_bin(s->sequence_key, tmp, 32);
}

void state_debug(const state *s)
{
	printf("Sequence key: ");
	num_print(s->sequence_key, 16);
	printf("Counter: ");
	num_print(s->counter, 16);
}
