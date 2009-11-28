/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * (C) 2009 by Tomasz bla Fortuna <bla@thera.be>, <bla@af.gliwice.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * See LICENSE file for details.
 **********************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include "print.h"
#include "state.h"
#include "crypto.h"
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
static int _state_file_permissions(const state *s)
{
	struct stat st;
	if (stat(s->filename, &st) != 0) {
		/* Does not exists */
		return 1;
	}

	/* It should be a file or a link to file */
	if (!S_ISREG(st.st_mode)) {
		/* Error, not a file */
		print(PRINT_ERROR, "ERROR: %s is not a regular file\n", s->filename);
		return 2;
	}

	if (chmod(s->filename, S_IRUSR|S_IWUSR) != 0) {
		print_perror(PRINT_ERROR, "chmod");
		print(PRINT_ERROR, "Unable to enforce %s permissions", s->filename);
		return 3;
	}
	return 0;
}


static int _state_lock(state *s)
{
	struct flock fl;
	int ret;
	int cnt;
	int fd;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	fd = open(s->filename, O_WRONLY, 0);

	if (fd == -1) {
		print_perror(PRINT_NOTICE, "Unable to lock file");
		return 1; /* Unable to create file, therefore unable to obtain lock */
	}/* FIXME: DO NOT CREATE */

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
		ret = fcntl(fd, F_SETLK, &fl);
		if (ret == 0)
			break;
		usleep(700);
	}

	if (ret != 0) {
		/* Unable to lock for 10 times */
		close(fd);
		print(PRINT_NOTICE, "Unable to lock opened state file\n");
		return 1;
	}

	s->lock_fd = fd;
	print(PRINT_NOTICE, "Got lock on state file\n");

	return 0; /* Got lock */
}

static int _state_unlock(state *s)
{
	struct flock fl;

	if (s->lock_fd < 0) {
		print(PRINT_NOTICE, "No lock to release!\n");
		return 1; /* No lock to release */
	}

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	int ret = fcntl(s->lock_fd, F_SETLK, &fl);

	close(s->lock_fd);
	s->lock_fd = -1;

	if (ret != 0) {
		print(PRINT_NOTICE, "Strange error while releasing lock\n");
		/* Strange error while releasing the lock */
		return 2;
	}

	return 0;
}


static int _rng_read(const char *device, const char *msg, unsigned char *buf, const int count)
{
	const char spinner[] = "|/-\\"; // ".oO0Oo. ";
	const int size = strlen(spinner);
	int i;
	FILE *f;
	f= fopen(device, "r");
	if (!f) {
		return 1;
	}

	puts(
		"Hint: Move your mouse, cause some disc activity\n"
		"or type on keyboard to make the progress faster.\n");

	for (i=0; i<count; i++) {
		buf[i] = fgetc(f);
		if (msg && i%11 == 0) {
			printf("\r%s %3d%%  %c ", msg, i*100 / count, spinner[i/11 % size]);
			fflush(stdout);
		}
	}
	fclose(f);
	if (msg)
		printf("\r%s OK!       \n", msg);
	return 0;
}

/**********************************************
 * Interface functions for managing state files
 *
 **********************************************/

int state_load(state *s)
{
	/* TODO: Maybe rewrite using strtok? */


	if (s->filename == NULL) {
		print(PRINT_CRITICAL, "State data not initialized?\n");
		return 1;
	}

	/*
	 * Lock file
	 * Read data
	 * Unlock / leave locked?
	 */
	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while reading from it\n");
	}

	int ret = 0;
	FILE *f;

	if (_state_file_permissions(s) != 0) {
		print(PRINT_NOTICE, "Unable to load state file\n");
		return 1;
	}

	f = fopen(s->filename, "r");
	if (!f) {
		print_perror(PRINT_ERROR, "Unable to open %s for reading. Have you tried -k option?", 
			     s->filename);
		return 1;
	}

	ret = mpz_inp_str(s->sequence_key, f, STATE_BASE);
	if (ret == 0) {
		print_perror(PRINT_ERROR, 
			     "Error while reading sequence key from %s", 
			     s->filename);
		goto error;
	}

	ret = mpz_inp_str(s->counter, f, STATE_BASE);
	if (ret == 0) {
		print_perror(PRINT_ERROR, 
			     "Error while reading counter from %s",
			     s->filename);
		goto error;
	}

	ret = mpz_inp_str(s->furthest_printed, f, STATE_BASE);
	if (ret == 0) {
		print_perror(PRINT_ERROR,
			     "Error while reading number of "
			     "last printed passcode from %s", s->filename);
		goto error;
	}

	ret = fscanf(f, "%u\n", &s->code_length);
	if (ret != 1) {
		print_perror(PRINT_ERROR, 
			     "Error while reading passcode length from %s",
			     s->filename);
		goto error;
	}

	ret = fscanf(f, "%u", &s->flags);
	if (ret != 1) {
		print_perror(PRINT_ERROR, "Error while reading flags from %s",
			     s->filename);
		goto error;
	}

	/* Read a whitecharacter after flags */
	if (fgetc(f) != '\n') {
		print_perror(PRINT_ERROR, "Syntax error in %s.", s->filename);
		goto error;
	}

	if (fgets(s->label, sizeof(s->label), f) == NULL) {
		/* Nothing read, there should be at least one \n */
		print_perror(PRINT_ERROR, "Error while reading label from %s"
			     ", unexpected end of file",
			     s->filename);
		goto error;
	}

	if (s->label[strlen(s->label) - 1] != '\n') {
		/* \n is put there if we find end of file,
		 * it's lack might be caused by too long entry
		 * at end of file 
		 */
		print_perror(PRINT_ERROR, "Garbage near label data in %s.", s->filename);
		goto error;
	}

	if (fgets(s->contact, sizeof(s->contact), f) == NULL) {
		/* Nothing read, there should be at least one \n */
		print_perror(PRINT_ERROR, "Error while reading contact data from %s"
			     ", unexpected end of file",
			     s->filename);
		goto error;
	}

	if (s->label[strlen(s->contact) - 1] != '\n') {
		/* \n is put there if we find end of file,
		 * it's lack might be caused by too long entry
		 * at end of file 
		 */
		print_perror(PRINT_ERROR, "Garbage near contact data at end of %s.", s->filename);
		goto error;
	}


	s->label[strlen(s->label) - 1] = '\0';

	/* Everything is read. Now - check if it's correct */
	/* TODO, FIXME */
	if (mpz_sgn(s->sequence_key) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative sequence key. File %s is corrupted.\n",
		      s->filename);
		goto error;
	}

	if (mpz_sgn(s->counter) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative counter. File %s is corrupted.\n",
		      s->filename);
		goto error;
	}

	if (mpz_sgn(s->furthest_printed) == -1) {
		print(PRINT_ERROR, 
		      "Last printed card has a negative counter. File %s is corrupted.\n",
		      s->filename);
		goto error;
	}

	if (s->code_length < 2 || s->code_length > 16) {
		print(PRINT_ERROR, "Illegal passcode length. %s is invalid\n", 
		      s->filename);
		goto error;
	}

	if (s->flags > (FLAG_SHOW|FLAG_SKIP|FLAG_ALPHABET_EXTENDED|FLAG_NOT_SALTED)) {
		print(PRINT_ERROR, "Unsupported set of flags. %s is invalid\n", 
		      s->filename);
		goto error;

	}
	fclose(f);
	return 0;

error:
	fclose(f);
	return 1;
}

int state_store(const state *s)
{
	/* Rewrite maybe using gmp_scanf? */
	int ret;
	FILE *f;

	if (s->filename == NULL) {
		print(PRINT_CRITICAL, "State data not initialized?\n");
		return 1;
	}

	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while writting to it\n");
	}

	f = fopen(s->filename, "w");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for writting",
			     s->filename);
		return 1;
	}

	/* Write using ascii safe approach */
	ret = mpz_out_str(f, STATE_BASE, s->sequence_key);
	if (ret == 0) {
		print(PRINT_ERROR, "Error while saving sequence key\n");
		goto error;
	}

	if (fputc('\n', f) == EOF) {
		print(PRINT_ERROR, "Error while writting to %s\n", 
		      s->filename);
		goto error;
	}

	ret = mpz_out_str(f, STATE_BASE, s->counter);
	if (ret == 0) {
		print(PRINT_ERROR, "Error while saving counter\n");
		goto error;
	}

	if (fputc('\n', f) == EOF) {
		print(PRINT_ERROR, "Error while writting to %s\n", 
		      s->filename);
		goto error;
	}

	ret = mpz_out_str(f, STATE_BASE, s->furthest_printed);
	if (ret == 0) {
		print(PRINT_ERROR, 
		      "Error while saving number of last printed passcode\n");
		goto error;
	}

	ret = fprintf(f, "\n%u\n%u\n%s\n%s\n", s->code_length, s->flags, s->label, s->contact);
	if (ret <= 0) {
		print(PRINT_ERROR, 
		      "Error while writting passlength, flags, label and contact data to %s\n",
		      s->filename);
		goto error;
	}

	/* lock? */
	print(PRINT_NOTICE, "State file written\n");
	fclose(f);
	return 0;

error:
	fclose(f);
	return 1;
}

int state_load_inc_store(state *s)
{
	int ret = 1;

	if (_state_lock(s) != 0)
		return 1;

	if (state_load(s) != 0)
		goto cleanup1;

	/* Store current counter */
	mpz_t tmp;
	mpz_init(tmp);
	mpz_set(tmp, s->counter);

	/* Increment and save state */
	state_inc(s);

	if (state_store(s) != 0) {
		goto cleanup2;
	}

	/* Restore current counter */
	mpz_set(s->counter, tmp);

cleanup2:
	num_dispose(tmp);

cleanup1:
	_state_unlock(s);
	return ret;
}

/******************************************
 * Functions for managing state information
 ******************************************/
void state_inc(state *s)
{
	mpz_add_ui(s->counter, s->counter, 1);
}

int state_init(state *s)
{
	const char salt_mask[] =
		"FFFFFFFFFFFFFFFFFFFFFFFF00000000";
	assert(sizeof(salt_mask) == 33);

	mpz_init(s->counter);
	mpz_init(s->sequence_key);
	mpz_init(s->furthest_printed);
	mpz_init(s->current_card);
	assert(mpz_init_set_str(s->salt_mask, salt_mask, 16) == 0);

	s->code_length = 4;
	s->flags = FLAG_SHOW;
	memset(s->label, 0x00, STATE_LABEL_SIZE);

	s->fd = -1;
	s->lock_fd = -1;
	s->filename = _state_file();
	if (s->filename == NULL) {
		print(PRINT_CRITICAL, 
		      "Unable to locate user home directory\n");
		return 1;
	}

	s->codes_on_card = s->codes_in_row = s->current_row =
		s->current_column = 0;
	return 0;
}

void state_fini(state *s)
{
	num_dispose(s->counter);
	num_dispose(s->sequence_key);
	num_dispose(s->furthest_printed);
	num_dispose(s->current_card);
	num_dispose(s->salt_mask);

	free(s->filename);
}

int state_key_generate(state *s, const int salt)
{
	unsigned char entropy_pool[128]; /* 1024 bits */
	unsigned char key_bin[32];
	/* TODO: implement salting */
	print(PRINT_NOTICE, "Generating new %s key.\n", salt ? "salted" : "not salted");

	/* Gather entropy from random, then fallback to urandom... */
	if (_rng_read(
		    "/dev/random",
		    "Gathering entropy...",
		    entropy_pool, sizeof(entropy_pool)) != 0)
	{
		print_perror(PRINT_WARN, "Unable to open /dev/random");
		print(PRINT_NOTICE,
		      "Trying /dev/urandom device\n");

		if (_rng_read(
			    "/dev/urandom",
			    "Gathering entropy...",
			    entropy_pool,
			    sizeof(entropy_pool)) != 0)
		{
			print(PRINT_ERROR,
			      "Unable to use neither"
			      " /dev/random nor urandom.\n");
			return 1;
		}
	}
	if (salt == 0) {
		crypto_sha256(entropy_pool, sizeof(entropy_pool), key_bin);
		memset(entropy_pool, 0, sizeof(entropy_pool));

		num_from_bin(s->sequence_key, key_bin, sizeof(key_bin));
		memset(key_bin, 0, sizeof(key_bin));
		mpz_set_d(s->counter, 0);
		mpz_set_d(s->furthest_printed, 0);
	} else {
		/* Use half of entropy to generate key */
		crypto_sha256(entropy_pool, sizeof(entropy_pool)/2, key_bin);
		num_from_bin(s->sequence_key, key_bin, sizeof(key_bin));

		/* And half to initialize counter */
		crypto_sha256(entropy_pool+sizeof(entropy_pool)/2, sizeof(entropy_pool)/2, key_bin);
		num_from_bin(s->counter, key_bin, 16); /* Counter is 128 bit only */
		mpz_and(s->counter, s->counter, s->salt_mask);
		mpz_set(s->furthest_printed, s->counter);

		memset(entropy_pool, 0, sizeof(entropy_pool));
		memset(key_bin, 0, sizeof(key_bin));
	}

	if (salt)
		s->flags &= ~(FLAG_NOT_SALTED); 
	return 0;
}


/******************************************
 * Miscellaneous functions
 ******************************************/
void state_debug(const state *s)
{
	printf("Sequence key: ");
	num_print(s->sequence_key, 16);
	printf("Counter: ");
	num_print(s->counter, 16);
}


void state_testcase(void)
{
	state s1, s2;
	int failed = 0;
	int test = 0;

	if (state_init(&s1) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);
	test++; if (state_init(&s2) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (state_key_generate(&s1, 0) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);
	mpz_set_ui(s1.counter, 321323211UL);

	test++; if (state_store(&s1) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (state_load(&s2) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	/* Compare */
	test++; if (mpz_cmp(s1.sequence_key, s2.sequence_key) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (mpz_cmp(s1.counter, s2.counter) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (mpz_cmp(s1.furthest_printed, s2.furthest_printed) != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (s1.flags != s2.flags || s1.code_length != s2.code_length)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);


	print(PRINT_NOTICE, "state_testcases %d FAILED %d PASSED\n", failed, test-failed);

	state_fini(&s1);
	state_fini(&s2);
}
