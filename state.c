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
#include <string.h>
#include <unistd.h>
#include <ctype.h>
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

int state_validate_str(const char *str)
{
	const int len = strlen(str);
	int i;
	/* Spaces are ok, \n and \r not.
	 * alpha, digits, +, -, @ are ok
	 * These characters must be LaTeX safe, so no {}
	 * Also they can be passed to some external script,
	 * so they must obey restrictions.
	 */
	for (i=0; i<len; i++) {
		if (isalnum(str[i]))
			continue;
		if (str[i] == ' ' || str[i] == '+' || str[i] == '@' || 
		    str[i] == '-' || str[i] == '.' || str[i] == ',' ||
		    str[i] == '*')
			continue;
		return 0; /* False */
	}
	return 1;
}

static char *_strtok(char *input, const char *delim)
{
	static char *position;
	if (input != NULL)
		position = input;
	char *token = strsep(&position, delim); /* Non C99 function */

	/* Cut token at any \n found */
	if (token) {
		char *pos = strchr(token, '\n');
		if (pos)
			*pos = '\0';
	}
	return token;
}

/* Returns name to user state file */
static char *_state_file(const char *username, const char *filename)
{
	static struct passwd *pwdata = NULL;
	char *home = NULL;
	char *name = NULL;
	int length;


	if (username == NULL) {
		if (getenv("HOME"))
			home = strdup(getenv("HOME"));

		if (!home) {
			/* No env? Get home dir for current UID */
			uid_t uid = geteuid();
			pwdata = getpwuid(uid);
			
			if (pwdata) {
				home = strdup(pwdata->pw_dir);
			} else
				return NULL; /* Unable to locate home directory */
		}
	} else {
		const struct passwd *pwent;
		while ((pwent = getpwent()) != NULL) {
			if (strcmp(pwent->pw_name, username) == 0) {
				home = strdup(pwent->pw_dir);
				endpwent();
				break;
			}
		}
		if (!home) {
			endpwent();
			return NULL;
		}
		
	}

	/* Append a filename */
	const char *configfile;
	if (filename)
		configfile = filename;
	else
		configfile = STATE_FILENAME;

	length = strlen(home);
	length += strlen(configfile);
	length += 2;

	name = malloc(length);
	if (!name) 
		goto error;

	int ret = snprintf(name, length, "%s/%s", home, configfile);

	assert( ret == length - 1 );

	if (ret != length -1) {
		goto error;
	}

	free(home);
	return name;

error:
	free(home);
	free(name);
	return NULL;
}

/* Check if file exists, and if
 * it does - enforce it's permissions */
static int _state_file_permissions(const state *s)
{
	struct stat st;
	if (stat(s->filename, &st) != 0) {
		/* Does not exists */
		return STATE_DOESNT_EXISTS;
	}

	/* It should be a file or a link to file */
	if (!S_ISREG(st.st_mode)) {
		/* Error, not a file */
		print(PRINT_ERROR, "ERROR: %s is not a regular file\n", s->filename);
		return STATE_DOESNT_EXISTS;
	}

	if (chmod(s->filename, S_IRUSR|S_IWUSR) != 0) {
		print_perror(PRINT_ERROR, "chmod");
		print(PRINT_ERROR, "Unable to enforce %s permissions", s->filename);
		return 3;
	}
	return 0;
}

int state_lock(state *s)
{
	struct flock fl;
	int ret;
	int cnt;
	int fd;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	/* Create lock filename; normal file + .lck */
	s->lockname = malloc(strlen(s->filename) + 4 + 1);
	if (!s->lockname)
		return 1;
	assert(sprintf(s->lockname, "%s.lck", s->filename) > 0);

	/* Open/create lock file */
	fd = open(s->lockname, O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR);

	if (fd == -1) {
		/* Unable to create file, therefore unable to obtain lock */
		print_perror(PRINT_NOTICE, "Unable to create lock file");
		goto error;
	}

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
		goto error;
	}

	s->lock_fd = fd;
	print(PRINT_NOTICE, "Got lock on state file\n");

	return 0; /* Got lock */
error:
	free(s->lockname);
	s->lockname = NULL;
	return STATE_LOCK_ERROR;
}

int state_unlock(state *s)
{
	struct flock fl;

	if (s->lock_fd < 0) {
		print(PRINT_NOTICE, "No lock to release!\n");
		return STATE_LOCK_ERROR; /* No lock to release */
	}

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	int ret = fcntl(s->lock_fd, F_SETLK, &fl);

	close(s->lock_fd);
	s->lock_fd = -1;

	unlink(s->lockname);
	free(s->lockname);
	s->lockname = NULL;

	if (ret != 0) {
		print(PRINT_NOTICE, "Strange error while releasing lock\n");
		/* Strange error while releasing the lock */
		return STATE_LOCK_ERROR;
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
 **********************************************/

static const int _version = 2;
static const int _fields = 8;
static const char *_delim = ":";

enum {
	FIELD_VERSION = 0,
	FIELD_KEY,
	FIELD_COUNTER,
	FIELD_LATEST_CARD,
	FIELD_CODE_LENGTH,
	FIELD_FLAGS,
	FIELD_LABEL,
	FIELD_CONTACT,
};

int state_load(state *s)
{
	/* State file should never be larger than 160 bytes */
	char buff[512];
	/* How many bytes are in buff? */
	unsigned int buff_size = 0; 

	/* Did we lock it here? */
	int locked = 0;

	char *field[_fields]; /* Fields in file */

	int i;
	int ret = 0;
	FILE *f = NULL;

	assert(s->filename != NULL);

	if (_state_file_permissions(s) != 0) {
		print(PRINT_NOTICE,
		      "Unable to load state file. "
		      "Have you created key with -k option?\n");
		return STATE_DOESNT_EXISTS;
	}

	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while reading from it\n");
		if (state_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for reading!\n");
			return 1;
		}
		locked = 1;
	}

	f = fopen(s->filename, "r");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for reading.",
			     s->filename);
		goto error;
	}

	/* Read all file into buffer */
	buff_size = fread(buff, 1, sizeof(buff), f);
	if (buff_size < 10) {
		/* This can't hold correct state */
		print(PRINT_NOTICE, 
		      "State file %s is invalid\n", s->filename);
		goto error;
	}

	/* Split into fields */
	for (i=0; i<_fields; i++) {
		field[i] = _strtok(i == 0 ? buff : NULL, _delim);
		if (field[i] == NULL) {
			print(PRINT_ERROR, "State file invalid. Not enough fields.\n");
			goto error;
		}
	}

	if (_strtok(NULL, _delim) != NULL) {
		print(PRINT_ERROR, "State file invalid. Too much fields.\n");
		goto error;
	}

	/* Parse fields */
	if (sscanf(field[FIELD_VERSION], "%u", &ret) != 1) {
		print(PRINT_ERROR, "Error while parsing state file version.\n");
		goto error;
	}

	if (ret != _version) {
		print(PRINT_ERROR, "State file version is incompatible. Recreate key.\n");
		goto error;		
	}

	if (mpz_set_str(s->sequence_key, field[FIELD_KEY], 62) != 0) {
		print(PRINT_ERROR, "Error while parsing sequence key.\n");
		goto error;
	}

	if (mpz_set_str(s->counter, field[FIELD_COUNTER], 62) != 0) {
		print(PRINT_ERROR, "Error while parsing counter.\n");
		goto error;
	}

	if (mpz_set_str(s->furthest_printed, 
			field[FIELD_LATEST_CARD], 62) != 0) {	
		print(PRINT_ERROR,
		      "Error while parsing number "
		      "of latest printed passcard\n");
		goto error;
	}

	if (sscanf(field[FIELD_CODE_LENGTH], "%u", &s->code_length) != 1) {
		print(PRINT_ERROR, "Error while parsing passcode length\n");
		goto error;
	}

	if (sscanf(field[FIELD_FLAGS], "%u", &s->flags) != 1) {
		print(PRINT_ERROR, "Error while parsing flags\n");
		goto error;
	}

	/* Copy label and contact */
	strncpy(s->label, field[FIELD_LABEL], sizeof(s->label)-1);
	strncpy(s->contact, field[FIELD_CONTACT], sizeof(s->contact)-1);

	if (s->label[sizeof(s->label)-1] != '\0') {
		print(PRINT_ERROR, "Label field too long\n");
		goto error;
	}

	if (s->contact[sizeof(s->contact)-1] != '\0') {
		print(PRINT_ERROR, "Contact field too long\n");
		goto error;
	}

	if (!state_validate_str(s->label)) {
		print(PRINT_ERROR, "Illegal characters in label\n");
		goto error;
	}

	if (!state_validate_str(s->contact)) {
		print(PRINT_ERROR, "Illegal characters in contact\n");
		goto error;
	}

	/* Everything is read. Now - check if it's correct */
	if (mpz_sgn(s->sequence_key) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative sequence key. "
		      "State file is invalid\n");
		goto error;
	}

	if (mpz_sgn(s->counter) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative counter. "
		      "State file is corrupted.\n");
		goto error;
	}

	if (mpz_sgn(s->furthest_printed) == -1) {
		print(PRINT_ERROR, 
		      "Latest printed card is negative. "
		      "State file is corrupted.\n");
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

	if (locked && state_unlock(s) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file!\n");
	}
	fclose(f);
	return 0;

error:
	memset(buff, 0, sizeof(buff));
	if (locked && state_unlock(s) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file!\n");
	}
	fclose(f);
	return 1;
}

int state_store(state *s)
{
	/* Return value, by default return error */
	int ret = 1;

	/* State file */
	FILE *f;

	/* Did we lock the file? */
	int locked = 0;

	/* Converted state parts */
	char *sequence_key = NULL;
	char *counter = NULL;
	char *latest_card = NULL;

	int tmp;

	assert(s->filename != NULL);

	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while writing to it\n");
		if (state_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for reading!\n");
			return 1;
		}
		locked = 1;
	}

	f = fopen(s->filename, "w");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for writting",
			     s->filename);

		if (locked)
			state_unlock(s);
		return STATE_PERMISSIONS;
	}

	/* Write using ascii safe approach */
	sequence_key = mpz_get_str(NULL, STATE_BASE, s->sequence_key);
	counter = mpz_get_str(NULL, STATE_BASE, s->counter);
	latest_card = mpz_get_str(NULL, STATE_BASE, s->furthest_printed);

	if (!sequence_key || !counter || !latest_card) {
		print(PRINT_ERROR, "Error while converting numbers\n");
		goto error;
	}

	const char d = _delim[0];
	tmp = fprintf(f, "%d%c%s%c%s%c%s%c%u%c%u%c%s%c%s\n",
		      _version, d,
		      sequence_key, d, counter, d, latest_card, d,
		      s->code_length, d, s->flags, d, s->label, d, s->contact);
	if (tmp <= 0) {
		print(PRINT_ERROR, "Error while writing data to state file.");
		goto error;
	}
	
	tmp = fflush(f);
	tmp += fclose(f);
	if (tmp != 0)
		print_perror(PRINT_ERROR, "Error while flushing/closing state file");
	else
		print(PRINT_NOTICE, "State file written\n");

	/* It might fail, but shouldn't
	 * Also we just want to ensure others 
	 * can't read this file */
	if (_state_file_permissions(s) != 0) {
		print(PRINT_WARN, 
		      "Unable to set state file permissions. "
		      "Key might be world-readable!\n");
	}

	ret = 0; /* More less fine */

error:
	if (locked && state_unlock(s) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file!\n");
	}

	free(sequence_key);
	free(counter);
	free(latest_card);
	return ret;
}

/******************************************
 * Functions for managing state information
 ******************************************/
int state_init(state *s, const char *username, const char *configfile)
{
	const char salt_mask[] =
		"FFFFFFFFFFFFFFFFFFFFFFFF00000000";
	const char code_mask[] =
		"000000000000000000000000FFFFFFFF";

	assert(sizeof(salt_mask) == 33);

	mpz_init(s->counter);
	mpz_init(s->sequence_key);
	mpz_init(s->furthest_printed);
	mpz_init(s->current_card);
	mpz_init(s->max_card);
	mpz_init(s->max_code);
	assert(mpz_init_set_str(s->salt_mask, salt_mask, 16) == 0);
	assert(mpz_init_set_str(s->code_mask, code_mask, 16) == 0);

	s->code_length = 4;
	s->flags = FLAG_SHOW;
	memset(s->label, 0x00, sizeof(s->label));
	memset(s->contact, 0x00, sizeof(s->contact));

	s->prompt = NULL;

	s->fd = -1;
	s->lock_fd = -1;
	s->filename = _state_file(username, configfile);
	s->lockname = NULL;
	if (username)
		s->username = strdup(username);
	else 
		s->username = NULL;
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
	num_dispose(s->code_mask);
	num_dispose(s->max_card);
	num_dispose(s->max_code);

	if (s->prompt) {
		const int length = strlen(s->prompt);
		memset(s->prompt, 0, length);
		free(s->prompt);
		s->prompt = NULL;
	}

	free(s->filename);
	free(s->username);
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
		mpz_set_ui(s->furthest_printed, 0);

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
void state_testcase(void)
{
	state s1, s2;
	int failed = 0;
	int test = 0;

	if (state_init(&s1, NULL, ".otpasswd_testcase") != 0)
		print(PRINT_WARN, "state_testcase[%2d] failed\n", test, failed++);

	test++; if (state_init(&s2, NULL, ".otpasswd_testcase") != 0)
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
