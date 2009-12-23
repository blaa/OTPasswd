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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>	/* usleep, open, close, unlink */
#include <sys/types.h>
#include <sys/stat.h>	/* stat */
#include <fcntl.h>

#include "print.h"
#include "state.h"

/******************
 * Static helpers 
 ******************/
static char *_strtok(char *input, const char *delim)
{
	static char *position = NULL;

	if (input != NULL)
		position = input;

	/* FIXME: valgrind doesn't like following line: */
	char *token = strsep(&position, delim); /* Non C99 function */

	/* Cut token at any \n found */
	if (token) {
		char *pos = strchr(token, '\n');
		if (pos)
			*pos = '\0';
	}
	return token;
}

/* Check if file exists, and if
 * it does - enforce it's permissions */
static int _db_file_permissions(const state *s)
{
	struct stat st;

	if (stat(s->db_path, &st) != 0) {
		/* Does not exists */
		return STATE_DOESNT_EXISTS;
	}

	/* It should be a file or a link to file */
	if (!S_ISREG(st.st_mode)) {
		/* Error, not a file */
		print(PRINT_ERROR, "ERROR: %s is not a regular file\n", s->db_path);
		return STATE_DOESNT_EXISTS;
	}

	if (chmod(s->db_path, S_IRUSR|S_IWUSR) != 0) {
		print_perror(PRINT_ERROR, "chmod");
		print(PRINT_ERROR, "Unable to enforce %s permissions", s->db_path);
		return 3;
	}
	return 0;
}

/* State files constants */
static const int _version = 5;
static const char *_delim = ":";

static const int fields = 13;

enum {
	FIELD_USER = 0,
	FIELD_VERSION,
	FIELD_KEY,
	FIELD_COUNTER,
	FIELD_LATEST_CARD,
	FIELD_FAILURES,
	FIELD_RECENT_FAILURES,
	FIELD_CHANNEL_TIME,
	FIELD_CODE_LENGTH,
	FIELD_FLAGS,
	FIELD_SPASS,
	FIELD_LABEL,
	FIELD_CONTACT,
};

/* Find entry in database for username. Unmodified line
 * is left in buffer.
 * 
 * If out is given each line we pass without a match 
 * is written into this file.
 */
static int _db_find_user_entry(
	const char *username, FILE *f, FILE *out,
	char *buff, size_t buff_size)
{
	size_t line_length;
	size_t username_length;

	assert(username);
	assert(f);
	assert(buff);

	username_length = strlen(username);

	while (!feof(f)) {
		/* Read all file into a buffer */
		if (fgets(buff, buff_size, f) == NULL) {
			if (feof(f))
				return 1; /* Not found */
			else
				return 2; /* Error */
		}
		
		line_length = strlen(buff);
		
		if (buff[line_length-1] != '\n') {
			print(PRINT_NOTICE, 
			      "Line too long inside the state file\n");
			return 3;
		} 
		
		if (line_length < 10) {
			/* This can't hold correct state */
			print(PRINT_NOTICE, 
			      "State file is invalid. Line too short.\n");
			return 3;
		}
		
		/* Check the username without modyfing buffer. */
		if (strncmp(buff, username, username_length) == 0) {
			/* Found */
			return 0;
		}

		if (out) {
			if (fputs(buff, out) < 0) {
				print(PRINT_NOTICE, 
				      "Error while writting data to file!\n");
				return 4;
			}
		}
	}

	/* Not found */
	return 1;
}

static int _db_parse_user_entry(char *buff, char **field)
{
	int i, ret;

	/* Parse entry - split into fields, verify version */
	for (i=0; i<fields; i++) {
		field[i] = _strtok(i == 0 ? buff : NULL, _delim);
		if (field[i] == NULL) {
			print(PRINT_ERROR,
			      "State file invalid. Not enough fields.\n");
			return 1;
		}

		/* If we parsed field version, check it immediately */
		if (i == FIELD_VERSION) {
			if (sscanf(field[i], "%u", &ret) != 1) {
				print(PRINT_ERROR,
				      "Error while parsing state file "
				      "version.\n");
				return 1;
			}

			if (ret != _version) {
				print(PRINT_ERROR,
				      "State file version is incompatible. "
				      "Recreate key.\n");
				return 1;
			}
		}
	}

	if (_strtok(NULL, _delim) != NULL) {
		print(PRINT_ERROR, "State file invalid. Too much fields.\n");
		return 1;
	}

	return 0;
}




/**********************************************
 * Interface functions for managing state files
 **********************************************/
int db_file_load(state *s)
{
	/* State file should never be larger than 160 bytes */
	char buff[STATE_ENTRY_SIZE];

	/* Did we lock it here? */
	int locked = 0;

	char *field[fields]; /* Pointers to fields in file */

	int ret = 0;
	FILE *f = NULL;

	assert(s->db_path != NULL);

	if (_db_file_permissions(s) != 0) {
		print(PRINT_NOTICE,
		      "Unable to load state file. "
		      "Have you created key with -k option?\n");
		return STATE_DOESNT_EXISTS;
	}

	/* DB file should always be locked before changing 
	 * Here we just detect that it's not locked and lock it then
	 * This generally shouldn't happen */
	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while reading from it\n");
		if (state_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for reading!\n");
			return 1;
		}
		locked = 1;
	}

	f = fopen(s->db_path, "r");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for reading.",
			     s->db_path);
		goto error;
	}

	/* Read all file into a buffer */
	ret = _db_find_user_entry(s->username, f, NULL, buff, sizeof(buff));
	if (ret != 0)
		goto error;

	ret = _db_parse_user_entry(buff, field);
	if (ret != 0)
		goto error;

	/* Parse fields */
	if (mpz_set_str(s->sequence_key, field[FIELD_KEY], 62) != 0) {
		print(PRINT_ERROR, "Error while parsing sequence key.\n");
		goto error;
	}

	if (mpz_set_str(s->counter, field[FIELD_COUNTER], 62) != 0) {
		print(PRINT_ERROR, "Error while parsing counter.\n");
		goto error;
	}

	if (mpz_set_str(s->latest_card, 
			field[FIELD_LATEST_CARD], 62) != 0) {	
		print(PRINT_ERROR,
		      "Error while parsing number "
		      "of latest printed passcard\n");
		goto error;
	}

	if (sscanf(field[FIELD_FAILURES], "%u", &s->failures) != 1) {
		print(PRINT_ERROR, "Error while parsing failures count\n");
		goto error;
	}

	if (sscanf(field[FIELD_RECENT_FAILURES], "%u", &s->recent_failures) != 1) {
		print(PRINT_ERROR, "Error while parsing recent failure count\n");
		goto error;
	}

	if (mpz_set_str(s->channel_time, field[FIELD_CHANNEL_TIME], 62) != 0) {
		print(PRINT_ERROR, "Error while parsing channel use time.\n");
		goto error;
		s->spass_set = 0;
	}


	if (sscanf(field[FIELD_CODE_LENGTH], "%u", &s->code_length) != 1) {
		print(PRINT_ERROR, "Error while parsing passcode length\n");
		goto error;
	}

	if (sscanf(field[FIELD_FLAGS], "%u", &s->flags) != 1) {
		print(PRINT_ERROR, "Error while parsing flags\n");
		goto error;
	}

	if (strlen(field[FIELD_SPASS]) == 0) {
		s->spass_set = 0;
	} else {
		if (mpz_set_str(s->spass, field[FIELD_SPASS], 62) != 0) {
			print(PRINT_ERROR, "Error while parsing static password.\n");
			goto error;
		}
		s->spass_set = 1;
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

	if (mpz_sgn(s->latest_card) == -1) {
		print(PRINT_ERROR, 
		      "Latest printed card is negative. "
		      "State file is corrupted.\n");
		goto error;
	}

	if (s->code_length < 2 || s->code_length > 16) {
		print(PRINT_ERROR, "Illegal passcode length. %s is invalid\n", 
		      s->db_path);
		goto error;
	}

	if (s->flags > (FLAG_SHOW|FLAG_ALPHABET_EXTENDED|FLAG_NOT_SALTED)) {
		print(PRINT_ERROR, "Unsupported set of flags. %s is invalid\n", 
		      s->db_path);
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

int db_file_store(state *s)
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
	char *spass = NULL;
	char *channel_time = NULL;

	int tmp;

	assert(s->db_path != NULL);
	assert(s->username != NULL);

	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while writing to it\n");
		if (state_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for reading!\n");
			return 1;
		}
		locked = 1;
	}

	f = fopen(s->db_path, "w");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for writting",
			     s->db_path);

		if (locked)
			state_unlock(s);
		return STATE_PERMISSIONS;
	}

	/* Write using ascii-safe approach */
	sequence_key = mpz_get_str(NULL, STATE_BASE, s->sequence_key);
	counter = mpz_get_str(NULL, STATE_BASE, s->counter);
	latest_card = mpz_get_str(NULL, STATE_BASE, s->latest_card);

	if (s->spass_set) 
		spass = mpz_get_str(NULL, STATE_BASE, s->spass);
	else
		spass = strdup("");

	channel_time = mpz_get_str(NULL, STATE_BASE, s->channel_time);

	if (!sequence_key || !counter || !latest_card) {
		print(PRINT_ERROR, "Error while converting numbers\n");
		goto error;
	}

	const char d = _delim[0];
	tmp = fprintf(f, 
		      "%s%c%d%c"
		      "%s%c%s%c%s%c" /* Key, counter, latest_card */
		      "%u%c%u%c%s%c" /* Failures, recent fails, channel time */
		      "%u%c%u%c%s%c" /* Codelength, flags, spass */
		      "%s%c%s\n",
		      s->username, d, _version, d,
		      sequence_key, d, counter, d, latest_card, d,
		      s->failures, d, s->recent_failures, d, channel_time, d,
		      s->code_length, d, s->flags, d, spass, d,
		      s->label, d, s->contact);
	if (tmp <= 10) {
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
	if (_db_file_permissions(s) != 0) {
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
	free(channel_time);
	free(spass);
	return ret;
}


int db_file_lock(state *s)
{
	struct flock fl;
	int ret;
	int cnt;
	int fd;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	/* Create lock filename; normal file + .lck */
	s->lockname = malloc(strlen(s->db_path) + 4 + 1);
	if (!s->lockname)
		return 1;

	ret = sprintf(s->lockname, "%s.lck", s->db_path);
	assert(ret > 0);

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



int db_file_unlock(state *s)
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




int db_mysql_lock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_mysql_unlock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}


int db_mysql_load(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_mysql_store(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_ldap_lock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_ldap_unlock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_ldap_load(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_ldap_store(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}
