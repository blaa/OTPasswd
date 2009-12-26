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
#include "db.h"

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
		return STATE_NON_EXISTENT;
	}

	/* It should be a file or a link to file */
	if (!S_ISREG(st.st_mode)) {
		/* Error, not a file */
		print(PRINT_ERROR, "ERROR: %s is not a regular file\n", s->db_path);
		return STATE_IO_ERROR;
	}

	if (chmod(s->db_path, S_IRUSR|S_IWUSR) != 0) {
		print_perror(PRINT_ERROR, "chmod");
		print(PRINT_ERROR, "Unable to enforce %s permissions", s->db_path);
		return STATE_IO_ERROR;
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

	if (username)
		username_length = strlen(username);
	else 
		username_length = 0;

	while (!feof(f)) {
		/* Read all file into a buffer */
		if (fgets(buff, buff_size, f) == NULL) {
			if (feof(f))
				/* Not found */
				return STATE_NO_USER_ENTRY;
			else
				/* Error */
				return STATE_IO_ERROR; 
		}
		
		line_length = strlen(buff);
		
		if (buff[line_length-1] != '\n') {
			print(PRINT_NOTICE, 
			      "Line too long inside the state file\n");
			return STATE_PARSE_ERROR;
		} 
		
		if (line_length < 10) {
			/* This can't hold correct state */
			print(PRINT_NOTICE, 
			      "State file is invalid. Line too short.\n");
			return STATE_PARSE_ERROR;
		}

		/* Temporary change first separator into \0 */
		char *first_sep = strchr(buff, _delim[0]);
		if (first_sep) {
			*first_sep = '\0';
			
			/* Check the username */
			if (username && (strcmp(buff, username) == 0)) {
				/* Found */
				*first_sep = _delim[0];
				return 0;
			}

			*first_sep = _delim[0];
		}

		if (out) {
			if (fputs(buff, out) < 0) {
				print(PRINT_NOTICE, 
				      "Error while writting data to file!\n");
				return STATE_IO_ERROR;
			}
		}
	}

	/* Not found */
	return STATE_NO_USER_ENTRY;
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
			return STATE_PARSE_ERROR;
		}

		if (strlen(field[i]) > STATE_MAX_FIELD_SIZE) {
			print(PRINT_ERROR,
			      "State file corrupted. Entry too long\n");
			return STATE_PARSE_ERROR;
		}

		/* If we parsed field version, check it immediately */
		if (i == FIELD_VERSION) {
			if (sscanf(field[i], "%u", &ret) != 1) {
				print(PRINT_ERROR,
				      "Error while parsing state file "
				      "version.\n");
				return STATE_PARSE_ERROR;
			}

			if (ret != _version) {
				print(PRINT_ERROR,
				      "State file version is incompatible. "
				      "Recreate key.\n");
				return STATE_PARSE_ERROR;
			}
		}
	}

	if (_strtok(NULL, _delim) != NULL) {
		print(PRINT_ERROR, "State file invalid. Too much fields.\n");
		return STATE_PARSE_ERROR;
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
	int locked;

	/* Pointers to fields in file */
	char *field[fields]; 

	/* Temporary variable for returned values */
	int ret = 0;

	/* State file */
	FILE *f = NULL;

	/* Value returned. */
	int retval;

	ret = _db_file_permissions(s);
	if (ret != 0) {
		print(PRINT_NOTICE, "Unable to load state file.\n");
		return ret;
	}

	/* DB file should always be locked before changing.
	 * Locking can only be omitted when we want to discard 
	 * any changes or that we don't bother if somebody changes 
	 * them at the same time.
	 * Here we just detect that it's not locked and lock it then 
	 */
	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while reading from it\n");
		if (db_file_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for reading!\n");
			return STATE_LOCK_ERROR;
		}

		/* Locked locally, unlock locally later */
		locked = 1;
	} else {
		locked = 0;
	}

	f = fopen(s->db_path, "r");
	if (!f) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for reading.",
			     s->db_path);
		retval = STATE_IO_ERROR;
		goto cleanup;
	}

	/* Read all file into a buffer */
	ret = _db_find_user_entry(s->username, f, NULL, buff, sizeof(buff));
	if (ret != 0) {
		/* No entry, or file invalid */
		retval = ret;
		goto cleanup;
	}

	ret = _db_parse_user_entry(buff, field);
	if (ret != 0) {
		/* Parse error */
		retval = ret;
		goto cleanup;
	}

	/* Parse fields, if anybody bad happens return parse error */
	retval = STATE_PARSE_ERROR;

	if (mpz_set_str(s->sequence_key, field[FIELD_KEY], STATE_BASE) != 0) {
		print(PRINT_ERROR, "Error while parsing sequence key.\n");
		goto cleanup;
	}

	if (mpz_set_str(s->counter, field[FIELD_COUNTER], STATE_BASE) != 0) {
		print(PRINT_ERROR, "Error while parsing counter.\n");
		goto cleanup;
	}

	if (mpz_set_str(s->latest_card, 
			field[FIELD_LATEST_CARD], STATE_BASE) != 0) {	
		print(PRINT_ERROR,
		      "Error while parsing number "
		      "of latest printed passcard\n");
		goto cleanup;
	}

	if (sscanf(field[FIELD_FAILURES], "%u", &s->failures) != 1) {
		print(PRINT_ERROR, "Error while parsing failures count\n");
		goto cleanup;
	}

	if (sscanf(field[FIELD_RECENT_FAILURES], "%u", &s->recent_failures) != 1) {
		print(PRINT_ERROR, "Error while parsing recent failure count\n");
		goto cleanup;
	}

	if (mpz_set_str(s->channel_time, field[FIELD_CHANNEL_TIME], STATE_BASE) != 0) {
		print(PRINT_ERROR, "Error while parsing channel use time.\n");
		goto cleanup;
	}

	if (sscanf(field[FIELD_CODE_LENGTH], "%u", &s->code_length) != 1) {
		print(PRINT_ERROR, "Error while parsing passcode length\n");
		goto cleanup;
	}

	if (sscanf(field[FIELD_FLAGS], "%u", &s->flags) != 1) {
		print(PRINT_ERROR, "Error while parsing flags\n");
		goto cleanup;
	}

	if (strlen(field[FIELD_SPASS]) == 0) {
		s->spass_set = 0;
	} else {
		if (mpz_set_str(s->spass, field[FIELD_SPASS], STATE_BASE) != 0) {
			print(PRINT_ERROR, "Error while parsing static password.\n");
			goto cleanup;
		}
		s->spass_set = 1;
	}

	/* Copy label and contact */
	strncpy(s->label, field[FIELD_LABEL], sizeof(s->label)-1);
	strncpy(s->contact, field[FIELD_CONTACT], sizeof(s->contact)-1);

	if (s->label[sizeof(s->label)-1] != '\0') {
		print(PRINT_ERROR, "Label field too long\n");
		goto cleanup;
	}

	if (s->contact[sizeof(s->contact)-1] != '\0') {
		print(PRINT_ERROR, "Contact field too long\n");
		goto cleanup;
	}

	if (!state_validate_str(s->label)) {
		print(PRINT_ERROR, "Illegal characters in label\n");
		goto cleanup;
	}

	if (!state_validate_str(s->contact)) {
		print(PRINT_ERROR, "Illegal characters in contact\n");
		goto cleanup;
	}

	/* Everything is read. Now - check if it's correct */
	if (mpz_sgn(s->sequence_key) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative sequence key. "
		      "State file is invalid\n");
		goto cleanup;
	}

	if (mpz_sgn(s->counter) == -1) {
		print(PRINT_ERROR, 
		      "Read a negative counter. "
		      "State file is corrupted.\n");
		goto cleanup;
	}

	if (mpz_sgn(s->latest_card) == -1) {
		print(PRINT_ERROR, 
		      "Latest printed card is negative. "
		      "State file is corrupted.\n");
		goto cleanup;
	}

	if (s->code_length < 2 || s->code_length > 16) {
		print(PRINT_ERROR, "Illegal passcode length. %s is invalid\n", 
		      s->db_path);
		goto cleanup;
	}

	if (s->flags > (FLAG_SHOW|FLAG_ALPHABET_EXTENDED|FLAG_NOT_SALTED)) {
		print(PRINT_ERROR, "Unsupported set of flags. %s is invalid\n", 
		      s->db_path);
		goto cleanup;

	}

	retval = 0;
cleanup:
	/* Clear memory */
	memset(buff, 0, sizeof(buff));

	/* Unlocked if locally locked */
	if ((locked == 1) && (db_file_unlock(s) != 0)) {
		print(PRINT_ERROR, "Error while unlocking state file!\n");
		if (retval == 0)
			retval = STATE_LOCK_ERROR;
	}

	fclose(f);
	return retval;
}

static int _db_generate_user_entry(const state *s, char *buffer, int buff_length)
{
	int tmp;

	/* Converted state parts */
	char *sequence_key = NULL;
	char *counter = NULL;
	char *latest_card = NULL;
	char *spass = NULL;
	char *channel_time = NULL;


	/* Write using ascii-safe approach */
	sequence_key = mpz_get_str(NULL, STATE_BASE, s->sequence_key);
	counter = mpz_get_str(NULL, STATE_BASE, s->counter);
	latest_card = mpz_get_str(NULL, STATE_BASE, s->latest_card);

	if (s->spass_set) 
		spass = mpz_get_str(NULL, STATE_BASE, s->spass);
	else
		spass = strdup("");

	channel_time = mpz_get_str(NULL, STATE_BASE, s->channel_time);

	if (!sequence_key || !counter || !latest_card || !channel_time || !spass) {
		print(PRINT_ERROR, "Error while converting numbers\n");
		goto error;
	}

	const char d = _delim[0];
	tmp = snprintf(buffer, buff_length, 
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
	if (tmp < 10 || tmp == buff_length) {
		print(PRINT_ERROR, "Error while writing data to state file.");
		goto error;
	}

	return 0;
error:
	free(sequence_key);
	free(counter);
	free(latest_card);
	free(channel_time);
	free(spass);
	return 1;
}

int db_file_store(state *s)
{
	/* Return value, by default return error */
	int ret;

	/* State file */
	FILE *in = NULL, *out = NULL;

	/* Did we lock the file? */
	int locked = 0;

	char user_entry_buff[STATE_ENTRY_SIZE];

	int tmp;

	assert(s->db_path != NULL);
	assert(s->username != NULL);

	if (s->lock_fd <= 0) {
		print(PRINT_NOTICE, 
		      "State file not locked while writing to it\n");
		if (db_file_lock(s) != 0) {
			print(PRINT_ERROR, "Unable to lock file for writing!\n");
			return STATE_LOCK_ERROR;
		}
		locked = 1;
	}

	in = fopen(s->db_path, "r");
	if (!in) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for reading",
			     s->db_path);

		ret = STATE_IO_ERROR;
		goto cleanup;
	}

	out = fopen(s->db_tmp_path, "w");
	if (!out) {
		print_perror(PRINT_ERROR,
			     "Unable to open %s for writing",
			     s->db_tmp_path);

		ret = STATE_IO_ERROR;
		goto cleanup;

	}

	/* 1) Copy entries before our username */
	ret = _db_find_user_entry(s->username, in, out,	user_entry_buff, sizeof(user_entry_buff));
	if (ret != 1 && ret != 0) {
		/* Error happened. */
		goto cleanup;
	}

	/* 2) Generate our new entry and store it into file */
	ret = _db_generate_user_entry(s, user_entry_buff, sizeof(user_entry_buff));
	if (ret != 0) {
		print(PRINT_ERROR, "Strange error while generating new user entry line\n");
		goto cleanup;
	}

	if (fputs(user_entry_buff, out) < 0) {
		print(PRINT_ERROR, "Error while writing user entry to database\n");
		ret = STATE_IO_ERROR;
		goto cleanup;
	}

	/* 3) Copy rest of the file */
	ret = _db_find_user_entry(s->username, in, out,	user_entry_buff, sizeof(user_entry_buff));
	if (ret == 0) {
		print(PRINT_ERROR, "Duplicate entry for user %s in state file\n", s->username);
		goto cleanup;
	}

	if (ret != STATE_NO_USER_ENTRY) {
		/* Double user entry. */
		print(PRINT_NOTICE, "Double user entry in state file.\n");
		ret = STATE_PARSE_ERROR;
		goto cleanup;
	}

	/* 4) Flush, save... then rename in cleanup part */
	tmp = fflush(out);
	tmp += fclose(out);
	out = NULL;
	if (tmp != 0) {
		print_perror(PRINT_ERROR, "Error while flushing/closing state file");
		ret = STATE_IO_ERROR;
		goto cleanup;
	}

	ret = 0; /* We are fine! */
cleanup:
	if (in)
		fclose(in);
	if (out)
		fclose(out);

	if (ret == 0) {
		/* If everything went fine, rename tmp to normal file */
		if (rename(s->db_tmp_path, s->db_path) != 0) {
			print_perror(PRINT_WARN, 
				     "Unable to rename temporary state "
				     "file and save state\n");
			ret = STATE_IO_ERROR;
		} else {
			/* It might fail, but shouldn't
			 * Also we just want to ensure others 
			 * can't read this file */
			if (_db_file_permissions(s) != 0) {
				print(PRINT_WARN, 
				      "Unable to set state file permissions. "
				      "Key might be world-readable!\n");
			}
			print(PRINT_NOTICE, "State file written correctly\n");
		}
	} else if (unlink(s->db_tmp_path) != 0) {
		print_perror(PRINT_WARN, "Unable to unlink temporary state file %s\n", 
			     s->db_tmp_path);
	}

	if (locked && db_file_unlock(s) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file!\n");
	}

	return ret;
}

int db_file_lock(state *s)
{
	struct flock fl;
	int ret;
	int cnt;
	int fd;

	assert(s->db_lck_path);
	assert(s->db_path);
	assert(s->lock_fd == -1);

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	/* Open/create lock file */
	fd = open(s->db_lck_path, O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR);

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

	unlink(s->db_lck_path);

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
