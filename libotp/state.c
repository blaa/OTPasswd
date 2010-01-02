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
#include <string.h>
#include <unistd.h>
#include <ctype.h>	/* isalnum  */
#include <pwd.h>	/* getpwuid */

#include "print.h"
#include "state.h"
#include "crypto.h"
#include "num.h"
#include "config.h"
#include "db.h"

/********************************************
 * Helper functions for managing state files
 ********************************************/
int state_validate_str(const char *str)
{
	const int len = strlen(str);
	int i;
	/* Spaces are ok, \n and \r not.
	 * alpha, digits, +, -, @, _ are ok
	 * These characters should be LaTeX safe, so no {}
	 * Also they can be passed to some external script,
	 * so they must obey restrictions.
	 */
	for (i=0; i<len; i++) {
		if (isalnum(str[i]))
			continue;
		if (str[i] == ' ' || str[i] == '+' || str[i] == '@' || 
		    str[i] == '-' || str[i] == '.' || str[i] == ',' ||
		    str[i] == '_' || str[i] == '*')
			continue;
		return 0; /* False */
	}
	return 1;
}

/* Returns a name of user state file */
static char *_state_user_db_file(const char *username)
{
	static struct passwd *pwdata = NULL;
	char *home = NULL;
	char *name = NULL;
	cfg_t *cfg = cfg_get();
	int length;

	assert(username);

	/* Get home */
	pwdata = getpwnam(username);
	if (pwdata && pwdata->pw_dir)
		home = pwdata->pw_dir;
	else
		return NULL;

	/* Append a filename */
	length = strlen(home);
	length += strlen(cfg->user_db_path);
	length += 2;

	name = malloc(length);
	if (!name) 
		goto error;

	int ret = snprintf(name, length, "%s/%s", home, cfg->user_db_path);

	assert( ret == length - 1 );

	if (ret != length - 1) {
		goto error;
	}

	return name;

error:
	free(name);
	return NULL;
}

static int _state_lck_tmp_path(const char *base, char **lck, char **tmp)
{
	int ret;

	/* Create lock filename; normal file + .lck */
	*lck = malloc(strlen(base) + 5 + 1);

	if (!*lck) {
		return PPP_NOMEM; 
	}

	*tmp = malloc(strlen(base) + 5 + 1);
	if (!*tmp) {
		free(*lck);
		*lck = NULL;
		return PPP_NOMEM; 
	}

	ret = sprintf(*lck, "%s.lck", base);
	assert(ret > 0);
	
	ret = sprintf(*tmp, "%s.tmp", base);
	assert(ret > 0);

	return 0;
}


/******************************************
 * Functions for managing state information
 ******************************************/
int state_init(state *s, const char *username)
{
	const char salt_mask[] =
		"FFFFFFFFFFFFFFFFFFFFFFFF00000000";
	const char code_mask[] =
		"000000000000000000000000FFFFFFFF";

	int ret;
	cfg_t *cfg = NULL;

	assert(sizeof(salt_mask) == 33);

	assert(s);
	assert(username);

	/* Initialize logging subsystem */
	/** This will ensure that all further state_ calls requiring
	 * a cfg might not check the return value as state_init is called
	 * first */
	cfg = cfg_get();
	if (cfg == NULL) {
		print(PRINT_ERROR, "Unable to read config file\n");
		return 2;
	}

	assert(cfg->passcode_def_length >= 2 &&
	       cfg->passcode_def_length <= 16);

	/** Non-allocating initialization of state variables */
	s->failures = 0;
	s->recent_failures = 0;
	s->spass_set = 0;
	s->lock_fd = -1;

	s->prompt = NULL;
	s->db_path = NULL;
	s->db_lck_path = NULL;

	memset(s->label, 0x00, sizeof(s->label));
	memset(s->contact, 0x00, sizeof(s->contact));

	s->code_length = cfg->passcode_def_length;
	if (cfg->show != 0)
		s->flags = FLAG_SHOW;
	if (cfg->alphabet_def == 2)
		s->flags |= FLAG_ALPHABET_EXTENDED;

	/* This will be calculated later by ppp.c */
	s->codes_on_card = s->codes_in_row = s->current_row =
		s->current_column = 0;

	/** Determine state file position */
	switch (cfg->db) {
	case CONFIG_DB_USER:
		s->db_path = _state_user_db_file(username);

		if (s->db_path == NULL) {
			print(PRINT_ERROR, "Unable to determine home directory of user\n");
			return 4;
		}

		/* Create lock filename; normal file + .lck */
		if (_state_lck_tmp_path(s->db_path,
					&s->db_lck_path,
					&s->db_tmp_path) != 0) {
			free(s->db_path), s->db_path = NULL;
			return PPP_NOMEM;
		}
		break;

	case CONFIG_DB_GLOBAL:
		s->db_path = strdup(cfg->global_db_path);
		if (!s->db_path) {
			return PPP_NOMEM;
		}

		if (_state_lck_tmp_path(s->db_path, 
					&s->db_lck_path, 
					&s->db_tmp_path) != 0) {
			free(s->db_path), s->db_path = NULL;
			return PPP_NOMEM;
		}
		break;

	case CONFIG_DB_MYSQL:
	case CONFIG_DB_LDAP:
		print(PRINT_ERROR, "Database type not yet implemented.\n");
		return 1; 
	}

	/* Save user name in state */
	s->username = strdup(username);

	/** GMP numbers initialization */
	mpz_init(s->counter);
	mpz_init(s->sequence_key);
	mpz_init(s->latest_card);
	mpz_init(s->current_card);
	mpz_init(s->channel_time);

	mpz_init(s->max_card);
	mpz_init(s->max_code);

	mpz_init(s->spass);

	ret = mpz_init_set_str(s->salt_mask, salt_mask, 16);
	assert(ret == 0);
	ret = mpz_init_set_str(s->code_mask, code_mask, 16);
	assert(ret == 0);


	return 0;
}

void state_fini(state *s)
{
	if (s->lock_fd > 0)
		state_unlock(s);

	mpz_clear(s->counter);
	mpz_clear(s->sequence_key);
	mpz_clear(s->latest_card);
	mpz_clear(s->current_card);
	mpz_clear(s->spass);
	mpz_clear(s->channel_time);
	mpz_clear(s->salt_mask);
	mpz_clear(s->code_mask);
	mpz_clear(s->max_card);
	mpz_clear(s->max_code);

	if (s->prompt) {
		const int length = strlen(s->prompt);
		memset(s->prompt, 0, length);
		free(s->prompt);
		s->prompt = NULL;
	}

	free(s->db_path);
	free(s->db_lck_path);
	free(s->db_tmp_path);
	free(s->username);

	/* Clear the rest of memory */
	memset(s, 0, sizeof(*s));
}

int state_key_generate(state *s, const int salt)
{
	unsigned char entropy_pool[1024]; /* 160 + 8032 bits */
	unsigned char key_bin[32];

	const int real_random = 20;
	const int pseudo_random = sizeof(entropy_pool) - real_random;

	printf("Generating new %s key.\n\n", salt ? "salted" : "not salted");
	puts(
		"Hint: Move your mouse, cause some disc activity (`find /` is good)\n"
		"or type on keyboard to make the progress faster.\n");

/*
  Openssl rng:
	if (crypto_rng(entropy_pool, pseudo_random, 1) != 0) {
		print(PRINT_ERROR, "Unable to get enough pseudo random bytes\n");
		return 1;
	}
*/

	/* Gather entropy from random, then fallback to urandom... */
	printf("Gathering entropy...");
	if (crypto_file_rng("/dev/random", NULL,
		    entropy_pool, real_random) != 0)
	{
		print_perror(PRINT_ERROR, "Unable to open /dev/random");
		return 1;
	}

	if (crypto_file_rng("/dev/urandom", NULL,
		    entropy_pool+real_random, pseudo_random) != 0)
	{
		print_perror(PRINT_ERROR, "Unable to open /dev/random");
		return 1;
	}
	printf("DONE\n");

	if (salt == 0) {
		crypto_sha256(entropy_pool, sizeof(entropy_pool), key_bin);
		memset(entropy_pool, 0, sizeof(entropy_pool));

		num_from_bin(s->sequence_key, key_bin, sizeof(key_bin));
		memset(key_bin, 0, sizeof(key_bin));
		mpz_set_d(s->counter, 0);
		mpz_set_d(s->latest_card, 0);
	} else {
		/* Use half of entropy to generate key */
		crypto_sha256(entropy_pool, sizeof(entropy_pool)/2, key_bin);
		num_from_bin(s->sequence_key, key_bin, sizeof(key_bin));

		/* And half to initialize counter */
		crypto_sha256(entropy_pool+sizeof(entropy_pool)/2, sizeof(entropy_pool)/2, key_bin);
		num_from_bin(s->counter, key_bin, 16); /* Counter is 128 bit only */
		mpz_and(s->counter, s->counter, s->salt_mask);
		mpz_set_ui(s->latest_card, 0);

		memset(entropy_pool, 0, sizeof(entropy_pool));
		memset(key_bin, 0, sizeof(key_bin));
	}

	if (salt)
		s->flags &= ~(FLAG_NOT_SALTED); 
	return 0;
}


int state_lock(state *s)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);

	assert(s->db_path != NULL);

	switch (cfg->db) {
	case CONFIG_DB_USER:
	case CONFIG_DB_GLOBAL:
		return db_file_lock(s);

	case CONFIG_DB_MYSQL:
		return db_mysql_lock(s);

	case CONFIG_DB_LDAP:
		return db_ldap_lock(s);
	default:
		assert(0);
		return 1;
	}
}

int state_unlock(state *s)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);
	switch (cfg->db) {
	case CONFIG_DB_USER:
	case CONFIG_DB_GLOBAL:
		return db_file_unlock(s);

	case CONFIG_DB_MYSQL:
		return db_mysql_unlock(s);

	case CONFIG_DB_LDAP:
		return db_ldap_unlock(s);
	default:
		assert(0);
		return 1;
	}
}

int state_load(state *s)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);

	switch (cfg->db) {
	case CONFIG_DB_USER:
	case CONFIG_DB_GLOBAL:
		return db_file_load(s);

	case CONFIG_DB_MYSQL:
		return db_mysql_load(s);

	case CONFIG_DB_LDAP:
		return db_ldap_load(s);
	default:
		assert(0);
		return 1;
	}
}


int state_store(state *s)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);
	switch (cfg->db) {
	case CONFIG_DB_USER:
	case CONFIG_DB_GLOBAL:
		return db_file_store(s);

	case CONFIG_DB_MYSQL:
		return db_mysql_store(s);

	case CONFIG_DB_LDAP:
		return db_ldap_store(s);
	default:
		assert(0);
		return 1;
	}
}
