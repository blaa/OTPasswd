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
 **********************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>	/* isalnum  */
#include <pwd.h>	/* getpwuid */

/* libotp declarations. Internal since we need 
 * to know state struct. */
#define PPP_INTERNAL 1
#include "ppp.h"

/* Low-level interface */
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
	 * These characters should be Shell & LaTeX safe, so no {}
	 * and other strange characters which aren't necessary
	 * for labels and contacts.
	 */
	for (i=0; i<len; i++) {
		if (isalnum(str[i]))
			continue;
		if (str[i] == ' ' || str[i] == '+' || str[i] == '@' || 
		    str[i] == '-' || str[i] == '.' ||
		    str[i] == '_' || str[i] == '*')
			continue;
		return 0; /* False */
	}
	return 1;
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
	s->spass_time = 0;
	s->channel_time = 0;
	s->lock = -1;

	s->prompt = NULL;

	memset(s->sequence_key, 0, sizeof(s->sequence_key));
	memset(s->label, 0, sizeof(s->label));
	memset(s->contact, 0, sizeof(s->contact));

	s->code_length = cfg->passcode_def_length;
	if (cfg->show_def == 1)
		s->flags = FLAG_SHOW;

	if (cfg->salt_def == 1)
		s->flags |= FLAG_SALTED;
	
	s->alphabet = cfg->alphabet_def;

	/* This will be calculated later by ppp.c */
	s->codes_on_card = s->codes_in_row = s->current_row =
		s->current_column = 0;

	/* Save user name in state */
	s->username = strdup(username);

	/** GMP numbers initialization */
	mpz_init(s->counter);
	mpz_init(s->latest_card);
	mpz_init(s->current_card);

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
	if (s->lock > 0)
		state_unlock(s);

	mpz_clear(s->counter);
	mpz_clear(s->latest_card);
	mpz_clear(s->current_card);
	mpz_clear(s->spass);
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

	free(s->username);

	/* Clear the rest of memory, this includes sequence_key */
	memset(s, 0, sizeof(*s));
}

int state_key_generate(state *s)
{
	unsigned char entropy_pool[1024]; /* 160 + 8032 bits */

	const int real_random = 20;
	const int pseudo_random = sizeof(entropy_pool) - real_random;

	const int salt = s->flags & FLAG_SALTED;

	printf("Generating new %s key.\n\n", salt ? "salted" : "not salted");
	puts(
		"Hint: Move your mouse, cause some disc activity (`find /` is good)\n"
		"or type on keyboard to make the progress faster.\n");

/*
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
		crypto_sha256(entropy_pool, sizeof(entropy_pool), s->sequence_key);
		memset(entropy_pool, 0, sizeof(entropy_pool));

		mpz_set_d(s->counter, 0);
		mpz_set_d(s->latest_card, 0);

		s->flags &= ~(FLAG_SALTED); 
	} else {
		/* Use half of entropy to generate key */
		crypto_sha256(entropy_pool, sizeof(entropy_pool)/2, s->sequence_key);

		/* And half to initialize counter */
		unsigned char cnt_bin[32];
		crypto_sha256(entropy_pool + sizeof(entropy_pool)/2, sizeof(entropy_pool)/2, cnt_bin);
		num_from_bin(s->counter, cnt_bin, 16); /* Counter is 128 bit only */
		mpz_and(s->counter, s->counter, s->salt_mask);
		mpz_set_ui(s->latest_card, 0);

		memset(entropy_pool, 0, sizeof(entropy_pool));
		memset(cnt_bin, 0, sizeof(cnt_bin));

		s->flags |= FLAG_SALTED;
	}

	return 0;
}


int state_lock(state *s)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);

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


int state_store(state *s, int remove)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);
	switch (cfg->db) {
	case CONFIG_DB_USER:
	case CONFIG_DB_GLOBAL:
		return db_file_store(s, remove);

	case CONFIG_DB_MYSQL:
		return db_mysql_store(s, remove);

	case CONFIG_DB_LDAP:
		return db_ldap_store(s, remove);
	default:
		assert(0);
		return 1;
	}
}
