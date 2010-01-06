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

#define PPP_INTERNAL 1

#include "num.h"
#include "crypto.h"

#include "ppp.h"
#include "print.h"
#include "config.h"


/* Number of combinations calculated for 4 passcodes */
/* 64 characters -> 16 777 216 */
static const char alphabet_simple[] =
	"!#%+23456789:=?@ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* 88 characters -> 59 969 536 */
static const char alphabet_extended[] =
	"!\"#$%&'()*+,-./23456789:;<=>?@ABCDEFGHJKLMNO"
	"PRSTUVWXYZ[\\]^_abcdefghijkmnopqrstuvwxyz{|}~";

/* 54 chars -> 8 503 056 */
static const char alphabet_simple_no_vowels[] =
	"!#%+23456789:=?@BCDFGHJKLMNPRSTVWXZbcdfghjkmnpqrstvwxz";

/* 78 chars -> 37 015 056 */
static const char alphabet_extended_no_vowels[] =
	"!\"#$%&'()*+,-./23456789:;<=>?@BCDFGHJKLMNPRSTVWXZ[\\]^_bcdfghjkmnpqrstvwxz{|}~";

/* 56 chars -> 9 834 496 */
static const char alphabet_alpha[] =
	"23456789ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const char *alphabets[] = {
	NULL, /* Custom */
	alphabet_simple,
	alphabet_extended,
	alphabet_simple_no_vowels,
	alphabet_extended_no_vowels,
	alphabet_alpha,
};

static const int alphabet_cnt = sizeof(alphabets) / sizeof(*alphabets);

/***********************
 * Verification group 
 ***********************/
int ppp_verify_code_length(int length)
{
	cfg_t *cfg = cfg_get();
	assert(cfg);

	if (length < 2 || length > 16)
		return PPP_ERROR_RANGE;

	if (length < cfg->passcode_min_length ||
	    length > cfg->passcode_max_length) {
		return PPP_ERROR_POLICY;
	}

	return 0;
}

int ppp_verify_alphabet(int id)
{
	const cfg_t *cfg = cfg_get();
	assert(cfg);

	const int min = cfg->alphabet_min_length;
	const int max = cfg->alphabet_max_length;

	/* Check if it's legal */
	if (id < 0 || id > alphabet_cnt)
		return PPP_ERROR_RANGE;

	/* Fail also if changing is denied and this
	 * alphabet is not default one */
	if  (cfg->alphabet_allow_change == 0 &&
	     cfg->alphabet_def != id)
		return PPP_ERROR_POLICY;


	const char *alphabet;
	if (id == 0) {
		/* 0 - custom */
		alphabet = cfg->alphabet_custom;
	} else {
		alphabet = alphabets[id];
	}

	const int len = strlen(alphabet);

	if (len<min || len>max)
		return PPP_ERROR_POLICY;

	/* OK */
	return 0;
}

int ppp_verify_range(const state *s)
{
	/* First verify two conditions that should never happen
	 * then check something theoretically possible */

	/* ppp_calculate must've been called before */
	assert(s->codes_on_card > 0);

	/* Verify key size */
	const char max_key_hex[] =
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	mpz_t max_key;
	mpz_init_set_str(max_key, max_key_hex, 16);

	if (mpz_cmp(s->sequence_key, max_key) > 0) {
		print(PRINT_ERROR, "State file corrupted. Key number too big\n");
		mpz_clear(max_key);
		return STATE_PARSE_ERROR;
	}
	mpz_clear(max_key);

	/* Verify counter size */
	const char max_counter_hex[] =
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	mpz_t max_counter;
	mpz_init_set_str(max_counter, max_counter_hex, 16);

	if (mpz_cmp(s->counter, max_counter) > 0) {
		print(PRINT_ERROR, "State file corrupted. Counter number too big\n");
		mpz_clear(max_counter);
		return STATE_PARSE_ERROR;
	}
	mpz_clear(max_counter);

	/* Check if we have runned out of available passcodes */

	/* Retrieve current counter without salt */
	mpz_t just_counter;
	mpz_init(just_counter);
	if (s->flags & FLAG_SALTED) {
		mpz_and(just_counter, s->counter, s->code_mask);
	} else {
		mpz_set(just_counter, s->counter);
	}

	/* Equal is too big because max_code is calculated starting from 1
	 * whereas counter starts from 0 */
	if (mpz_cmp(just_counter, s->max_code) >= 0) {
		/* Whoops */
		mpz_clear(just_counter);
		return STATE_NUMSPACE;
	}

	mpz_clear(just_counter);
	return 0;
}

int ppp_verify_flags(int flags)
{
	const cfg_t *cfg = cfg_get();
	assert(cfg);

	/* Show */
	if (flags & FLAG_SHOW && cfg->show_allow == 0) {
		return PPP_ERROR_POLICY;
	}

	if (!(flags & FLAG_SHOW) && cfg->show_allow == 2) {
		return PPP_ERROR_POLICY;
	}

	/* Salted */
	if (flags & FLAG_SALTED && cfg->salt_allow == 0) {
		return PPP_ERROR_POLICY;
	}

	if (!(flags & FLAG_SALTED) && cfg->salt_allow == 2) {
		return PPP_ERROR_POLICY;
	}

	return 0;
}

int ppp_verify_state(const state *s)
{
	if (ppp_verify_flags(s->flags) != 0)
		return PPP_ERROR_POLICY;

	if (ppp_verify_alphabet(s->alphabet) != 0)
		return PPP_ERROR_POLICY;

	if (ppp_verify_code_length(s->code_length) != 0)
		return PPP_ERROR_POLICY;

	if (ppp_verify_range(s) != 0)
		return PPP_ERROR_POLICY;

	return 0;
}

void ppp_alphabet_print(void)
{
	const cfg_t *cfg = cfg_get();
	assert(cfg);

	const int min = cfg->alphabet_min_length;
	const int max = cfg->alphabet_max_length;

	int i;

	for (i=0; i<alphabet_cnt; i++) {
		int len;
		const char *alphabet;
		if (i == 0) {
			/* 0 - custom */
			alphabet = cfg->alphabet_custom;
		} else {
			alphabet = alphabets[i];
		}

		len = strlen(alphabet);
		printf("Alphabet ID = %d (%s by policy):\n", i,
		       (len>=min && len<=max) ? "accepted" : "denied");
		puts(alphabet);
	}
}

void ppp_add_salt(const state *s, mpz_t passcode)
{
	if (s->flags & FLAG_SALTED) {
		mpz_t salt;
		mpz_init_set(salt, s->counter);
		mpz_and(salt, salt, s->salt_mask);
		mpz_add(passcode, passcode, salt);
		mpz_clear(salt);
	}
}

int ppp_get_passcode_number(const state *s, const mpz_t passcard, mpz_t passcode, char column, char row)
{
	if (column < 'A' || column >= 'A' + s->codes_in_row) {
		print(PRINT_NOTICE, "Column out of possible range!\n");
		return 1;
	}

	if (row < 1 || row > 10) {
		print(PRINT_NOTICE, "Row out of range!\n");
		return 1;
	}

	/* Start with calculating first passcode on card */
	/* passcode = (passcard-1)*codes_on_card + salt */
	mpz_sub_ui(passcode, passcard, 1);
	mpz_mul_ui(passcode, passcode, s->codes_on_card);

	/* Then add location on card */
	mpz_add_ui(passcode, passcode, (row - 1) * s->codes_in_row);
	mpz_add_ui(passcode, passcode, column - 'A');

	/* Add salt if required */
	ppp_add_salt(s, passcode);
	return 0;
}

int ppp_get_passcode(const state *s, const mpz_t counter, char *passcode)
{
	unsigned char key_bin[32];
	unsigned char cnt_bin[16];
	unsigned char cipher_bin[16];
	mpz_t cipher;
	mpz_t quotient;
	int i;

	int ret;

	const cfg_t *cfg = cfg_get();
	assert(cfg);

	/* Assure range during development */
	assert(mpz_tstbit(counter, 128) == 0);

	/* Check for illegal data */
	assert(s->code_length >= 2 && s->code_length <= 16);
	assert(mpz_sgn(s->counter) >= 0);

	if (!passcode)
		return 2;

	mpz_init(quotient);
	mpz_init(cipher);

	/* Convert numbers to binary */
	num_to_bin(s->sequence_key, key_bin, 32);
	num_to_bin(counter, cnt_bin, 16);

	/* Encrypt counter with key */
	ret = crypto_aes_encrypt(key_bin, cnt_bin, cipher_bin);
	if (ret != 0) {
		goto clear;
	}

	/* Convert result back to number */
	num_from_bin(cipher, cipher_bin, 16);

	if (ppp_verify_alphabet(s->alphabet) != 0) {
		print(PRINT_ERROR, "State contains invalid alphabet\n");
		goto clear;
	}

	const char *alphabet;
	if (s->alphabet == 0) {
		alphabet = cfg->alphabet_custom;
	} else {
		alphabet = alphabets[s->alphabet];
	}
	const int alphabet_len = strlen(alphabet);

	for (i=0; i<s->code_length; i++) {
		unsigned long int r = mpz_fdiv_q_ui(quotient, cipher, alphabet_len);
		mpz_set(cipher, quotient);

		passcode[i] = alphabet[r];
	}

	passcode[i] = '\0';

clear:
	memset(key_bin, 0, sizeof(key_bin));
	memset(cnt_bin, 0, sizeof(cnt_bin));
	memset(cipher_bin, 0, sizeof(cipher_bin));

	mpz_clear(quotient);
	mpz_clear(cipher);
	return ret;
}

int ppp_get_current(const state *s, char *passcode)
{
	if (passcode == NULL)
		return 1;

	if (ppp_get_passcode(s, s->counter, passcode) != 0)
		return 2;

	return 0;
}

int ppp_authenticate(const state *s, const char *passcode)
{
	int retval;
	char current_passcode[17] = {0};

	if (passcode == NULL)
		return 1;

	/* Disabled user can't authenticate */
	if (ppp_flag_check(s, FLAG_DISABLED)) {
		return PPP_ERROR_DISABLED;
	}

	/* User with state inconsistent with policy can't authenticate */
	retval = ppp_verify_state(s);
	if (retval != 0) {
		return retval;
	}

	/* Read current passcode */
	if (ppp_get_passcode(s, s->counter, current_passcode) != 0)
		return 2;

	/* Check if it matches */
	if (strcmp(passcode, current_passcode) != 0)
		return 3;

	/* Success */
	return 0;
}

/**********************
 * Passcard management
 **********************/

/* Number of passcodes in row depending on passcode length */
static int _len_to_card_size[] = {
	-1, /* use up index 0, just to make it easier */
	-1, /* minimal length is 2 */
	11, /* which fits 11 passcodes in row */
	8,
	7,
	5, /* 5 - 6 */
	5,
	4, /* 7 */
	3, /* 8 - 10 */
	3,
	3,
	2, /* 11 - 16 */
	2,
	2,
	2,
	2,
	2,

};

void ppp_calculate(state *s)
{
	const char columns[] = "ABCDEFGHIJKL";

	/* Do some checks */
	assert(s->code_length >= 2 && s->code_length <= 16);
	assert(mpz_sgn(s->counter) >= 0);

	s->codes_in_row = _len_to_card_size[s->code_length];
	s->codes_on_card = s->codes_in_row * ROWS_PER_CARD;

	/* Calculate current card */
	mpz_t unsalted_counter;
	mpz_init_set(unsalted_counter, s->counter);
	if (s->flags & FLAG_SALTED) {
		mpz_and(unsalted_counter, unsalted_counter, s->code_mask);
	}

	unsigned long int r = mpz_fdiv_q_ui(s->current_card, unsalted_counter, s->codes_on_card);
	mpz_add_ui(s->current_card, s->current_card, 1);

	mpz_clear(unsalted_counter);

	/* Calculate column/row using rest from division */
	int current_column = r % s->codes_in_row;
	r -= current_column;
	s->current_row = 1 + r / s->codes_in_row;
	s->current_column = columns[current_column];

	/* Calculate max passcard */
	if (s->flags & FLAG_SALTED) {
		mpz_set(s->max_card, s->code_mask);
	} else {
		const char max_hex[] =
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
		assert(sizeof(max_hex)  == 33);
		mpz_set_str(s->max_card, max_hex, 16);
	}

	mpz_div_ui(s->max_card, s->max_card, s->codes_on_card);

	/* s->max_card is now technically correct, but
	 * we must be sure, that the last passcode is not
	 * the last from number namespace, like 2^128-1 when
	 * using not-salted key.
	 * This should not happen... but, just for the sake
	 * of simplicity.
	 */
	mpz_sub_ui(s->max_card, s->max_card, 1);

	/* Calculate max passcode.
	 * This is the last passcode on last card.
	 * (Which does not equal last counter value)
	 * Cards and codes are calculated from 1 here.
	 */
	mpz_set(s->max_code, s->max_card);
	mpz_mul_ui(s->max_code, s->max_code, s->codes_on_card);
}

/******************
 * Warning support
 ******************/
int ppp_get_warning_conditions(const state *s)
{
	int warnings = 0;

	assert(s->codes_on_card > 0);

	int tmp = mpz_cmp(s->current_card, s->latest_card);
	if (tmp == 0)
		warnings |= PPP_WARN_LAST_CARD;
	else if (tmp > 0)
		warnings |= PPP_WARN_NOTHING_LEFT;

	if (s->recent_failures > 0)
		warnings |= PPP_WARN_RECENT_FAILURES;

	return warnings;
}

const char *ppp_get_warning_message(const state *s, int *warning)
{
	const char *nothing_left = "You have no printed passcodes left!";
	const char *last_card = "You are on your last printed passcard!";
	const char *failure_template =
		"There was 1 recent auth failure!";
	const char failures_template[] =
		"There were %d recent auth failures! Are your static passwords compromised?";

	static char failures_buff[sizeof(failures_template) + 10];

	assert(sizeof(failures_buff) > 50);

	if (*warning == PPP_WARN_OK)
		return NULL;

	if (*warning & PPP_WARN_RECENT_FAILURES) {
		int ret;
		*warning &= ~PPP_WARN_RECENT_FAILURES;
		if (s->recent_failures == 1) {
			return failure_template;
		}

		/* Just to be sure */
		assert(s->recent_failures < 999999999);

		ret = snprintf(failures_buff, sizeof(failures_buff),
			       failures_template, s->recent_failures);
		if (ret < 10)
			return NULL;

		failures_buff[sizeof(failures_buff) - 1] = '\0';
		return failures_buff;
	}

	switch (*warning) {
	case PPP_WARN_LAST_CARD:
		*warning &= ~PPP_WARN_LAST_CARD;
		return last_card;

	case PPP_WARN_NOTHING_LEFT:
		*warning &= ~PPP_WARN_NOTHING_LEFT;
		return nothing_left;

	default:
		assert(0);
		return 0;
	}
}

const char *ppp_get_error_desc(int error)
{
	switch (error) {
	case 0:
		return "No error";
	case STATE_NOMEM:
		return "Out of memory while reading state.";

	case STATE_LOCK_ERROR:
		return "Unable to lock state file!";

	case STATE_NON_EXISTENT:
		return "Have you created key with --key option?";

	case STATE_IO_ERROR:
		return "I/O error (permissions, file type, connection, ...) while reading state.";

	case STATE_NUMSPACE:
		return "You've used up all available passcodes! Regenerate key.";

	case STATE_PARSE_ERROR:
		return "State file invalid.";

	case STATE_NO_USER_ENTRY:
		return "No user entry. Have you created key with --key option?";

	case STATE_NO_SUCH_USER:
		return "No such Unix user in passwd database. Unable to locate home.";

		
	case PPP_ERROR:
		return "Generic PPP error. (Try -v to get details)";

	case PPP_ERROR_POLICY:
		return "Action denied by policy.";

	case PPP_ERROR_RANGE:
		return "Argument out of range.";

	case PPP_ERROR_ILL_CHAR:
		return "Illegal character in input.";

	case PPP_ERROR_TOO_LONG:
		return "Input too long.";

	case PPP_ERROR_DISABLED:
		return "User state disabled.";

	default:
		return "Error occured while reading state. Use -v to determine which.";
	}
}

/****************************************
 * High-level state management functions
 ****************************************/
int ppp_init(state **s, const char *user)
{
	int ret;
	*s = malloc(sizeof(**s));
	if (!*s)
		return STATE_NOMEM;
	ret = state_init(*s, user);

	if (ret == 0)
		return 0;

	free(*s);
	*s = NULL;

	return ret;
}

void ppp_fini(state *s)
{
	state_fini(s);
	free(s);
}


int ppp_load(state *s)
{
	int retval = 1;

	/* Locking */
	retval = state_lock(s);
	if (retval != 0)
		return retval;

	/* Loading... */
	retval = state_load(s);
	if (retval != 0)
		goto cleanup1;

	/* Calculation and validation */
	ppp_calculate(s);

	/* We can't check whole state for policy because 
	 * we'd make it impossible to fix state files. 
	 * Check whole policy before authentication only.
	 * Here just ensure most important things like key/counter.
	 */
	retval = ppp_verify_range(s);
	if (retval != 0) {
		goto cleanup1;
	}

	/* Everything fine */
	return 0;

cleanup1:
	state_unlock(s);
	return retval;
}

int ppp_flag_check(const state *s, int flag)
{
	return s->flags & flag;
}

void ppp_flag_add(state *s, int flag)
{
	/* TODO: Check policy */
	s->flags |= flag;
}

void ppp_flag_del(state *s, int flag)
{
	/* TODO: Check policy */
	s->flags &= ~flag;
}


int ppp_release(state *s, int store, int unlock)
{
	int ret;
	int retval = 0;

	if (store && (ret = state_store(s, 0)) != 0) {
		print(PRINT_ERROR, "Error while storing state file\n");
		print(PRINT_NOTICE, "(%d: %s)\n", ret, ppp_get_error_desc(ret));
		retval++;
	}

	if (unlock && (ret = state_unlock(s)) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file\n");
		print(PRINT_NOTICE, "(%d: %s)\n", ret, ppp_get_error_desc(ret));
		retval++;
	}

	return retval;
}

/*******************
 * Atomic combos
 *******************/

/* Lock, load, increment, save, unlock */
int ppp_increment(state *s)
{
	int ret;

	/* Load user state */
	ret = ppp_load(s);
	if (ret != 0)
		return ret;

	/* Verify state correctness before trying anything more */
	ret = ppp_verify_state(s);
	if (ret != 0) {
		goto error;
	}

	/* Do not increment anything if user is disabled */
	if (ppp_flag_check(s, FLAG_DISABLED)) {
		ret = PPP_ERROR_DISABLED;
		goto error;
	}

	/* Hold temporarily current counter */
	mpz_t tmp;
	mpz_init_set(tmp, s->counter);

	/* Increment and save state */
	mpz_add_ui(s->counter, s->counter, 1);

	/* We will return it's return value if anything failed */
	ret = ppp_release(s, 1, 1);

	/* Restore current counter */
	mpz_set(s->counter, tmp);

	mpz_clear(tmp);
	return ret;

error:
	/* Unlock. And ignore unlocking errors */
	(void) ppp_release(s, 0, 1);
	return ret;
}


int ppp_failures(const state *s, int zero)
{
	state *s_tmp; /* Second state. We don't want to clobber current one
		       * also we must read failure count from disk. */
	int ret = 1;

	if (ppp_init(&s_tmp, s->username) != 0)
		return 1;

	/* Lock&Load state from disk */
	ret = ppp_load(s_tmp);
	if (ret != 0)
		goto cleanup;

	/* Increment failure counters */
	if (zero == 0) {
		s_tmp->failures++;
		s_tmp->recent_failures++;
	} else {
		s_tmp->recent_failures = 0;
	}

	/* Store changes and unlock */
	ret = ppp_release(s_tmp, 1, 1);
	if (ret != 0) {
		print(PRINT_WARN, "Unable to save decremented state\n");
		goto cleanup;
	}

	ret = 0; /* Everything ok */

cleanup:
	ppp_fini(s_tmp);

	return ret;
}

/**************************************
 * Getters / Setters
 **************************************/

unsigned int ppp_get_int(const state *s, int field)
{
	switch (field) {
	case PPP_FIELD_FAILURES:        return s->failures;
	case PPP_FIELD_RECENT_FAILURES: return s->recent_failures;
	case PPP_FIELD_CODE_LENGTH:     return s->code_length;
	case PPP_FIELD_ALPHABET:        return s->alphabet;
	case PPP_FIELD_FLAGS:           return s->flags;

	default:
		print(PRINT_CRITICAL, "Illegal field passed to ppp_get_int\n");
		assert(0);
		return PPP_ERROR;
	}
}

int ppp_set_int(state *s, int field, unsigned int arg, int options)
{
	int ret;
	switch (field) {
	case PPP_FIELD_FAILURES:
		s->failures = arg;
		break;

	case PPP_FIELD_RECENT_FAILURES: 
		s->recent_failures = arg;
		break;

	case PPP_FIELD_CODE_LENGTH:
		/* Always check policy */
		ret = ppp_verify_code_length(arg);
		if (ret != 0)
			return ret;

		s->code_length = arg;
		break;

	case PPP_FIELD_ALPHABET:
		/* Always check policy */
		ret = ppp_verify_alphabet(arg);
		if (ret != 0)
			return ret;


		s->alphabet = arg;
		break;

	case PPP_FIELD_FLAGS:
		if (arg > (FLAG_SHOW|FLAG_SALTED|FLAG_DISABLED)) {
			print(PRINT_WARN, "Illegal set of flags.\n");
			return PPP_ERROR;
		}

		if (options & PPP_CHECK_POLICY) {
			/* TODO: Check policy */
		}

		s->flags = arg;
		break;

	default:
		print(PRINT_CRITICAL, "Illegal field passed to ppp_set_int\n");
		assert(0);
		return PPP_ERROR;
	}

	return 0;
}


int ppp_get_mpz(const state *s, int field, mpz_t arg)
{
	assert(arg);
	switch (field) {
	case PPP_FIELD_KEY:
		mpz_set(arg, s->sequence_key);
		break;

	case PPP_FIELD_COUNTER:
		mpz_set(arg, s->counter);
		break;

	case PPP_FIELD_LATEST_CARD:
		mpz_set(arg, s->latest_card);
		break;

	default:
		print(PRINT_CRITICAL, "Illegal field passed to ppp_get_mpz\n");
		mpz_set_ui(arg, 0);
		assert(0);
		return PPP_ERROR;
	}

	return 0;
}

/* ppp_get_str helpers! */
static void _ppp_dispose_prompt(state *s)
{
	if (!s->prompt)
		return;

	const int length = strlen(s->prompt);
	memset(s->prompt, 0, length);
	free(s->prompt);
	s->prompt = NULL;
}

/* Generate prompt used for authentication
 * Do not free returned value. It's stored in state
 * and freed in state_fini.
 */
static const char *_ppp_get_prompt(state *s)
{
	/* "Passcode RRC [number]: " */
	const char intro[] = "Passcode ";
	int length = sizeof(intro)-1 + 3 + 5 + 1;
	char *num;

	if (s->prompt)
		_ppp_dispose_prompt(s);

	/* Ensure ppp_calculate was called already! */
	assert(s->codes_on_card != 0);

	num = mpz_get_str(NULL, 10, s->current_card);
	length += strlen(num);

	s->prompt = malloc(length);
	if (!s->prompt)
		return NULL;

	int ret = sprintf(s->prompt, "%s%2d%c [%s]: ", intro, s->current_row, s->current_column, num);

	memset(num, 0, strlen(num));
	free(num);
	num = NULL;

	assert(ret+1 == length);

	if (ret <= 0) {
		memset(s->prompt, 0, length);
		free(s->prompt);
		s->prompt = NULL;
		return NULL;
	}
	return s->prompt;
}

int ppp_get_str(const state *s, int field, const char **arg)
{
	assert(s && arg);

	switch (field) {

	case PPP_FIELD_USERNAME:
		*arg = s->username;
		break;

	case PPP_FIELD_PROMPT:
		/* Prompt might change state a bit, but 
		 * this should be transparent */
		*arg = _ppp_get_prompt((state *)s);
		break;

	case PPP_FIELD_CONTACT:
		*arg = s->contact;
		break;

	case PPP_FIELD_LABEL:
		*arg = s->label;
		break;

	default:
		print(PRINT_CRITICAL, "Illegal field passed to ppp_get_str\n");
		assert(0);
		return PPP_ERROR;
	}

	return 0;
}

int ppp_set_str(state *s, int field, const char *arg, int options)
{
	const int check_policy = options & PPP_CHECK_POLICY;
	cfg_t *cfg = cfg_get();

	assert(cfg);
	assert(s);

	int length;

	if (arg)
		length = strlen(arg);
	else
		length = 0;

	switch (field) {
	case PPP_FIELD_CONTACT:
		if (check_policy && cfg->allow_contact_change == 0) {
			return PPP_ERROR_POLICY;
		}

		if (length + 1 > STATE_CONTACT_SIZE) {
			return PPP_ERROR_TOO_LONG;
		}

		if (!state_validate_str(arg)) {
			return PPP_ERROR_ILL_CHAR;
		}

		if (length == 0)
			s->contact[0] = '\0';
		else 
			strcpy(s->contact, arg); 
		break;

	case PPP_FIELD_LABEL:
		if (check_policy && cfg->allow_label_change == 0) {
			return PPP_ERROR_POLICY;
		}

		if (length + 1 > STATE_LABEL_SIZE) {
			return PPP_ERROR_TOO_LONG;
		}

		if (!state_validate_str(arg)) {
			return PPP_ERROR_ILL_CHAR;
		}

		if (length == 0)
			s->label[0] = '\0';
		else 
			strcpy(s->label, arg); 

		break;

	default:
		print(PRINT_CRITICAL, "Illegal field passed to ppp_set_str\n");
		assert(0);
		return PPP_ERROR;
	}

	return 0;
}
