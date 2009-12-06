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

#define PPP_INTERNAL 1

#include "num.h"
#include "crypto.h"

#include "ppp.h"
#include "print.h"

/* 64 characters -> 16 777 216 passcodes for length 4 */
const char alphabet_simple[] =
	"!#%+23456789:=?@"
	"ABCDEFGHJKLMNPRSTUVWXYZ"
	"abcdefghijkmnopqrstuvwxyz";

/* 88 characters -> 59 969 536 passcodes for length 4 */
const char alphabet_extended[] =
	"!\"#$%&'()*+,-./23456789:;<=>?@ABCDEFGHJKLMNO"
	"PRSTUVWXYZ[\\]^_abcdefghijkmnopqrstuvwxyz{|}~";

void ppp_add_salt(const state *s, mpz_t passcode)
{
	if (!(s->flags & FLAG_NOT_SALTED)) {
		mpz_t salt;
		mpz_init_set(salt, s->counter);
		mpz_and(salt, salt, s->salt_mask);
		mpz_add(passcode, passcode, salt);
		num_dispose(salt);
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

	int alphabet_len;
	const char *alphabet;
	if (s->flags & FLAG_ALPHABET_EXTENDED) {
		alphabet = alphabet_extended;
		alphabet_len = sizeof(alphabet_extended) - 1;
	} else {
		alphabet = alphabet_simple;
		alphabet_len = sizeof(alphabet_simple) - 1;
	}

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

	num_dispose(quotient);
	num_dispose(cipher);
	return ret;
}

void ppp_dispose_prompt(state *s)
{
	if (!s->prompt)
		return;

	const int length = strlen(s->prompt);
	memset(s->prompt, 0, length);
	free(s->prompt);
	s->prompt = NULL;
}

const char *ppp_get_prompt(state *s)
{
	/* "Passcode RRC [number]: " */
	const char intro[] = "Passcode ";
	int length = sizeof(intro)-1 + 3 + 5 + 1;
	char *num;

	if (s->prompt)
		ppp_dispose_prompt(s);

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

int ppp_get_current(const state *s, char *passcode)
{
	if (passcode == NULL)
		return 1;

	if (ppp_get_passcode(s, s->counter, passcode) != 0)
		return 2;

	return 0;
}

const char *ppp_get_contact(const state *s)
{
	return s->contact;
}

int ppp_authenticate(const state *s, const char *passcode)
{
	char current_passcode[17];

	if (passcode == NULL)
		return 1;

	if (ppp_get_passcode(s, s->counter, current_passcode) != 0)
		return 2;

	if (strcmp(passcode, current_passcode) != 0)
		return 3;

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
	if (!(s->flags & FLAG_NOT_SALTED)) {
		mpz_and(unsalted_counter, unsalted_counter, s->code_mask);
	}

	unsigned long int r = mpz_fdiv_q_ui(s->current_card, unsalted_counter, s->codes_on_card);
	mpz_add_ui(s->current_card, s->current_card, 1);

	num_dispose(unsalted_counter);

	/* Calculate column/row using rest from division */
	int current_column = r % s->codes_in_row;
	r -= current_column;
	s->current_row = 1 + r / s->codes_in_row;
	s->current_column = columns[current_column];

	/* Calculate max passcard */
	if (s->flags & FLAG_NOT_SALTED) {
		const char max_hex[] =
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
		assert(sizeof(max_hex)  == 33);
		mpz_set_str(s->max_card, max_hex, 16);
	} else {
		mpz_set(s->max_card, s->code_mask);
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
		num_dispose(max_key);
		return STATE_RANGE;
	}
	num_dispose(max_key);

	/* Verify counter size */
	const char max_counter_hex[] =
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	mpz_t max_counter;
	mpz_init_set_str(max_counter, max_counter_hex, 16);

	if (mpz_cmp(s->counter, max_counter) > 0) {
		print(PRINT_ERROR, "State file corrupted. Counter number too big\n");
		num_dispose(max_counter);
		return STATE_RANGE;
	}
	num_dispose(max_counter);

	/* Check if we have runned out of available passcodes */

	/* Retrieve current counter without salt */
	mpz_t just_counter;
	mpz_init(just_counter);
	if (s->flags & FLAG_NOT_SALTED) {
		mpz_set(just_counter, s->counter);
	} else {
		mpz_and(just_counter, s->counter, s->code_mask);
	}

	/* Equal is too big because max_code is calculated starting from 1
	 * whereas counter starts from 0 */
	if (mpz_cmp(just_counter, s->max_code) >= 0) {
		/* Whoops */
		num_dispose(just_counter);
		return STATE_NUMSPACE;
	}

	num_dispose(just_counter);
	return 0;
}

/******************
 * Warning support
 ******************/
int ppp_get_warning_condition(const state *s)
{
	assert(s->codes_on_card > 0);

	int tmp = mpz_cmp(s->current_card, s->latest_card);
	if (tmp == 0)
		return PPP_WARN_LAST_CARD;
	if (tmp > 0)
		return PPP_WARN_NOTHING_LEFT;

	return PPP_WARN_OK;
}

const char *ppp_get_warning_message(enum ppp_warning warning)
{
	const char *nothing_left = "You have no printed passcodes left!";
	const char *last_card = "You are on your last printed passcard!";

	switch (warning) {
	case PPP_WARN_OK:
		return NULL;
	case PPP_WARN_LAST_CARD:
		return last_card;
	case PPP_WARN_NOTHING_LEFT:
		return nothing_left;
	default:
		assert(0);
		return 0;
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
		return PPP_NOMEM;
	ret = state_init(*s, user, NULL);

	if (ret == 0)
		return 0;

	free(*s);
	*s = NULL;

	return ret;
}

void ppp_fini(state *s)
{
	if (s->lock_fd > 0)
		state_unlock(s);
	state_fini(s);
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

int ppp_is_flag(const state *s, int flag)
{
	return s->flags & flag;
}

int ppp_release(state *s, int store, int unlock)
{
	int retval = 0;

	if (store && state_store(s) != 0) {
		print(PRINT_ERROR, "Error while storing state file\n");
		retval++;
	}

	if (unlock && state_unlock(s) != 0) {
		print(PRINT_ERROR, "Error while unlocking state file\n");
		retval++;
	}

	return retval;
}

int ppp_increment(state *s)
{
	int ret;

	/* Load user state */
	ret = ppp_load(s);
	if (ret != 0)
		return ret;

	/* Hold temporarily current counter */
	mpz_t tmp;
	mpz_init_set(tmp, s->counter);

	/* Increment and save state */
	mpz_add_ui(s->counter, s->counter, 1);

	/* We will return it's return value if anything failed */
	ret = ppp_release(s, 1, 1);

	/* Restore current counter */
	mpz_set(s->counter, tmp);


	num_dispose(tmp);
	return ret;
}

int ppp_decrement(state *s)
{
	state *s_tmp; /* Second state, so we won't clobber current one */
	int ret = 1;

	if (ppp_init(&s_tmp, s->username) != 0)
		return 1;

	/* Load state from disk */
	ret = ppp_load(s_tmp);
	if (ret != 0)
		goto cleanup;

	/* Freshly read counter must be bigger by 1
	 * to continue, so decrement it and compare... */
	mpz_sub_ui(s_tmp->counter, s_tmp->counter, 1);

	if (mpz_cmp(s_tmp->counter, s->counter) != 0) {
		/* Whoops, in the meantime somebody else
		 * tried to authenticate! */
		print(PRINT_NOTICE,
		      "Load/decrement failed, file "
		      "modified in the meantime!\n");
		ret = 2;
		goto cleanup;
	}

	/* Didn't changed, store state with decremented counter */
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


/***************************
 * Testcases
 **************************/

static int _ppp_testcase_statistical(const state *s, const int alphabet_len, const int code_length, const int tests)
{
	/* Calculate distribution of 1s and 0s in
	 * generated passcodes for specified state key
	 */
	int bits_to_test;
	int bits_in_character;
	if (alphabet_len <= 64) {
		bits_in_character = 6; /* Exactly 6! */
		bits_to_test = code_length * bits_in_character;
	} else if (alphabet_len <= 128) { /* 2^x = 88 -> 6.4594bits */
		bits_in_character = 6;
		bits_to_test = code_length * bits_in_character;
	}

	unsigned long zeroes[130] = {0};
	unsigned long ones[130] = {0};

	/* 6 is number of bits in a
	 * character of 64-letter alphabet */

	unsigned char key_bin[32];
	unsigned char cnt_bin[16];
	unsigned char cipher_bin[16];
	mpz_t counter;
	mpz_t cipher;
	mpz_t quotient;
	int i;
	unsigned int cnt;

	int ret;

	mpz_init(counter);
	mpz_init(quotient);
	mpz_init(cipher);

	/* Convert numbers to binary */
	num_to_bin(s->sequence_key, key_bin, 32);

	printf("ppp_testcase_stat: Evaluating %d bits distribution in %u passcodes\n", bits_to_test, tests);
	for (cnt = 0; cnt < tests; cnt++) {
		mpz_add_ui(counter, counter, 1);
		num_to_bin(counter, cnt_bin, 16);

		/* Encrypt counter with key */
		ret = crypto_aes_encrypt(key_bin, cnt_bin, cipher_bin);
		if (ret != 0) {
			printf("AES ERROR\n");
			goto clear;
		}

		/* Convert result back to number */
		num_from_bin(cipher, cipher_bin, 16);

		int bit = 0;
		int y;
		for (i=0; i<code_length; i++) {
			unsigned long int r = mpz_fdiv_q_ui(quotient, cipher, alphabet_len);
			mpz_set(cipher, quotient);

			// calculate things in r
			for (y=0; y<bits_in_character; y++) {
				if (r & (1<<y))
					ones[bit]++;
				else
					zeroes[bit]++;
				bit++;
			}
		}

	}
	int bit;
	int failed = 0;
	/* Perfect distribution */
	const double perfect = tests / 2.0;

	/* Calculate distribution */
	double average1 = 0.0, average0 = 0.0;
	printf("ppp_testcase_stat: Results:\n");

	for (bit=0; bit<bits_to_test; bit++) {
		average1 += ones[bit];
		average0 += zeroes[bit];
		double tmp1= (double)ones[bit] / perfect;
		double tmp0 = (double)zeroes[bit] / perfect;
		if (tmp1 > 1.004 || tmp1 < 0.993 || tmp0 < 0.993 || tmp0 > 1.004) {
			printf("ppp_testcase_stat: FAILED. Bit %d has too big error (%0.10f, %0.10f)\n",
			       bit, tmp1, tmp0);
			failed = 1; /* Count each fail as one */
		}
	}

	average1 /= bits_to_test;
	average0 /= bits_to_test;
	printf("Perfect distribution is %.2f\n", perfect);
	printf("Average distribution 1/0: %.10f %.10f\n", average1, average0);
	double abs_err1 = average1 > perfect ? average1 - perfect : perfect - average1;
	double abs_err0 = average0 > perfect ? average0 - perfect : perfect - average0;
	double rel_err1 = average1 / perfect;
	double rel_err0 = average0 / perfect;
	printf("Absolute error: 1/0: %.10f %.10f\n", abs_err1, abs_err0);
	printf("Relative error: 1/0: %.10f %.10f\n", rel_err1, rel_err0);

	if (rel_err1 > 1.001 || rel_err1 < 0.999 || rel_err0 > 1.001 || rel_err0 < 0.999) {
		printf("ppp_testcase_stat: FAILED. Too big average relative errors!\n");
		failed++;
	} else {
		printf("ppp_testcase_stat: PASSED!\n");
	}

	printf("\n");

clear:
	memset(key_bin, 0, sizeof(key_bin));
	memset(cnt_bin, 0, sizeof(cnt_bin));
	memset(cipher_bin, 0, sizeof(cipher_bin));

	num_dispose(quotient);
	num_dispose(cipher);
	num_dispose(counter);

	return failed;
}


static int _ppp_testcase_authenticate(const char *passcode)
{
	int retval = 0;

	const char *prompt = NULL;

	/* OTP State */
	state s;

	/* Module options */

	/* Enforced makes any user without an .otpasswd config
	 * fail to login */
	int enforced = 0;	/* Do we enforce OTP logons? */

	printf("*** Authenticate testcase\n");
	print_init(PRINT_NOTICE, 1, 1, "/tmp/otpasswd_dbg");

	/* Initialize state with given username, and default config file */
	if (state_init(&s, NULL, ".otpasswd_testcase") != 0) {
		/* This will fail if we're unable to locate home directory */
		printf("STATE_INIT FAILED\n");
		print_fini();
		return retval;
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_increment(&s);
	switch (retval) {
	case 0:
		printf("LOAD_INC_STORE=OK\n");
		/* Everything fine */
		break;

	case STATE_DOESNT_EXISTS:
		if (enforced == 0) {
			/* Not enforced - ignore */
			printf("IGNORING - NO DIR\n");
			goto cleanup;
		} else {
			printf("ENFORCING AND NO DIRECTORY\n");
			goto cleanup;
		}


	default: /* Any other problem - error */
		printf("STATE_LOAD_INC_STORE FAILED\n");
		goto cleanup;
	}


	/* Generate prompt */
	ppp_calculate(&s);
	prompt = ppp_get_prompt(&s);
	if (!prompt) {
		printf("GET_PROMPT FAILED\n");
		goto cleanup;
	}

	if (ppp_authenticate(&s, passcode) == 0) {

		/* Correctly authenticated */
		printf("AUTHENTICATION SUCCESSFULL\n");
		retval = 1;
		goto cleanup;
	}

	printf("AUTHENTICATION NOT SUCCESSFULL\n");
	retval = 0;
cleanup:
	state_fini(&s);
	return retval;
}

#define _PPP_TEST(cnt,len, col, row, code)			\
mpz_set_ui(s.counter, (cnt)); s.code_length = (len);		\
ppp_calculate(&s);						\
buf1 = mpz_get_str(NULL, 10, s.counter);			\
buf2 = mpz_get_str(NULL, 10, s.current_card);			\
ppp_get_passcode(&s, s.counter, passcode);			\
printf("ppp_testcase[%2d]: ", test++);				\
printf("cnt=%10s len=%2d in_row=%d pos=%d%c[%8s] code=%16s",	\
       buf1, s.code_length, s.codes_in_row, s.current_row,	\
       s.current_column, buf2, passcode);			\
if (s.current_row == (row) && s.current_column == (col)		\
    && strcmp(passcode, (code)) == 0)				\
	printf(" PASSED\n"); else {				\
		printf(" FAILED\n\n");				\
		failed++; }					\
free(buf1); free(buf2);

int ppp_testcase(void)
{
	int failed = 0;
	char *buf1, *buf2;
	int test = 1;
	char passcode[17] = {0};

	/* Check calculations */
	state s;
	state_init(&s, NULL, NULL);

	/* Statistical tests using key = 0 */
	mpz_set_ui(s.sequence_key, 1345126463UL);
	failed += _ppp_testcase_statistical(&s, 64, 16, 500000);

	/* Following test should fail using norms from first test */
	// failed += _ppp_testcase_statistical(&s, 88, 16, 500000);

	printf("*** Sequence key = 0.\n");
	mpz_set_ui(s.sequence_key, 0UL);
	_PPP_TEST(0, 4, 'A', 1, "NH7j");
	_PPP_TEST(34, 4, 'G', 5, "EXh5");
	_PPP_TEST(864197393UL+50UL, 4, 'E', 8, "u2Yp");

	/* length = 5 */
	_PPP_TEST(0UL, 5, 'A', 1, "NH7js");
	_PPP_TEST(124UL, 5, 'E', 5, "+S:HK");

	/* length = 16 */
	_PPP_TEST(574734UL, 16, 'A', 8, "wcLSDqSyXJqxxYyr");

	/*** Tests with extended alphabet ***/
	printf("*** Extended alphabet tests:\n");
	s.flags |= FLAG_ALPHABET_EXTENDED;
	_PPP_TEST(0, 4, 'A', 1, "7OPJ");
	_PPP_TEST(34, 4, 'G', 5, "Y7CB");
	_PPP_TEST(864197393UL+50UL, 4, 'E', 8, "=sb;");
	s.flags &= ~FLAG_ALPHABET_EXTENDED;

	printf("*** Another sequence key tests:\n");
	/*** Tests with other sequence_key ***/
	const unsigned char key_bin[32] = {
		0x80, 0x45, 0x32, 0x22,
		0x10, 0xFF, 0xEE, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x65, 0x75, 0x86, 0x98,
	};
	// 8045322210FFEE00000000000000000000000000000000000000000065758698
	num_from_bin(s.sequence_key, key_bin, 32);

	printf("New key: ");
	crypto_print_hex(key_bin, 32);
	/* length = 4 */
	_PPP_TEST(0, 4, 'A', 1, ":LJ%");

	_PPP_TEST(34, 4, 'G', 5, "#W++");
	_PPP_TEST(864197393UL+50UL, 4, 'E', 8, "BBaF");

	/* length = 5 */
	_PPP_TEST(0UL, 5, 'A', 1, ":LJ%@");
	_PPP_TEST(124UL, 5, 'E', 5, "rUiHE");

	/* length = 16 */
	_PPP_TEST(574734UL, 16, 'A', 8, "vaxZ5sXJryc?KCn8");

	/*** Try second alphabet ***/
	s.flags |= FLAG_ALPHABET_EXTENDED;
	printf("Second alphabet\n");
	_PPP_TEST(0, 7, 'A', 1, "Y*HJ;,(");
	_PPP_TEST(70+34, 7, 'A', 7, "Ao_\"e82");
	_PPP_TEST(70+36, 7, 'C', 7, "(&JV?E_");

	/* TODO: do some get_passcode_number testcases */

	state_fini(&s);

	/* Authenticate testcase */
	/* Create file with empty key */
	if (state_init(&s, NULL, ".otpasswd_testcase") != 0) {
		printf("ERROR WHILE CREATING TEST KEY\n");
		failed++;
		return failed;
	}
	state_store(&s);
	state_fini(&s);

	printf("Should succeed:\n");
	if (_ppp_testcase_authenticate("NH7j") == 0) { /* Check if returned true */
		failed++;
	}
	printf("Should NOT succeed:\n");
	if (_ppp_testcase_authenticate("aSsD") != 0) {
		failed++;
	}

	return failed;
}
