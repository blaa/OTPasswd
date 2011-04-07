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

#include "testcases.h"

#define PPP_INTERNAL 1
#include "ppp.h"

#include "security.h"

/***************************
 * Crypto/NUM Testcases
 **************************/
int crypto_testcase(void)
{
	int failed = 0;
	int i;

	unsigned char plain[] = 
		"To be encrypted.";
	unsigned char encrypted_origin[] = 
		"\x4e\xb9\x42\x33\xa2\xcf\x6c\x3c"
		"\x5f\x96\xf1\x11\x57\x8a\xa7\x78";

	unsigned char encrypted[16], decrypted[17];
	unsigned char key[32] = "This is the key";

	crypto_aes_encrypt(key, plain, encrypted);
	crypto_aes_decrypt(key, encrypted, decrypted); 

	printf("crypto_aes_test [ 1]: ");
	if (memcmp(plain, decrypted, 16) != 0) {
		printf("FAILED ");
		failed++;
	} else {
		printf("PASSED ");		
	}

	if (memcmp(encrypted, encrypted_origin, 16) != 0) {
		printf("FAILED\n");
		crypto_print_hex(encrypted, 16);
		failed++;
	} else {
		printf("PASSED\n");		
	}

	printf("crypto_aes_test (enc/dec) [ 2]: ");
	for (i = 0; i < 10; i++) {
		crypto_file_rng("/dev/urandom", NULL, plain, 16);
		crypto_aes_encrypt(key, plain, encrypted);
		crypto_aes_decrypt(key, encrypted, decrypted);
		

		if (memcmp(plain, decrypted, 16) != 0) {
			printf("FAILED ");
			failed++;
		} else {
			printf("PASSED ");		
		}
	}
	printf("\n");


	/* SHA256 testcase */
	{
		const unsigned char hash_plain[] = "To be encrypted.";
		unsigned char hash[32];
		const unsigned char hash_origin[32] =
			"\x4f\xee\xfa\x18\x7b\x71\xc8\xf1\x36\xb6\xdb\xc8\x6e"
			"\xa6\x4f\x72\x1f\xfa\xa6\x0c\x52\x34\x96\x45\xeb\x87"
			"\x82\x56\x8e\x72\x17\xe1";

		crypto_sha256(hash_plain, strlen((char *) hash_plain), hash);
		printf("sha_test [ 1]: ");
		if (memcmp(hash, hash_origin, 32) != 0) {
			printf("FAILED\n");
			failed++;
		} else {
			printf("PASSED\n");
		}
	}

	return failed;
}


int spass_testcase(void)
{
	int ret;
	state s;
	int failed = 0;
	char *current_user = security_get_calling_user();
	state_init(&s, current_user);
	free(current_user), current_user = NULL;

	ret = ppp_set_spass(&s, "TestSpAsSs#4$4", 0);
	printf("SPASS TESTCASE [1]: ");
	if (ret != PPP_ERROR_SPASS_SET) {
		failed++;
		printf("FAILED\n");
	} else {
		printf("OK\n");
	}
		
	ret = ppp_spass_validate(&s, "TestSpAsSs#4$4");
	printf("SPASS TESTCASE [2]: ");
	if (ret != 0) {
		failed++;
		printf("FAILED (%d)\n", ret);
	} else {
		printf("OK\n");
	}

	ret = ppp_spass_validate(&s, "TestSpAsSs#4$5");
	printf("SPASS TESTCASE [3]: ");
	if (ret == 0) {
		failed++;
		printf("FAILED\n");
	} else {
		printf("OK\n");
	}

	ret = ppp_set_spass(&s, NULL, 0);
	printf("SPASS TESTCASE [4]: ");
	if (ret != PPP_ERROR_SPASS_UNSET) {
		failed++;
		printf("FAILED\n");
	} else {
		printf("OK\n");
	}

	ret = ppp_spass_validate(&s, "whatever");
	printf("SPASS TESTCASE [5]: ");
	if (ret == 0) {
		failed++;
		printf("FAILED\n");
	} else {
		printf("OK\n");
	}
		
	state_fini(&s);

	return failed;
}

/***************************
 * Passcards testcases
 **************************/
#if 0
/* TODO: Reimplement in utility */
int card_testcase(void)
{
	unsigned char hash[32];
	char *card;
	state s;
	num_t cnt;
	int test = 0;
	int failed = 0;

	mpz_init(cnt);
	char *current_user = security_get_calling_user();
	state_init(&s, current_user);
	free(current_user), current_user = NULL;
	strcpy(s.label, "hostname long");

	const unsigned char hash1[] =
		"\x84\x68\x05\x94\x99\x1F\x8C\xF8\x19\x3A\x1F\x3A"
		"\xC2\x03\x77\x95\xAA\xA4\x2E\x2E\x2C\x0A\x01\x0E"
		"\x20\x71\x5C\xD9\xE1\x22\x74\x93";

	const unsigned char hash2[] =
		"\xDC\x83\x59\x47\x47\x96\x65\x82\x46\x67\xB9\x9F"
		"\x0D\xC1\x5C\x10\xC4\xD8\xC6\xF2\xA4\x4C\xDD\xB8"
		"\x52\x1F\x73\x25\x53\x3C\x13\xE3";

	/* Test 1 */
	test++;
	s.code_length = 10;
	ppp_calculate(&s);

	mpz_set_ui(cnt, 254323245UL);
	mpz_mul_ui(cnt, cnt, 21234887UL);
	mpz_mul_ui(cnt, cnt, 21234565UL);
	mpz_mul_ui(cnt, cnt, 21234546UL);
	mpz_add_ui(cnt, cnt, 1UL);

	card = card_ascii(&s, cnt);

	crypto_sha256((unsigned char *)card, strlen(card), hash);

	if (memcmp(hash, hash1, 32) != 0) {
		failed++;
		printf("passcard_testcase[%2d]: FAILED\n", test);
		printf("CARD:\n%s\n", card);
		printf("Got hash: ");
		crypto_print_hex(hash, 32);
		printf("Expected: ");
		crypto_print_hex(hash1, 32);
	}
	free(card);

	/* Test 2 */
	strncpy(s.label, "hostname very long this time."
		" I guess it will be truncated", STATE_LABEL_SIZE);
	test++;
	s.code_length = 2;
	ppp_calculate(&s);

	mpz_set_ui(cnt, 25432UL);
	mpz_mul_ui(cnt, cnt, 214887UL);
	mpz_mul_ui(cnt, cnt, 2134565UL);
	mpz_mul_ui(cnt, cnt, 214546UL);
	mpz_add_ui(cnt, cnt, 1UL);

	card = card_ascii(&s, cnt);

	crypto_sha256((unsigned char *)card, strlen(card), hash);

	if (memcmp(hash, hash2, 32) != 0) {
		failed++;
		printf("passcard_testcase[%2d]: FAILED\n", test);
		printf("CARD:\n%s\n", card);
		printf("Got hash: ");
		crypto_print_hex(hash, 32);
		printf("Expected: ");
		crypto_print_hex(hash2, 32);
	}
	free(card);

	printf("passcard_testcases: %d out of %d tests failed\n", failed, test);
	state_fini(&s);
	mpz_clear(cnt);

	return failed;
}
#endif

/***************************
 * State Testcases
 **************************/
int state_testcase(void)
{
	state s1, s2;
	int failed = 0;
	int test = 0;
	char *current_user = security_get_calling_user();

	if (state_init(&s1, current_user) != 0)
		printf("state_testcase[%2d] failed (%d)\n", test, failed++);

	test++; if (state_init(&s2, current_user) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	ppp_flag_del(&s1, FLAG_SALTED);
	test++; if (state_key_generate(&s1) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);
	
	s1.counter = num_i(321323211UL);


	/*
	test++; if (state_lock(&s1) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);
	*/
	test++; if (state_store(&s1, 0) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (state_unlock(&s1) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);


	test++; if (state_load(&s2) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	/* Compare */
	test++; if (memcmp(s1.sequence_key, s2.sequence_key, 32) != 0) {
		printf("state_testcase[%2d] failed (seq key) (%d)\n", test, failed++);
		printf("Orig: ");
		crypto_print_hex(s1.sequence_key, sizeof(s1.sequence_key));
		printf("Read: ");
		crypto_print_hex(s2.sequence_key, sizeof(s2.sequence_key));
	}

	test++; if (num_cmp(s1.counter, s2.counter) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (num_cmp(s1.latest_card, s2.latest_card) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (s1.flags != s2.flags || s1.code_length != s2.code_length)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);


	printf("state_testcases %d FAILED %d PASSED\n", failed, test-failed);

	state_fini(&s1);
	state_fini(&s2);

	free(current_user);
	return failed;
}


/***************************
 * PPP Testcases
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
	} else {
		printf("Impossible. Alphabet should never exceed 128 characters!\n");
		printf("Nor be negative. It's value is %d\n", alphabet_len);
		assert(0);
	}

	unsigned long zeroes[130] = {0};
	unsigned long ones[130] = {0};

	/* 6 is number of bits in a
	 * character of 64-letter alphabet */

	unsigned char cnt_bin[16];
	unsigned char cipher_bin[16];
	num_t counter = num_i(0);
	num_t cipher = num_i(0);
	num_t quotient = num_i(0);
	int i;
	unsigned int cnt;

	int ret;
	int failed = 0;

	printf("ppp_testcase_stat: Evaluating %d bits distribution in %u passcodes\n", bits_to_test, tests);
	for (cnt = 0; cnt < tests; cnt++) {
		counter = num_add_i(counter, 1);
		num_export(counter, (char *)cnt_bin, NUM_FORMAT_BIN);
//		num_to_bin(counter, cnt_bin, 16);

		/* Encrypt counter with key */
		ret = crypto_aes_encrypt(s->sequence_key, cnt_bin, cipher_bin);
		if (ret != 0) {
			printf("AES ERROR\n");
			goto clear;
		}

		/* Convert result back to number */
//		num_from_bin(cipher, cipher_bin, 16);
		num_import(&cipher, (char *)cipher_bin, NUM_FORMAT_BIN);

		int bit = 0;
		int y;
		for (i=0; i<code_length; i++) {
			unsigned long int r = num_div_i(&quotient, cipher, alphabet_len);
			cipher = quotient;

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
		if (tmp1 > 1.04 || tmp1 < 0.93 || tmp0 < 0.93 || tmp0 > 1.04) {
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

	if (rel_err1 > 1.01 || rel_err1 < 0.99 || rel_err0 > 1.01 || rel_err0 < 0.99) {
		printf("ppp_testcase_stat: FAILED. Too big average relative errors!\n");
		failed++;
	} else {
		printf("ppp_testcase_stat: PASSED!\n");
	}

	printf("\n");

clear:
	memset(cnt_bin, 0, sizeof(cnt_bin));
	memset(cipher_bin, 0, sizeof(cipher_bin));

	num_clear(quotient);
	num_clear(cipher);
	num_clear(counter);

	return failed;
}

static int _ppp_testcase_stat_2(const state *s,
				const int alphabet_len,
				const int code_length, 
				const int tests)
{
	/* Calculate passcode character distribution
	 * (not bit distribution) */

	/* char_count[i] - how many character[i]
	 * happened */
	/* 130 >= alphabet_length */
	unsigned long char_count[130] = {0};

	unsigned char cnt_bin[16];
	unsigned char cipher_bin[16];
	num_t counter = num_i(0);
	num_t cipher = num_i(0);
	num_t quotient = num_i(0);

	int i;
	unsigned int cnt;
	int failed = 0;

	int ret;

	printf("ppp_testcase_stat: Evaluating character distribution in %u passcodes\n", tests);
	for (cnt = 0; cnt < tests; cnt++) {
		/* Increment counter */
		counter = num_add_i(counter, 119);

		/* Convert to binary for encryption */
		num_export(counter, (char *)cnt_bin, NUM_FORMAT_BIN);

		/* Encrypt counter with key */
		ret = crypto_aes_encrypt(s->sequence_key, cnt_bin, cipher_bin);
		if (ret != 0) {
			printf("AES ERROR\n");
			goto clear;
		}

		/* Convert result back to number */
		num_import(&cipher, (char *)cipher_bin, NUM_FORMAT_BIN);

		for (i=0; i<code_length; i++) {
			unsigned long int r = num_div_i(&quotient, cipher, alphabet_len);
			cipher = quotient;

			/* r selects passcode */
			char_count[r]++;
		}
	}


	/* Perfect distribution */
	const double perfect = tests * code_length / alphabet_len;

	/* Calculate distribution */
	double average = 0.0;
	printf("ppp_testcase_stat2: Results:\n");

	int pos;
	for (pos=0; pos < alphabet_len; pos++) {
		average += char_count[pos];
		double tmp = (double)char_count[pos] / perfect;
		if (tmp > 1.02 || tmp < 0.85) {
			printf("ppp_testcase_stat2: FAILED. Code %d has too big error (%0.10f)\n",
			       pos, tmp);
			failed = 1; /* Count each fail as one */
		}
	}
	average /= alphabet_len;

	printf("Perfect distribution is %.2f\n", perfect);
	printf("Average distribution: %.10f\n", average);
	double abs_err = average > perfect ? average - perfect : perfect - average;
	double rel_err = average / perfect;
	printf("Absolute error: 1/0: %.10f\n", abs_err);
	printf("Relative error: 1/0: %.10f\n", rel_err);

	if (rel_err > 1.0001 || rel_err < 0.9999) {
		printf("ppp_testcase_stat2: FAILED. Too big average relative errors!\n");
		failed++;
	} else {
		printf("ppp_testcase_stat2: PASSED!\n");
	}

	printf("\n");

clear:
	memset(cnt_bin, 0, sizeof(cnt_bin));
	memset(cipher_bin, 0, sizeof(cipher_bin));

	num_clear(quotient);
	num_clear(cipher);
	num_clear(counter);

	return failed;
}



static int _ppp_testcase_authenticate(const char *passcode)
{
	int retval = 0;

	const char *prompt = NULL;
	char *current_user = security_get_calling_user();

	/* OTP State */
	state s;

	/* Module options */

	/* Enforced makes any user without an .otpasswd config
	 * fail to login */
	int enforced = 0;	/* Do we enforce OTP logons? */

	printf("*** Authenticate testcase\n");

	/* Initialize state with given username, and default config file */
	if (state_init(&s, current_user) != 0) {
		/* This will fail if we're unable to locate home directory */
		printf("STATE_INIT FAILED\n");
		return retval;
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_increment(&s);
	switch (retval) {
	case 0:
		printf("LOAD_INC_STORE=OK\n");
		/* Everything fine */
		break;

	case STATE_NON_EXISTENT:
	case STATE_NO_USER_ENTRY: /* FIXME, TODO: Differentiate */
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
	retval = ppp_get_str(&s, PPP_FIELD_PROMPT, &prompt);
	if (retval != 0) {
		printf("ppp_get_str FAILED\n");
		goto cleanup;
	}

	retval = 1;

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
	free(current_user);
	state_fini(&s);
	return retval;
}

#define _PPP_TEST(cnt,len, col, row, code)			\
s.counter = num_i(cnt); s.code_length = (len);			\
ppp_calculate(&s);						\
tmp = num_export(s.counter, buf1, NUM_FORMAT_DEC);		\
assert(tmp == 0); 						\
tmp = num_export(s.current_card, buf2, NUM_FORMAT_DEC);		\
assert(tmp == 0); 						\
ppp_get_passcode(&s, s.counter, passcode);			\
printf("ppp_testcase[%2d]: ", test++);				\
printf("cnt=%10s len=%2d in_row=%d pos=%d%c[%8s] code=%16s",	\
       buf1, s.code_length, s.codes_in_row, s.current_row,	\
       s.current_column, buf2, passcode);			\
if (s.current_row == (row) && s.current_column == (col)		\
    && strcmp(passcode, (code)) == 0)				\
	printf(" PASSED\n"); else {				\
		printf(" FAILED\n\n");				\
		failed++; }

int ppp_testcase(int fast)
{
	int failed = 0;
	char buf1[50], buf2[50];
	int test = 1;
	char passcode[17] = {0};
	char *current_user = security_get_calling_user();
	int tmp;
	int stat_tests = (fast == 1) ? 500 : 120000;
	
	const unsigned char ex_bin[32] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x2d, 0x00, 0x3f, /* 1345126463UL = 0x502d003f */
	};


	/* Check calculations */
	state s;
	state_init(&s, current_user);

	if (state_load(&s) == 0) {
		printf("*** Performing statistical tests with your key\n");
	} else {
		printf("*** Performing statistical tests with generated key\n");
		memcpy(s.sequence_key, ex_bin, sizeof(s.sequence_key));
	}

	/* Statistical tests using following key */
	memcpy(s.sequence_key, ex_bin, sizeof(s.sequence_key));
	failed += _ppp_testcase_statistical(&s, 64, 16, stat_tests);
	/* Following test should fail using norms from first test */
	// failed += _ppp_testcase_statistical(&s, 88, 16, 500000);

	printf("Character count stats:\n");
	failed += _ppp_testcase_stat_2(&s, 88, 16, stat_tests);

	printf("*** PPPv3 compatibility tests\n");
	printf("* Sequence key = 0.\n");
	memset(s.sequence_key, 0, sizeof(s.sequence_key));
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
	s.alphabet = 2;
	_PPP_TEST(0, 4, 'A', 1, "7OPJ");
	_PPP_TEST(34, 4, 'G', 5, "Y7CB");
	_PPP_TEST(864197393UL+50UL, 4, 'E', 8, "=sb;");
	s.alphabet = 1;

	printf("*** Another sequence key tests:\n");
	/*** Tests with other sequence_key ***/
	const unsigned char ex2_bin[32] = {
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
	memcpy(s.sequence_key, ex2_bin, sizeof(s.sequence_key));

	printf("New key: ");
	crypto_print_hex(s.sequence_key, 32);
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
	s.alphabet = 2;
	printf("Second alphabet\n");
	_PPP_TEST(0, 7, 'A', 1, "Y*HJ;,(");
	_PPP_TEST(70+34, 7, 'A', 7, "Ao_\"e82");
	_PPP_TEST(70+36, 7, 'C', 7, "(&JV?E_");

	state_fini(&s);

	/* Authenticate testcase */
	/* Create file with empty key */
	if (state_init(&s, current_user) != 0) {
		printf("ERROR WHILE CREATING TEST KEY\n");
		failed++;
		free(current_user);
		return failed;
	}
	state_lock(&s);
	state_store(&s, 0);
	state_unlock(&s);
	state_fini(&s);

	printf("Should succeed:\n");
	if (_ppp_testcase_authenticate("NH7j") == 0) { /* Check if returned true */
		failed++;
	}
	printf("Should NOT succeed:\n");
	if (_ppp_testcase_authenticate("aSsD") != 0) {
		failed++;
	}

	free(current_user);
	return failed;
}

int config_testcase(void)
{
	cfg_t *cfg;
	
	cfg = cfg_get();
	if (!cfg) {
		printf("Can't read config - Queer.\n");
		return 1;
	} else 
		return 0;
}


int num_testcase(int fast)
{
	int failed = 0;
	int passes = (fast == 0) ? 100000 : 20;

#if !USE_GMP
	const uint64_t max64 = 18446744073709551615LLU;
	const num_t max128 = num_ii(max64, max64);
	char buff[42];

	num_t a, b, c, d;
	uint64_t r, bi = 0;
	int i;
	printf("*** Num testcase. (Testcasing internal 128bit implementation).\n");

	printf("* Shift test: ");
	a = num_i(1);
	for (i=0; i<127; i++) {
		a = num_lshift(a);
	}

	for (i=0; i<127; i++) {
		a = num_rshift(a);
	}

	if (num_cmp_i(a, 1) != 0) {
		failed++;
		printf("FAILED\n");
	} else 
		printf("OK\n");

	printf("* Hex conv test: ");
	i = num_import(&a, "00000000000000010000000000000023", NUM_FORMAT_HEX);
	assert(i == 0);
	if (a.hi != 1 && a.lo != 0x23) {
		printf("FAILED_IMP1 "); failed++;
	} else printf("OK ");

	/* Twice 16327946327849612384 = e29884ad0f1eb460e29884ad0f1eb460 */
	i = num_import(&a, "E29884AD0F1EB460E29884AD0F1EB460", NUM_FORMAT_HEX);
	assert(i == 0);
	if (a.hi != 0xE29884AD0F1EB460ULL || a.lo != 0xE29884AD0F1EB460ULL) {
		printf("FAILED_IMP2 "); failed++;
	} else printf("OK ");

	a = num_ii(0x08, 0xE0);
	i = num_export(a, buff, NUM_FORMAT_HEX);
	assert(i==0);
	if (strcmp(buff, "000000000000000800000000000000E0") != 0) {
		printf("FAILED_HEX2 "); failed++;
	} else printf("OK ");

	/* Exports: bin, hex, ppp_hex, dec */
	i = num_import(&a, "112233445566778899AABBCCDDEEFF00", NUM_FORMAT_HEX);
	assert(i == 0);
	i = num_export(a, buff, NUM_FORMAT_BIN);
	assert(i == 0);
	if (memcmp(buff,   "\x00\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11", 16) != 0) {
		printf("FAILED_BIN "); failed++;
	} else printf("OK ");

	i = num_export(a, buff, NUM_FORMAT_HEX);
	assert(i==0);
	if (strcmp(buff, "112233445566778899AABBCCDDEEFF00") != 0) {
		printf("FAILED_HEX "); failed++;
	} else printf("OK ");

	i = num_export(a, buff, NUM_FORMAT_PPP_HEX); 
	assert(i==0);
	if (strcmp(buff, "00FFEEDDCCBBAA998877665544332211") != 0) {
		printf("FAILED_HEX "); failed++;
	} else printf("OK ");


	i = num_export(a, buff, NUM_FORMAT_DEC); 
	assert(i==0);
	if (strcmp(buff, "22774453838368691933757882222884355840") != 0) {
		printf("FAILED_DEC (%s)", buff); failed++;
	} else printf("OK ");

	i = num_import(&b, "22774453838368691933757882222884355840", NUM_FORMAT_DEC);
	assert(i==0);
	if (num_cmp(a, b) != 0) {
		printf("FAILED_DEC_IMP "); failed++;
	} else printf("OK ");

	/* Should "fail": */
	i = num_import(&a, "", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_import(&a, "0 ", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	i = num_import(&a, "FG", NUM_FORMAT_HEX);
	if (i == 0) {
		printf("FAILED"); failed++;
	} else printf("OK ");
	
	printf("\n");


	/* GMP Compatibility test */
	printf("* GMP Compatibility: ");
	const int bytes = 16;

	memset(buff, 0, bytes);
	buff[10] = 0xAB;

	num_import(&a, (char *)buff, NUM_FORMAT_BIN);
	if (memcmp(buff,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00", 16) != 0) {
		printf("FAILED ");
		failed++;
	} else
		printf("OK ");

	memset(buff, 0x80, bytes);
	buff[0] = 0xAA;
	buff[bytes-1] = 0xFF;

	num_import(&a, (char *)buff, NUM_FORMAT_BIN);
	num_export(a, buff, NUM_FORMAT_DEC);
	if (strcmp(buff,
	           "339620359252449505361967613327236432042"
		    ) != 0) {
		printf("FAILED ");
		failed++;
	} else
		printf("OK ");

	/* Backward conversion of previous pattern */
	memcpy(buff, "somegarbagesomegarbagesomegarbage", 16);
	num_export(a, (char *)buff, NUM_FORMAT_BIN);

	if (memcmp(buff,
		   "\xaa\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\xff", 16) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("OK\n");



	/* Addition */
	printf("* Addition: ");

	a = num_i(max64);
	b = num_i(1);
	c = num_add(a, b);
	if (a.hi != 0 || c.hi != 1 || c.lo != 0 || b.hi != 0 || b.lo != 1) {
		printf("FAILED "); failed++;
	} else printf("OK ");
	d = num_sub(c, b);
	if (a.lo != d.lo || a.hi != d.hi || num_cmp(a, d) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	a = max128;
	b = max128;
	c = num_sub(a, b);
	if (num_cmp_i(c, 0) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	if (num_cmp(a, b) != 0 || num_cmp(a, c) != 1 || num_cmp(c, a) != -1) {
		printf("FAILED "); failed++;
	} else printf("OK ");

	b = num_i(max64);
	d = num_i(65784365938ULL);
	c = num_sub(a, d); 
	c = num_sub(c, b); 
	c = num_add(d, c);
	c = num_add(b, c);

	/* 340282366920938463463374607431768211455 - 18446744073709551615
	 * = 340282366920938463444927863358058659840 */
	if (num_cmp(c, a) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");


	/* Calculate high fibonacci */
	a = num_i(1);
	b = num_i(1);
	for (i=0; i<184; i++) {
		c = num_add(a, b);
		a = b;
		b = c;
	}

	/* 2^128     = 340282366920938463463374607431768211456L
	 * fibo(184) = 332825110087067562321196029789634457848 
	 * = FA63... */
	i = num_import(&a, "FA63C8D9FA216A8FC8A7213B333270F8", NUM_FORMAT_HEX);
	assert(i==0);

	if (num_cmp(b, a) != 0) {
		printf("FAILED "); failed++;
	} else printf("OK ");
 
	printf("\n");

	printf("* Multiplication/Division: ");
	fflush(stdout);

	/* A / B = C, r
	 * B * C + r = A
	 */
	a = num_i(18446744073709551615ULL);
	bi = 7;
	r = num_div_i(&c, a, bi);
	if (num_cmp(c, num_i(2635249153387078802ULL)) != 0 || r != 1) {
		printf("FAILED_DIV1 "); failed++;
	} else printf("OK_DIV1 ");

	c = num_mul_i(c, bi);
	c = num_add(c, num_i(r));
	if (num_cmp(c, a) != 0) {
		printf("FAILED_MUL1 "); failed++;
	} else printf("OK_MUL1 ");
	
	i = num_import(&a, "18446744073709551616", NUM_FORMAT_DEC);
	assert(i==0);
	bi = 9;
	r = num_div_i(&c, a, bi);

	if (num_cmp(c, num_i(2049638230412172401ULL)) != 0 || r != 7) {
		printf("FAILED_DIV2 "); failed++;
	} else printf("OK_DIV2 ");

	c = num_mul_i(c, bi);
	c = num_add(c, num_i(r));
	if (num_cmp(c, a) != 0) {
		printf("FAILED_MUL2 "); failed++;
	} else printf("OK_MUL2 ");

	/* TEST ON PARTICULAR VALUE */
	i = num_import(&a, "00000000000000010000000000000000", NUM_FORMAT_HEX);
	assert(i==0);
	bi = 0x8000008000000064ULL;
	r = num_div_i(&c, a, bi); //0x9000000000000000LLU);

	c = num_mul_i(c, bi);
	c = num_add(c, num_i(r));
	if (num_cmp(c, a) != 0) {
		printf("FAILED_MUL0 "); failed++;
	} else printf("OK ");

	i = num_import(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", NUM_FORMAT_HEX);
	assert(i==0);
	              bi = 0xFFFFFFFFFFFFFFFFULL;
	r = num_div_i(&c, a, bi);

	c = num_mul_i(c, bi);
	c = num_add(c, num_i(r));
	if (num_cmp(c, a) != 0) {
		printf("FAILED_MUL3 "); failed++;
	} else printf("OK ");

	/* DIVISION / MULTIPLICATION LOOP */
	i = num_import(&a, "EFABBBCCCDDEDEDED543543542385FFA", NUM_FORMAT_HEX);
	assert(i==0);
	fflush(stdout);
	for (i = 1; i < passes; i+=3) {
		bi = 0xFAEFBB * i + i;
		r = num_div_i(&c, a, bi);

		c = num_mul_i(c, bi);
		c = num_add(c, num_i(r));

		if (num_cmp(c, a) != 0) {
			failed++;
			printf("\nFAILED for %llu %llx\n",  (unsigned long long)bi, (unsigned long long int)bi);
			printf("MUL Result: hi=%llu lo=%llu\n\n", (unsigned long long)c.hi, (unsigned long long)c.lo);
			break;
		} 

		if (i % 20) {
			a = num_add(a, num_ii(0x117A3 * i + 0x12bd9264a662ULL , i * 0xFABCDEF02134ULL));
		}
	}

	if (i >= 30000) 
		printf("OK\n");

#else

	unsigned char num[16];
	num_t tmp_num;
	char result[45];

	/* Initialize num with garbage */
	mpz_init(tmp_num);
	mpz_set_d(tmp_num, 0xdeadbabe); 

	const int bytes = sizeof(num);

	/* Input: All 0, but one byte */
	memset(num, 0, bytes);
	num[10] = 0xAB;

	num_import(&tmp_num, (char *)num, NUM_FORMAT_BIN);
	printf("num_testcase [ 0]: ");
	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00", 16) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");

	/* Backward conversion of previous pattern */
  	memcpy(num, "somegarbagesomegarbagesomegarbage", bytes);
	num_export(tmp_num, (char *)num, NUM_FORMAT_BIN);
	printf("num_testcase [ 1]: ");

	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00", 16) != 0) {
		printf(" FAILED\n");
		failed++;
	} else
		printf("PASSED\n");

	/* 0xAA, filled with 0x80, then 0xFF = 
	 * 0xFF8080808080808080808080808080AA  */

	memset(num, 0x80, bytes);
	num[0] = 0xAA;
	num[bytes-1] = 0xFF;

	num_import(&tmp_num, (char *)num, NUM_FORMAT_BIN);
	num_export(tmp_num, result, NUM_FORMAT_DEC);

	printf("num_testcase [ 2]: ");
	if (strcmp(result,
	           "339620359252449505361967613327236432042"
		    ) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");

	/* Backward conversion of previous pattern */
	memcpy(num, "somegarbagesomegarbagesomegarbage", 16);
	num_export(tmp_num, (char *)num, NUM_FORMAT_BIN);
	printf("num_testcase [ 3]: ");

	if (memcmp(num,
		   "\xaa\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\xff", 16) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	
	num_clear(tmp_num);

#endif
	return failed;
}

