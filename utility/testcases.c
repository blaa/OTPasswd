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

#include "testcases.h"

#define PPP_INTERNAL 1
#include "num.h"
#include "crypto.h"
#include "state.h"
#include "ppp.h"
#include "passcards.h"

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
		failed++;
	} else {
		printf("PASSED\n");		
	}

	printf("crypto_aes_test [ 2]: ");
	for (i = 0; i < 10; i++) {
		crypto_rng(plain, 16, 0);
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

	return failed;
}

int num_testcase(void)
{
	int failed = 0;
	unsigned char num[32];
	mpz_t tmp_num;
	char *result;

	mpz_init(tmp_num);

	const int bytes = sizeof(num);
	/* All 0, but one byte */
	memset(num, 0, bytes);
	num[10] = 0xAB;

	mpz_set_d(tmp_num, 0xdeadbabe); /* Initialize with garbage */

	num_from_bin(tmp_num, num, bytes);
	result = mpz_get_str(NULL, 16, tmp_num);
	printf("num_testcase [ 0]: ");
	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		   "\x00\x00\x00\x00", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
  	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 1]: ");

	if (memcmp(num,
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xAB\x00\x00\x00"
		   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		   "\x00\x00\x00\x00", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");


	/* 0xAA, filled with 0x80, then 0xFF  */
	memset(num, 0x80, bytes);
	num[0] = 0xAA;
	num[bytes-1] = 0xFF;

	num_from_bin(tmp_num, num, bytes);
	result = mpz_get_str(NULL, 10, tmp_num);

	printf("num_testcase [ 2]: ");
	if (strcmp(result,
		   "1155668197009629607909301529759657"
		   "36218812795816796563554883271612554597662890"
		    ) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	free(result);

	/* Backward conversion of previous pattern */
	memcpy(num, "somegarbagesomegarbagesomegarbage", 32);
	num_to_bin(tmp_num, num, bytes);
	printf("num_testcase [ 3]: ");

	if (memcmp(num,
		   "\xaa\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
		   "\x80\x80\x80\xff", 32) != 0) {
		printf("FAILED\n");
		failed++;
	} else
		printf("PASSED\n");
	
	mpz_clear(tmp_num);
	return failed;
}

/***************************
 * Passcards testcases
 **************************/
int card_testcase(void)
{
	unsigned char hash[32];
	char *card;
	state s;
	mpz_t cnt;
	int test = 0;
	int failed = 0;

	mpz_init(cnt);
	state_init(&s, NULL, ".otpasswd_testcase");
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

/***************************
 * State Testcases
 **************************/
int state_testcase(void)
{
	state s1, s2;
	int failed = 0;
	int test = 0;

	if (state_init(&s1, NULL, ".otpasswd_testcase") != 0)
		printf("state_testcase[%2d] failed (%d)\n", test, failed++);

	test++; if (state_init(&s2, NULL, ".otpasswd_testcase") != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (state_key_generate(&s1, 0) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);
	mpz_set_ui(s1.counter, 321323211UL);

	test++; if (state_store(&s1) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (state_load(&s2) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	/* Compare */
	test++; if (mpz_cmp(s1.sequence_key, s2.sequence_key) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (mpz_cmp(s1.counter, s2.counter) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (mpz_cmp(s1.latest_card, s2.latest_card) != 0)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);

	test++; if (s1.flags != s2.flags || s1.code_length != s2.code_length)
		printf("state_testcase[%2d] failed(%d)\n", test, failed++);


	printf("state_testcases %d FAILED %d PASSED\n", failed, test-failed);

	state_fini(&s1);
	state_fini(&s2);

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
	int failed = 0;

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

	/* Initialize state with given username, and default config file */
	if (state_init(&s, NULL, ".otpasswd_testcase") != 0) {
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
	failed += _ppp_testcase_statistical(&s, 64, 16, 200000);

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
