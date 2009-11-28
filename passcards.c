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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>

#include "num.h"
#include "crypto.h"
#include "ppp.h"
#include "state.h"
#include "passcards.h"

/*
Cirrus                             [1]
    A    B    C    D    E    F    G
 1: jsa? EYKb s@#+ cCri aH?r RnDD hBy@
 2: +R2o Smx= rY#d gGvE fU5w 7u#h VyL:
 3: TiAP grLz vtEs f2W= 5R#F PMWz q6#?
 4: 9YBX %oL7 jAWs otr% ek+c NwJs hGG3
 5: AVe5 !eg+ 9o6q YMnb 4dGZ rqR3 EDv+
 6: Rqec KXgx tNed W3q3 KXcr nCKr szKA
 7: e%V@ cxEh Zvh5 jiVZ #seN iRu3 xD:X
 8: AKN9 LHcD T@g2 Tzjr 6b?R =FeZ qHZ#
 9: E4uo nNKE ?yi+ mZ#R =3F6 jJnv yyje
10: J5:X 3eWT GGdC JN4m oSbX r=vE Pnso
----    -----
  4     len+1
*/

char *card_ascii(const state *s, mpz_t number)
{
	const char columns[] = "ABCDEFGHIJKLMNOP";
	const int whitespace = 2;
	const int label_max = STATE_LABEL_SIZE;	/* Maximal length of label */
	const int num_min = 8;			/* Minimal size for number on card */
	
	char *label, *whole_card_num, *printed_card_num;
	int label_len, card_num_len;
	int i;

	assert(s->code_length > 1 && s->code_length < 17);
	assert(s->codes_in_row >= 2 && s->codes_on_card > 10);

	/* Calculate what you can */
	const int width = (whitespace + s->code_length) * s->codes_in_row + 3;
	const int size = (width + 1) * (10 + 2) + 1;
	const int label_len_max = width - num_min;

	/* Allocate memory */
	char *whole_card = malloc(size);
	if (!whole_card)
		return NULL;

	char *card = whole_card;

	memset(card, ' ', size);


	/* Determine a label */
	label_len = strlen(s->label);
	if (label_len > 0) {
		label = strdup(s->label);
	} else {
		/* Read hostname */
		label = malloc(label_max + 1);
		gethostname(label, label_max);
		label[label_max] = '\0'; /* Ensure string is null-terminated */
		label_len = strlen(label);
	}

	/* Get card number */
	whole_card_num = mpz_get_str(NULL, 10, number);
	printed_card_num = whole_card_num;

	card_num_len = strlen(whole_card_num);

	/* We limit label only if there's no place for num */
	if (label_len > label_len_max) {
		label_len = label_len_max;
		label[label_len] = '\0';
		label[label_len - 1] = '.';
		label[label_len - 2] = '.';
		label[label_len - 3] = '.';
	}

	if (card_num_len + 3 + label_len > width) {
		/* We must cut num */
		const int place = width - 3 - label_len;
		printed_card_num = whole_card_num + (card_num_len - place);
		*printed_card_num = '*';
		card_num_len = place;
	}

	memcpy(card, label, label_len);
	card += width - card_num_len - 2;
	*card++ = '[';
	memcpy(card, printed_card_num, card_num_len);
	card += card_num_len;
	*card++ = ']';
	*card++ = '\n';

	/* Columns description */
	card += 4;
	i = 0;
	do {
		*card = columns[i];
		i++;
		card += s->code_length + whitespace;

	} while (i < s->codes_in_row);
	card -= whitespace - 1;
	*(card-1) = '\n';	

	/* Passcodes */
	mpz_t code_num;
	mpz_init(code_num);
	mpz_set(code_num, number);
	mpz_mul_ui(code_num, code_num, s->codes_on_card);

	for (i = 1; i < 1 + ROWS_PER_CARD; i++) {
		sprintf(card, "%2d: ", i);
		card += 4;
		int y;
		for (y=0; y < s->codes_in_row; y++) {
			char passcode[17];
			ppp_get_passcode(s, code_num, passcode);
			memcpy(card, passcode, s->code_length);
			if (y + 1 != s->codes_in_row) {
				card += s->code_length + whitespace;
			} else {
				card += s->code_length;
				*card = '\n';
				card++;
			}
			mpz_add_ui(code_num, code_num, 1);
		}
	}
	num_dispose(code_num);

	free(label);
	free(whole_card_num);

	whole_card[size-1] = '\0';
	return whole_card;
}

void card_testcase(void) 
{
	unsigned char hash[32];
	char *card; 
	state s;
	mpz_t cnt;
	int test = 0;
	int failed = 0;

	mpz_init(cnt);
	state_init(&s);
	strcpy(s.label, "hostname long");

	const unsigned char hash1[] = 
		"\xEA\xBC\x42\xC2\x4A\xCB\xCB\xD1\xB7\x58\xA9\x2C"
		"\x3D\xE3\xF2\x43\x9A\x4B\xCD\xF4\x2A\xFB\x8C\x1A"
		"\xB8\xB0\x3A\x04\xF7\x28\x97\x6A";

	const unsigned char hash2[] = 
		"\x28\xAD\xC8\xC7\x82\xE0\x35\xE6\xD0\x7F\xBC\x28"
		"\x15\xDD\x27\x56\xB6\x5C\x59\xAA\x3A\xE7\x35\xC5"
		"\x94\xFD\x42\x85\xA0\x6E\x25\x38";

	/* Test 1 */
	test++;
	s.code_length = 10;
	ppp_calculate(&s);

	mpz_set_ui(cnt, 254323245UL);
	mpz_mul_ui(cnt, cnt, 21234887UL);
	mpz_mul_ui(cnt, cnt, 21234565UL); 
	mpz_mul_ui(cnt, cnt, 21234546UL); 
	
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
}


char *card_latex(const state *s, mpz_t number)
{
	return NULL; 
}
