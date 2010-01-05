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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>

#define PPP_INTERNAL 1
#include "ppp.h"
#include "print.h"
#include "num.h"
#include "crypto.h"
#include "passcards.h"

char *card_ascii(const state *s, const mpz_t passcard)
{
	const char columns[] = "ABCDEFGHIJKLMNOP";
	const int whitespace = 1;
	const int label_max = STATE_LABEL_SIZE;	/* Maximal length of label */
	const int num_min = 8;			/* Minimal size for number on card */

	char *label, *whole_card_num, *printed_card_num;
	int label_len, card_num_len;
	int i;

	print(PRINT_NOTICE, "Printing passcard number %s\n", print_mpz(passcard, 10));

	assert(s->code_length > 1 && s->code_length < 17);
	assert(s->codes_in_row >= 2 && s->codes_on_card > 10);

	/* Calculate what you can */
	const int width = (whitespace + s->code_length) * s->codes_in_row + 3;
	const int size = (width + 1) * (ROWS_PER_CARD + 2) + 1;
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
	mpz_t tmp;
	mpz_init_set(tmp, passcard);

	whole_card_num = mpz_get_str(NULL, 10, tmp);
	mpz_clear(tmp);
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
	mpz_sub_ui(code_num, passcard, 1);
	mpz_mul_ui(code_num, code_num, s->codes_on_card);

	ppp_add_salt(s, code_num);

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
	mpz_clear(code_num);

	free(label);
	free(whole_card_num);

	whole_card[size-1] = '\0';
	return whole_card;
}

char *card_latex(const state *s, const mpz_t number)
{
	const char intro[] =
		"\\documentclass[11pt,twocolumn,a4paper]{article}\n"
		"\\usepackage{fullpage}\n"
		"\\pagestyle{empty}\n"
		"\\begin{document}\n";

	const char block_start[] =
		"\\begin{verbatim}\n";

	const char block_stop[] =
		"\\end{verbatim}\n"
		"\\newpage";

	const char outro[] =
		"\\end{document}\n";

	int i;
	int size = 
		sizeof(intro) + sizeof(outro) +
		sizeof(block_start)*2 + sizeof(block_stop) * 2 +
		(60 * ROWS_PER_CARD) * 6;
	char *whole_card = malloc(size);
	char *card_pos = whole_card;
	
	if (!whole_card)
		return NULL;
	memset(whole_card, 0, size);

	mpz_t n;
	mpz_init(n);

	memcpy(card_pos, intro, sizeof(intro) - 1);
	card_pos += sizeof(intro) - 1;

	memcpy(card_pos, block_start, sizeof(block_start) - 1);
	card_pos += sizeof(block_start) - 1;
	for (i=0; i<=2; i++) {
		mpz_add_ui(n, number, i);
		char *part = card_ascii(s, n);
		memcpy(card_pos, part, strlen(part));
		card_pos += strlen(part);
		free(part);

		if (i != 2) {
			memcpy(card_pos, "\n", 1);
			card_pos += 1;
		} 
	}
	memcpy(card_pos, "\n\n", 2);
	card_pos += 2;

	memcpy(card_pos, block_stop, sizeof(block_stop) - 1);
	card_pos += sizeof(block_stop) - 1;

	memcpy(card_pos, block_start, sizeof(block_start) - 1);
	card_pos += sizeof(block_start) - 1;
	for (i=3; i<=5; i++) {
		mpz_add_ui(n, number, i);

		char *part = card_ascii(s, n);
		memcpy(card_pos, part, strlen(part));
		card_pos += strlen(part);
		free(part);

		if (i != 5) {
			memcpy(card_pos, "\n", 1);
			card_pos += 1;
		}
	}

	mpz_clear(n);

	memcpy(card_pos, block_stop, sizeof(block_stop) - 1);
	card_pos += sizeof(block_stop) - 1;

	memcpy(card_pos, outro, sizeof(outro) - 1);
	card_pos += sizeof(outro) - 1;

	return whole_card;
}

