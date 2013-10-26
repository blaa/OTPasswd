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
#include <errno.h>

#include "nls.h"
#include "print.h"
#include "ppp_common.h"
#include "num.h"
#include "agent_interface.h"


char *card_ascii(agent *a, const num_t passcard)
{
	int ret;

	const char columns[] = "ABCDEFGHIJKLMNOP";
	const int whitespace = 1;
	const int label_max = STATE_LABEL_SIZE;	/* Maximal length of label */
	const int num_min = 8;			/* Minimal size for number on card */

	char *card = NULL;
	char whole_card_num[50];
	int card_num_len;
	int label_len;
	char *printed_card_num = NULL;
	int i;

	/***
	 * Read require state data
	 ***/
	char *label = NULL;
	int code_length;

	num_t tmp = num_i(0);
	char *whole_card = NULL;
	num_t code_num;

	/* Get code length */
	if ((ret = agent_get_int(a, PPP_FIELD_CODE_LENGTH, &code_length)) != 0) {
		print(PRINT_ERROR, _("Unable to read code length: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto error;
	}

	/* Calculate what you can */
	const int codes_in_row = ppp_get_codes_per_row(code_length);
	const int codes_on_card = codes_in_row * ROWS_PER_CARD;

	const int width = (whitespace + code_length) * codes_in_row + 3;
	const int size = (width + 1) * (ROWS_PER_CARD + 2) + 1;
	const int label_len_max = width - num_min;

	/* Allocate memory */
	whole_card = malloc(size);
	if (whole_card == NULL) {
		if (errno == ENOMEM) {
			printf(_("You've run out of memory. Unable to print passcards\n"));
		} else
			perror("malloc");
		return NULL;
	}

	memset(whole_card, 0, size);

	card = whole_card;

	memset(card, ' ', size);

	/* Determine a label */
	if ((ret = agent_get_str(a, PPP_FIELD_LABEL, &label)) != 0) {
		print(PRINT_ERROR, _("Unable to read label: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto error;
	}
	
	if (label && strlen(label) > 0) {
		/* Ok, we will use this one */
	} else {
		/* Read hostname */
		if (label)
			free(label);

		label = malloc(label_max + 1);
		gethostname(label, label_max);
		label[label_max] = '\0'; /* Ensure string is null-terminated */

	}

	label_len = strlen(label);

	/* Get card number */
	tmp = passcard;
	
	num_export(tmp, whole_card_num, NUM_FORMAT_DEC);
	num_clear(tmp);
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
		card += code_length + whitespace;

	} while (i < codes_in_row);
	card -= whitespace - 1;
	*(card-1) = '\n';

	/* Passcodes */
	code_num = num_sub_i(passcard, 1);
	code_num = num_mul_i(code_num, codes_on_card);

	for (i = 1; i < 1 + ROWS_PER_CARD; i++) {
		int y;
		sprintf(card, "%2d: ", i);
		card += 4;
		for (y=0; y < codes_in_row; y++) {
			char passcode[17];
			ret = agent_get_passcode(a, code_num, passcode);
			switch (ret) {
			case AGENT_ERR_POLICY:
				printf(_("Passcode printing is denied by policy.\n"));
				goto error;
			default:
				print(PRINT_ERROR, _("Unable to read passcode: %s\n"), 
				      agent_strerror(ret));
				goto error;

			case 0:
				break;
			}

			memcpy(card, passcode, code_length);
			if (y + 1 != codes_in_row) {
				card += code_length + whitespace;
			} else {
				card += code_length;
				*card = '\n';
				card++;
			}
			code_num = num_add_i(code_num, 1);
		}
	}
	num_clear(code_num);

	free(label);

	whole_card[size-1] = '\0';
	return whole_card;

error:
	if (label)
		free(label);
	if (whole_card)
		free(whole_card);

	return NULL;
}

char *card_latex(agent *a, const num_t number)
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
	char *whole_card;
	char *card_pos;
	num_t max_card;
	int ret;

	errno = 0;

	/* Verify that we can print 6 passcards from this number.
	 * max_card - 6 must be >= number */
	if ((ret = agent_get_num(a, PPP_FIELD_MAX_CARD, &max_card)) != 0) {
		printf(_("Unable to read maximal card number: %s\n"), agent_strerror(ret));
		return NULL;
	}

	max_card = num_sub_i(max_card, 5);

	if (num_cmp(number, max_card) > 0) {
		printf(_("Given passcard out of valid range. Unable to print 6 passcards.\n"));
		return NULL;
	}

	whole_card = malloc(size);
	card_pos = whole_card;
	if (!whole_card)
		goto error;
	memset(whole_card, 0, size);



	memcpy(card_pos, intro, sizeof(intro) - 1);
	card_pos += sizeof(intro) - 1;

	memcpy(card_pos, block_start, sizeof(block_start) - 1);
	card_pos += sizeof(block_start) - 1;

	for (i=0; i<=2; i++) {
		const num_t n = num_add_i(number, i);
		char *part = card_ascii(a, n);
		if (!part)
			goto error;
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
		const num_t n = num_add_i(number, i);

		char *part = card_ascii(a, n);
		if (!part)
			goto error;
		memcpy(card_pos, part, strlen(part));
		card_pos += strlen(part);
		free(part);

		if (i != 5) {
			memcpy(card_pos, "\n", 1);
			card_pos += 1;
		}
	}

	memcpy(card_pos, block_stop, sizeof(block_stop) - 1);
	card_pos += sizeof(block_stop) - 1;

	memcpy(card_pos, outro, sizeof(outro) - 1);
	/* card_pos += sizeof(outro) - 1; */

	return whole_card;
error:
	free(whole_card);
	if (errno == ENOMEM) {
		printf(_("You've run out of memory. Unable to print passcards\n"));
	}
	return NULL;
}
