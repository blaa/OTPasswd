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
#include <ctype.h>
#include <gmp.h>

#include <assert.h>

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "ppp.h"
#include "state.h"
#include "passcards.h"

#include "otpasswd_actions.h"

/* Ask a question; return 0 only if "yes" was written, 1 otherwise */
static int _yes_or_no(const char *msg)
{
	char buf[20];

	printf("%s (yes/no): ", msg);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		/* End of file? */
		printf("\n");
		return 1;
	}

	if (strcasecmp(buf, "yes\n") == 0) {
		printf("\n");
		return 0;
	}

	return 1;
}

static int is_passcard_in_range(const state *s, const mpz_t passcard)
{
	/* 1..max_passcode/codes_on_passcard */
	if (mpz_cmp_ui(passcard, 1) < 0) {
		printf("Card numbering starts at 1\n");
		return 0; /* false */
	}

	if (mpz_cmp(passcard, s->max_card) > 0) {
		gmp_printf("Number of the last available passcard is %Zd\n", s->max_card);
		return 0;
	}

	return 1;
}

static int is_passcode_in_range(const state *s, const mpz_t passcard)
{
	/* 1..max_which_depends_on_salt and passcard configuration */
	if (mpz_cmp_ui(passcard, 1) < 0)
		return 0; /* false */

	if (mpz_cmp(passcard, s->max_code) > 0) {
		gmp_printf("Number of the last available passcode is %Zd\n", s->max_code);
		return 0;
	}

	return 1;
}

/* Authenticate; returns boolean; 1 - authenticated */
int action_authenticate(options_t *options)
{
	int retval = 0;

	/* OTP State */
	state s;

	if (state_init(&s, NULL, NULL) != 0) {
		/* This will fail if we're unable to locate home directory */
		print(PRINT_ERROR, "Unable to load state! Have you used -k option?\n");
		return 0; /* False - not authenticated */
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_load_increment(&s);
	switch (retval) {
	case 0:
		/* Everything fine */
		break;

	case STATE_NUMSPACE:
		printf("Counter overflowed. Regenerate key\n");
		retval = 0;
		goto cleanup;

	case STATE_DOESNT_EXISTS:
		retval = 0;
		goto cleanup;
		
	default: /* Any other problem - error */
		retval = 0;
		goto cleanup;
	}

	/* Generate prompt */
	ppp_calculate(&s);

	if (ppp_authenticate(&s, options->action_arg) == 0) {
		/* Correctly authenticated */
		retval = 1;
		goto cleanup;
	}

cleanup:
	if (retval)
		printf("Authentication successful.\n");
	else 
		printf("Authentication failed.\n");
		
	state_fini(&s);
	free(options->action_arg);
	return retval;
}

/* Generate new key */
void action_key(options_t *options)
{
	state s;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	/* Check existance of previous key */
	if (state_load(&s) == 0) {
		/* We loaded state correctly, key exists */
		if (_yes_or_no("This will erase irreversibly your previous key.\n"
			       "Are you sure you want to continue?") != 0) {
			printf("Stopping\n");
			exit(1);
		}
	}

	int salted = options->flag_set_mask & FLAG_NOT_SALTED ? 0 : 1;
	s.flags |= options->flag_set_mask;

	if (state_key_generate(&s, salted) != 0) {
		print(PRINT_ERROR, "Unable to generate new key\n");
		exit(1);
	}

	/* TODO: print first page in text */


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to %s file\n", s.filename);
		exit(1);
	}

	state_fini(&s);
}

void action_license(options_t *options)
{
	printf(
		"otpasswd -- One-time password manager and PAM module.\n"
		"Copyright (C) 2009 Tomasz bla Fortuna\n"
		"\n"
		"This program is free software: you can redistribute it and/or modify\n"
		"it under the terms of the GNU General Public License as published by\n"
		"the Free Software Foundation, either version 3 of the License, or\n"
		"(at your option) any later version.\n"
		"\n"
		"This program is distributed in the hope that it will be useful,\n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
		"GNU General Public License for more details.\n"
		"\n"
		"You should have received a copy of the GNU General Public License\n"
		"along with this program in a LICENSE file.\n"
	);
}

/* Update flags based on mask which are stored in options struct */
void action_flags(options_t *options)
{
	state s;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	/* Load our state */
	if (state_load(&s) != 0) {
		/* Unable to load state */
		print(PRINT_ERROR, "Error while reading state, have you created a key with -k option?\n");
		exit(1);
	}

	/* Change flags */
	s.flags |= options->flag_set_mask;
	s.flags &= ~(options->flag_clear_mask);

	if (options->set_codelength >= 2 && options->set_codelength <= 16)
		s.code_length = options->set_codelength;
	else if (options->set_codelength) {
		print(PRINT_ERROR, "Illegal passcode length specified\n");
		goto cleanup;
	}


	/* TODO: LOCK! */
	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to ~/" STATE_FILENAME " file\n");
		exit(1);
	}

	if (options->flag_set_mask || options->flag_clear_mask)
		printf("Flags updated, current configuration: ");
	else
		printf("Flags not changed, current configuration: ");
	if (s.flags & FLAG_SHOW)
		printf("show ");
	else
		printf("dont-show ");

	if (s.flags & FLAG_SKIP)
		printf("skip ");
	else
		printf("dont-skip ");

	if (s.flags & FLAG_ALPHABET_EXTENDED)
		printf("alphabet-extended ");
	else
		printf("alphabet-simple ");

	if (s.flags & FLAG_NOT_SALTED)
		printf("(no salt) ");
	else
		printf("(key salted) ");

	printf("codelength-%d\n", s.code_length);

cleanup:
	state_fini(&s);
}

void action_print(options_t *options)
{
	int ret;

	/* This action requires a created key */
	state s;
	int state_locked = 1;
	int state_changed = 0;
	if (state_init(&s, NULL, NULL) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	ret = state_lock(&s);
	if (ret != 0 && ret != STATE_DOESNT_EXISTS) {
		/* whoops! */
		print(PRINT_ERROR, "Unable to lock file! Unable to save"
		      " any changes back to file!\n");
		state_locked = 0;
	}

	/* Load our state */
	if (state_load(&s) != 0) {
		print(PRINT_ERROR, "Unable to load state file. Have you tried -k option?\n");
		goto cleanup;
	}

	/* Calculate current cards etc */
	ppp_calculate(&s);

	/* See if we have any counters left */
	int counter_correct = 1;
	ret = ppp_verify_range(&s);
	if (ret == 2) {
		/* State file corrupted */
		goto cleanup;
	}

	if (ret != 0)
		counter_correct = 0;

	/* Parse argument, we need card number + passcode number */
	int code_selected = 0;
	mpz_t passcard_num;
	mpz_t passcode_num;
	mpz_init(passcard_num);
	mpz_init(passcode_num);

	if (strcasecmp(options->action_arg, "current") == 0) {
		/* Current passcode */
		if (counter_correct == 0) {
			print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 1;
		mpz_set(passcode_num, s.counter);

	} else if (strcasecmp(options->action_arg, "next") == 0) {
		/* Next passcard */
		if (counter_correct == 0) {
			print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 0;
		mpz_add_ui(s.furthest_printed, s.furthest_printed, 1);
		mpz_set(passcard_num, s.furthest_printed);
		state_changed = 1;
	} else if (isalpha(options->action_arg[0])) {
		/* Format: CRR[number] */
		char column;
		int row;
		char number[41];
		ret = sscanf(options->action_arg, "%c%d[%40s]", &column, &row, number);
		column = toupper(column);
		if (ret != 3 || (column < 'A' || column > 'J')) {
			print(PRINT_ERROR, "Incorrect passcode specification. (%d)\n", ret);
			goto cleanup1;
		}

		ret = gmp_sscanf(number, "%Zu", passcard_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Incorrect passcard specification.\n");
			goto cleanup1;
		}

		if (!is_passcard_in_range(&s, passcard_num)) {
			print(PRINT_ERROR,
			      "Passcard number out of range. "
			      "First passcard has number 1.\n");
			goto cleanup1;
		}

		/* ppp_get_passcode_number adds salt as needed */
		ret = ppp_get_passcode_number(&s, passcard_num, passcode_num, column, row);
		if (ret != 0) {
			print(PRINT_ERROR, "Error while parsing passcard description.\n");
			goto cleanup1;
		}

		code_selected = 1;

	} else if (isdigit(options->action_arg[0])) {
		/* All characters must be a digit! */
		int i;
		for (i=0; options->action_arg[i]; i++) {
			if (!isdigit(options->action_arg[i])) {
				print(PRINT_ERROR, 
				      "Illegal passcode number!\n");
				goto cleanup1;
			}
		}


		/* number -- passcode number */
		ret = gmp_sscanf(options->action_arg, "%Zd", passcode_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Error while parsing passcode number.\n");
			goto cleanup1;
		}

		if (!is_passcode_in_range(&s, passcode_num)) {
			print(PRINT_ERROR, "Passcode number out of range.\n");
			goto cleanup1;
		}

		mpz_sub_ui(passcode_num, passcode_num, 1);

		/* Add salt and this number cames from user */
		ppp_add_salt(&s, passcode_num);

		code_selected = 1;
	} else if (options->action_arg[0] == '['
		   && options->action_arg[strlen(options->action_arg)-1] == ']') {
		/* [number] -- passcard number */
		ret = gmp_sscanf(options->action_arg, "[%Zd]", passcard_num);
		if (ret != 1) {
			print(PRINT_ERROR, "Error while parsing passcard number.\n");
			goto cleanup1;
		}

		if (!is_passcard_in_range(&s, passcard_num)) {
			print(PRINT_ERROR, "Passcard out of accessible range.\n");
			goto cleanup1;
		}

		code_selected = 0;
	} else {
		print(PRINT_ERROR, "Illegal argument passed to option.\n");
		goto cleanup1;
	}

	/* Print the thing requested */
	if (code_selected == 0) {
		char *card;
		switch (options->action) {
		case 't':
			card = card_ascii(&s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup1;
			}
			puts(card);
			free(card);
			break;

		case 'l':
			card = card_latex(&s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup1;
			}
			puts(card);
			free(card);
			break;

		case 's':
			if (counter_correct == 0) {
				print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}
			/* Skip to passcard... */
			ret = ppp_get_passcode_number(&s, passcard_num, passcode_num, 'A', 1);
			if (ret != 0) {
				print(PRINT_ERROR, "Error while generating destination passcode\n");
				goto cleanup1;
			}

			if (mpz_cmp(s.counter, passcode_num) > 0) {
				printf("WARNING: You should never skip "
				       "backwards to reuse your codes!\n");
			}

			printf("Skipped to specified passcard.\n");
			mpz_set(s.counter, passcode_num);
			state_changed = 1;
			break;
			
		case 'p':
			print(PRINT_ERROR, "Option requires passcode as argument\n");
			break;
		}
	} else {
		char passcode[17];
		const char *prompt;
		switch (options->action) {
		case 't':
			/* ppp_get_passcode wants internal
			 * passcodes (with salt) */
			ret = ppp_get_passcode(&s, passcode_num, passcode);
			if (ret != 0) {
				print(PRINT_ERROR, "Error while calculating passcode\n");
				goto cleanup1;
			}
			printf("%s\n", passcode);
			break;

		case 'l':
			print(PRINT_ERROR,
			      "LaTeX parameter works only with"
			      " passcard specification\n");
			break;

		case 's':
			if (counter_correct == 0) {
				print(PRINT_ERROR, "Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}
			/* Skip to passcode */
			if (mpz_cmp(s.counter, passcode_num) > 0) {
				printf("WARNING: You should never skip "
				       "backwards to reuse your codes!\n");
			}
			printf("Skipped to specified passcode.\n");
			mpz_set(s.counter, passcode_num);
			state_changed = 1;
			break;
			
		case 'p':
			/* Don't save state after this operation */
			mpz_set(s.counter, passcode_num);
			ppp_calculate(&s);
			prompt = ppp_get_prompt(&s);
			printf("%s\n", prompt);
			assert(state_changed == 0);
			break;
		}
	}

cleanup1:
	num_dispose(passcode_num);
	num_dispose(passcard_num);

cleanup:
	if (state_changed) {
		if (state_locked == 0)  {
			print(PRINT_NOTICE,  "NOT saving any changes since file is locked\n");
		} else {
			print(PRINT_NOTICE, "Saving changes to state file\n");
			if (state_store(&s) != 0) {
				print(PRINT_ERROR, "Error while saving changes!\n");
			}
		}
	}
	state_fini(&s);
	state_unlock(&s);
}


