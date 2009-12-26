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

#ifndef PROG_VERSION
#define PROG_VERSION "v0.5b"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>

#include <assert.h>

#include "print.h"
#include "crypto.h"
#include "num.h"
#include "config.h"

#define PPP_INTERNAL
#include "ppp.h"
#include "passcards.h"

#include "otpasswd_actions.h"

enum {
	QUERY_YES=0,
	QUERY_NO=2,
	QUERY_OBSCURE=1
};

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
		return QUERY_YES;
	} else if (strcasecmp(buf, "no\n") == 0) {
		return QUERY_NO;
	}

	/* Incomprehensible answer */
	return QUERY_OBSCURE;
}

static int _enforced_yes_or_no(const char *msg)
{
	int ret;
	do {
		ret = _yes_or_no(msg);
		if (ret == QUERY_OBSCURE) {
			printf("Please answer 'yes' or 'no'.\n");
			continue;
		}
	} while(ret != QUERY_YES && ret != QUERY_NO);
	return ret;
}

static int _is_passcard_in_range(const state *s, const mpz_t passcard)
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

static int _is_passcode_in_range(const state *s, const mpz_t passcard)
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

static void _show_flags(const state *s)
{
	if (s->flags & FLAG_SHOW)
		printf("show ");
	else
		printf("dont-show ");

	if (s->flags & FLAG_ALPHABET_EXTENDED)
		printf("alphabet-extended ");
	else
		printf("alphabet-simple ");

	printf("codelength-%d ", s->code_length);

	if (s->flags & FLAG_NOT_SALTED)
		printf("(no salt)\n");
	else
		printf("(key salted)\n");

	if (strlen(s->label) > 0) {
		printf("Passcard label='%s', ", s->label);
	} else {
		printf("No label, ");
	}

	if (strlen(s->contact) > 0) {
		printf("contact='%s'.\n", s->contact);
	} else {
		printf("no contact information.\n");
	}

	if (s->spass_set) {
		printf("Static password is set.\n");
	} else {
		printf("Static password is not set.\n");
	}
}

static void _show_keys(const state *s)
{
	assert(s->codes_on_card > 0);

	mpz_t unsalted_counter;
	mpz_init_set(unsalted_counter, s->counter);
	if (!(s->flags & FLAG_NOT_SALTED)) {
		mpz_and(unsalted_counter, unsalted_counter, s->code_mask);
	} 
	/* Convert to user numbering */
	mpz_add_ui(unsalted_counter, unsalted_counter, 1); 

	gmp_printf("Key     = %064ZX\n", s->sequence_key);
	gmp_printf("Counter = %032ZX\n", s->counter);
	gmp_printf("Current card        = %Zd\n", s->current_card);
	gmp_printf("Current code        = %Zd\n", unsalted_counter);
	gmp_printf("Latest printed card = %Zd\n", s->latest_card);
	gmp_printf("Max card            = %Zd\n", s->max_card);
	gmp_printf("Max code            = %Zd\n", s->max_code);

	mpz_clear(unsalted_counter);

}

/* Authenticate; returns boolean; 1 - authenticated */
int action_authenticate(options_t *options, const cfg_t *cfg)
{
	int retval = 0;

	/* OTP State */
	state s;

	if (state_init(&s, options->username) != 0) {
		/* This will fail if we're unable to locate home directory */
		print(PRINT_ERROR, "Unable to initialize state.\n");
		return 0; /* False - not authenticated */
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_increment(&s);
	switch (retval) {
	case 0:
		/* Everything fine */
		break;

	case STATE_NUMSPACE:
		printf("Authentication failed (Counter overflowed, regenerate key).\n");
		retval = 0;
		goto cleanup;

	case STATE_DOESNT_EXISTS:
		printf("Authentication failed (user doesn't have a key).\n");
		retval = 0;
		goto cleanup;
		
	default: /* Any other problem - error */
		printf("Authentication failed (error).\n");
		retval = 0;
		goto cleanup;
	}

	/* Generate prompt */
	ppp_calculate(&s);

	if (ppp_authenticate(&s, options->action_arg) == 0) {
		/* Correctly authenticated */
		printf("Authentication successful.\n");
		retval = 1;
		goto cleanup;
	}

cleanup:
	state_fini(&s);
	return retval;
}

/* Generate new key */
int action_key(options_t *options, const cfg_t *cfg)
{
	int retval = 1;

	if (cfg->allow_key_generation == 0) {
		// TODO; check if we can write to global db
		// if yes - ok, if not - diee.
	}


	int ret;
	state s;

	if (state_init(&s, options->username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}

	/* Check existance of previous key */
	if (state_load(&s) == 0) {
		/* We loaded state correctly, key exists */
		puts(
			"*****************************************************\n"
			"* This will irreversibly erase your previous key    *\n"
			"* making all already printed passcards worthless!   *\n"
			"*****************************************************\n"
		);

		if (_yes_or_no("Are you sure you want to continue?") != 0) {
			printf("Stopping\n");
			goto cleanup;
		}

		printf("Your current flags: ");
		_show_flags(&s);
		if (_enforced_yes_or_no(
			    "Do you want to keep them?") == QUERY_NO) {
			printf("Reverting to defaults.\n");
			state_fini(&s);
			state_init(&s, options->username);
		}
	} else {
		/* Failed load might have changed something in struct */
		state_fini(&s);
		state_init(&s, options->username);
	}

	s.flags |= options->flag_set_mask;

	int salted = 1;
	switch (cfg->allow_salt) {
	case 0: 
		salted = 0;
		break;
	case 2:
		salted = 1;
		break;
	default:
	case 1: 
		salted = options->flag_set_mask & FLAG_NOT_SALTED ? 0 : 1;
		break;
	}
	
	if (state_key_generate(&s, salted) != 0) {
		print(PRINT_ERROR, "Unable to generate new key\n");
		goto cleanup;
	}

	mpz_add_ui(s.latest_card, s.latest_card, 1);
	ppp_calculate(&s);
	puts(
		"\n"
		"*****************************************************\n"
		"* Print following passcard or at least make a note  *\n"
		"* with a few first passcodes so you won't loose     *\n"
		"* ability to log into your system!                  *\n"
		"*****************************************************\n"
	);
	char *card = card_ascii(&s, s.latest_card);
	puts(card);
	free(card);

	do {
		ret = _yes_or_no("Are you ready to start using one-time passwords?");
		if (ret == 1) {
			printf("Please answer 'yes' or 'no'.\n");
			continue;
		}
	} while(ret != 0 && ret != 2);

	if (ret != 0) {
		printf("Wiping out key. One-time passwords not enabled.\n");
		goto cleanup;
	}

	if (state_store(&s) != 0) {
		print(PRINT_ERROR, "Unable to save state to %s file\n", s.db_path);
		goto cleanup;
	}

	printf("Key stored! One-time passwords enabled for this account.\n");
	retval = 0;
	
cleanup:
	state_fini(&s);
	return retval;
}

int action_license(options_t *options, const cfg_t *cfg)
{
	printf(
		"otpasswd -- One-time password manager and PAM module.\n"
		"Version " PROG_VERSION "\n"
		"Copyright (C) 2009 Tomasz bla Fortuna <bla@thera.be>\n"
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
	return 0;
}

/* Update flags based on mask which are stored in options struct */
int action_flags(options_t *options, const cfg_t *cfg)
{
	int retval = 1;
	int ret, state_locked = 0;
	int state_changed = 0;
	state s;
	if (state_init(&s, options->username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		exit(1);
	}


	/* FIXME, TODO: Remove behaviour when locking fails
	 * but state_load is ok. It's rare, and state_load will fail
	 * also because it tries to lock */

	ret = state_lock(&s);
	if (ret != 0) {
		/* whoops! */
		print(PRINT_ERROR, "Unable to lock file! Unable to save"
		      " any changes back to file!\n");
	} else {
		state_locked = 1;
	}

	/* Load our state */
	ret = state_load(&s);
	if (ret == STATE_DOESNT_EXISTS) {
		/* Unable to load state */
		goto no_key_file;
	}

	if (ret != 0)
		goto cleanup;

	/* Calculate additional passcard info */
	ppp_calculate(&s);

	switch(options->action) {
	case 'f':
		/* Change flags */
		s.flags |= options->flag_set_mask;
		s.flags &= ~(options->flag_clear_mask);

		if (options->flag_set_mask || options->flag_clear_mask) {
			state_changed = 1;
		}

		if (options->set_codelength >= cfg->min_passcode_length &&
		    options->set_codelength <= cfg->max_passcode_length) {
			s.code_length = options->set_codelength;
			state_changed = 1;
		} else if (options->set_codelength) {
			printf("Illegal passcode length specified\n");
			goto cleanup;
		}
		break;
	case 'p':
	{
		const int len = strlen(options->action_arg);
		unsigned char sha_buf[32];
		if (len == 0) {
			s.spass_set = 0;
			mpz_set_ui(s.spass, 0);
			printf("Turning off static password.\n\n");
		} else {
			/* Change static password */
			/* TODO: Ensure its length/difficulty */
			crypto_sha256((unsigned char *)options->action_arg, len, sha_buf);
			num_from_bin(s.spass, sha_buf, sizeof(sha_buf));
			s.spass_set = 1;
			printf("Static password set.\n\n");
		}

		state_changed = 1;
		break;
	}
	case 'd':
		/* Change label */
		if (strlen(options->action_arg) + 1 > sizeof(s.label)) {
			printf("Label can't be longer than %zu characters\n", sizeof(s.label)-1);
			goto cleanup;
		}

		if (!state_validate_str(options->action_arg)) {
			printf(
			      "Contact contains illegal characters.\n"
			      "Alphanumeric + ' -+,.@_*' are allowed\n");
			goto cleanup;			
		}

		state_changed = 1;
		strcpy(s.label, options->action_arg);
		break;

	case 'c':
		/* Change contact info */
		if (strlen(options->action_arg) + 1 > sizeof(s.contact)) {
			printf("Contact can't be longer than %zu characters\n", sizeof(s.contact)-1);
			goto cleanup;
		}

		if (!state_validate_str(options->action_arg)) {
			printf(
			      "Contact contains illegal characters.\n"
			      "Alphanumeric + ' -+,.@_*' are allowed\n");
			goto cleanup;			
		}
		strcpy(s.contact, options->action_arg);
		state_changed = 1;
		break;

	case 'L': /* List */
		_show_keys(&s);
		printf("\nFlags:\n");
		_show_flags(&s);
		/* Omit saving */
		retval = 0;
		goto cleanup;

	default:
		printf("You should never end up here\n");
		assert(0);
	}


	if (state_locked == 1 && state_changed == 1) {
		print(PRINT_NOTICE, "Saving changes to state file\n");
		if (state_store(&s) != 0) {
			print(PRINT_ERROR, "Error while saving changes!\n");
			goto cleanup;
		} else 
			printf("Flags updated, current configuration:\n");
	} else {
		printf("Flags not changed, current configuration:\n");
	}
	
	_show_flags(&s);
	retval = 0;
	
cleanup:
	if (state_locked) {
		if (state_unlock(&s) != 0) {
			print(PRINT_ERROR, "Error while releasing lock!\n");
			retval = 1;
		}
	}

	state_fini(&s);
	return retval;

no_key_file:
	printf("Error while reading state, have you created a key with -k option?\n");
	return 2;
}

int action_print(options_t *options, const cfg_t *cfg)
{
	int retval = 1;
	int ret;

	/* This action requires a created key */
	state s;
	int state_locked = 0;
	int state_changed = 0;
	if (state_init(&s, options->username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		return 1;
	}

	ret = state_lock(&s);
	if (ret != 0) {
		/* whoops! */
		print(PRINT_ERROR, "Unable to lock file! Unable to save"
		      " any changes back to file!\n");
	} else {
		state_locked = 1;
	}

	/* Load our state */
	ret = state_load(&s);
	if (ret == STATE_DOESNT_EXISTS) {
		printf("Unable to load state file. Have you tried -k option?\n");
		goto cleanup;
	} else if (ret != 0) {
		printf("Error while reading state file!\n");
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

	/* Do we have to just show any warnings? */
	if (options->action == 'w') {
		int e = ppp_get_warning_condition(&s);
		const char *warn = ppp_get_warning_message(e);
		if (warn) {
			const char *format = "* OTP WARNING: %s *\n";
			/* Calculate length */
			int a, c = snprintf(NULL, 0, format, warn);
			/* Print boxed */
			a = c; while (--a) putchar('*'); putchar('\n');
			printf(format, warn);
			a = c; while (--a) putchar('*'); putchar('\n');
		}
		retval = 0;
		goto cleanup;
	}

	/* Parse argument, we need card number + passcode number */
	int code_selected = 0;
	mpz_t passcard_num;
	mpz_t passcode_num;
	mpz_init(passcard_num);
	mpz_init(passcode_num);

	if (strcasecmp(options->action_arg, "current") == 0) {
		/* Current passcode */
		if (counter_correct == 0) {
			printf("Passcode counter overflowed. "
			       "Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 1;
		mpz_set(passcode_num, s.counter);

	} else if (strcasecmp(options->action_arg, "next") == 0) {
		/* Next passcard. */
		if (counter_correct == 0) {
			printf( 
			      "Passcode counter overflowed. "
			      "Regenerate key.\n");
			goto cleanup1;
		}

		code_selected = 0;

		/* If current code is further than s->latest_card
		 * Then ignore this setting and start printing 
		 * from current_card */
		if (mpz_cmp(s.current_card, s.latest_card) > 0) {
			mpz_set(passcard_num, s.current_card);

			/* Increment by 1 or by 6 for LaTeX */
			if (options->action == 'l') {
				mpz_add_ui(s.latest_card, s.current_card, 5);
			} else {
				mpz_set(s.latest_card, s.current_card);
			}
		} else {
			mpz_add_ui(passcard_num, s.latest_card, 1);

			/* Increment by 1 or by 6 for LaTeX */
			mpz_add_ui(
				s.latest_card,
				s.latest_card,
				options->action == 't' ? 1 : 6);
		}

		state_changed = 1;
	} else if (isalpha(options->action_arg[0])) {
		/* Format: CRR[number] */
		char column;
		int row;
		char number[41];
		ret = sscanf(options->action_arg, "%c%d[%40s]", &column, &row, number);
		column = toupper(column);
		if (ret != 3 || (column < 'A' || column > 'J')) {
			printf("Incorrect passcode specification. (%d)\n", ret);
			goto cleanup1;
		}

		ret = gmp_sscanf(number, "%Zu", passcard_num);
		if (ret != 1) {
			printf("Incorrect passcard specification.\n");
			goto cleanup1;
		}

		if (!_is_passcard_in_range(&s, passcard_num)) {
			printf(
			      "Passcard number out of range. "
			      "First passcard has number 1.\n");
			goto cleanup1;
		}

		/* ppp_get_passcode_number adds salt as needed */
		ret = ppp_get_passcode_number(&s, passcard_num, passcode_num, column, row);
		if (ret != 0) {
			printf("Error while parsing passcard description.\n");
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
			printf("Error while parsing passcode number.\n");
			goto cleanup1;
		}

		if (!_is_passcode_in_range(&s, passcode_num)) {
			printf("Passcode number out of range.\n");
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
			printf("Error while parsing passcard number.\n");
			goto cleanup1;
		}

		if (!_is_passcard_in_range(&s, passcard_num)) {
			printf("Passcard out of accessible range.\n");
			goto cleanup1;
		}

		code_selected = 0;
	} else {
		printf("Illegal argument passed to option.\n");
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
				printf("Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}
			/* Skip to passcard... */
			ret = ppp_get_passcode_number(&s, passcard_num,
						      passcode_num, 'A', 1);
			if (ret != 0) {
				print(PRINT_ERROR, 
				      "Error while generating destination passcode\n");
				goto cleanup1;
			}

			if (mpz_cmp(s.counter, passcode_num) > 0) {
				printf(
					"**********************************\n"
					"* WARNING: You should never skip *\n"
					"* backwards to reuse your codes! *\n"
					"**********************************\n");
			}

			printf("Skipped to specified passcard.\n");
			mpz_set(s.counter, passcode_num);
			state_changed = 1;
			break;
			
		case 'P':
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
			printf(
			      "LaTeX parameter works only with"
			      " passcard specification\n");
			break;

		case 's':
			if (counter_correct == 0) {
				printf("Passcode counter overflowed. Regenerate key.\n");
				goto cleanup1;
			}
			/* Skip to passcode */
			if (mpz_cmp(s.counter, passcode_num) > 0) {
				printf(
					"**********************************\n"
					"* WARNING: You should never skip *\n"
					"* backwards to reuse your codes! *\n"
					"**********************************\n");
			}
			printf("Skipped to specified passcode.\n");
			mpz_set(s.counter, passcode_num);
			state_changed = 1;
			break;
			
		case 'P':
			/* Don't save state after this operation */
			mpz_set(s.counter, passcode_num);
			ppp_calculate(&s);
			prompt = ppp_get_prompt(&s);
			printf("%s\n", prompt);
			assert(state_changed == 0);
			break;
		}
	}

	retval = 0;
cleanup1:
	mpz_clear(passcode_num);
	mpz_clear(passcard_num);

cleanup:
	if (state_changed) {
		if (state_locked == 0)  {
			print(PRINT_NOTICE,  "NOT saving any changes since file is not locked\n");
			retval = 1;
		} else {
			print(PRINT_NOTICE, "Saving changes to state file\n");
			if (state_store(&s) != 0) {
				print(PRINT_ERROR, "Error while saving changes!\n");
				retval = 1;
			}
			state_unlock(&s);
		}
	}

	state_fini(&s);
	return retval;
}


