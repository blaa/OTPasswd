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

#ifndef PROG_VERSION
#define PROG_VERSION "v0.5"
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
#include "security.h"

#define PPP_INTERNAL
#include "ppp.h"
#include "passcards.h"

#include "otpasswd_actions.h"

enum {
	QUERY_YES=0,
	QUERY_NO=2,
	QUERY_OBSCURE=1
};

/* Secure init/load state. Should be used everywhere
 * when state would be locked anyway (we can't block execution
 * after this function). */
static int _init_state(state **s, const options_t *options, int load)
{
	int ret;
	ret = ppp_init(s, options->username);
	if (ret != 0) {
		return ret;
	}

	if (load == 0) {
		/* Just initialize */
		return 0;
	}

	ret = ppp_load(*s);
	switch (ret) {
	case 0:
		/* All right */
		return 0;

	default:
		printf("%s\n", ppp_get_error_desc(ret));
		ppp_fini(*s);
		return ret;
	}
}

/* Finish anything started by "_load_state" */
static int _fini_state(state **s, int store)
{
	int ret;

	/* We store changes into the file
	 * We don't need to unlock just yet - ppp_fini
	 * will unlock state if it was locked
	 */
	ret = ppp_release(*s, store, 0);
	if (ret != 0) {
		printf("Error while saving state data. State not changed.\n");
	}

	ppp_fini(*s);
	*s = NULL;

	return ret;
}


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
		printf("show=on ");
	else
		printf("show=off ");

	printf("alphabet=%d ", s->alphabet);
	printf("codelength=%d ", s->code_length);

	if (s->flags & FLAG_SALTED)
		printf("(salt=on)\n");
	else
		printf("(salt=off)\n");


	if (strlen(s->label) > 0) {
		printf("Passcard label=\"%s\", ", s->label);
	} else {
		printf("No label, ");
	}

	if (strlen(s->contact) > 0) {
		printf("contact=\"%s\".\n", s->contact);
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

	cfg_t *cfg = cfg_get();
	assert(cfg);

	mpz_t unsalted_counter;
	mpz_init_set(unsalted_counter, s->counter);
	if (s->flags & FLAG_SALTED) {
		mpz_and(unsalted_counter, unsalted_counter, s->code_mask);
	}
	/* Convert to user numbering */
	mpz_add_ui(unsalted_counter, unsalted_counter, 1);

	if (cfg->allow_key_print == 1 || security_is_root()) {
		/* Print key in LSB as PPP likes */
		printf("Key     = "); num_print(s->sequence_key, 64);
		printf("\n");

		/* This prints data MSB */
		/* gmp_printf("Key     = %064ZX\n", s->sequence_key); */
		gmp_printf("Counter = %032ZX\n", s->counter);
	} else {
		printf("Key     = (denied by policy)\n");
		printf("Counter = (denied by policy)\n");
	}
	gmp_printf("Current card        = %Zd\n", s->current_card);
	gmp_printf("Current code        = %Zd\n", unsalted_counter);
	gmp_printf("Latest printed card = %Zd\n", s->latest_card);
	gmp_printf("Max card            = %Zd\n", s->max_card);
	gmp_printf("Max code            = %Zd\n", s->max_code);

	mpz_clear(unsalted_counter);

}

/* Parse specification of passcode or passcard from "spec" string
 * Result save to passcode (and return 1) or to passcard (and return 2)
 * any other return value means error 
 */
static int _parse_code_spec(const state *s, const char *spec, mpz_t passcard, mpz_t passcode)
{
	int ret;
	int selected;

	/* Determine what user wants to print(or skip) and parse it to
	 * either passcode number or passcard number. Remember what was
	 * read to selected so later we can print it
	 */
	if (strcasecmp(spec, "current") == 0) {
		/* Current passcode */
		selected = 1;
		mpz_set(passcode, s->counter);
	} else if (strcasecmp(spec, "[current]") == 0) {
		/* Current passcode */
		selected = 2;
		mpz_set(passcard, s->current_card);
	} else if ((strcasecmp(spec, "next") == 0) ||
		   (strcasecmp(spec, "[next]") == 0)) {
		/* Next passcard. */
		selected = 2;

		/* Set passcard to latest_card + 1, but if 
		 * current code is further than s->latest_card
		 * then start printing from current_card */
		if (mpz_cmp(s->current_card, s->latest_card) > 0) {
			mpz_set(passcard, s->current_card);
		} else {
			mpz_add_ui(passcard, s->latest_card, 1);
		}
	} else if (isalpha(spec[0])) {
		/* Format: CRR[number]; TODO: allow RRC[number] */
		char column;
		int row;
		char number[41];
		ret = sscanf(spec, "%c%d[%40s]", &column, &row, number);
		column = toupper(column);
		if (ret != 3 || (column < 'A' || column > 'J')) {
			printf("Incorrect passcode specification. (%d)\n", ret);
			goto error;
		}

		ret = gmp_sscanf(number, "%Zu", passcard);
		if (ret != 1) {
			printf("Incorrect passcard specification.\n");
			goto error;
		}

		if (!_is_passcard_in_range(s, passcard)) {
			printf(
			      "Passcard number out of range. "
			      "First passcard has number 1.\n");
			goto error;
		}

		/* ppp_get_passcode_number adds salt as needed */
		ret = ppp_get_passcode_number(s, passcard, passcode, column, row);
		if (ret != 0) {
			printf("Error while parsing passcard description.\n");
			goto error;
		}

		selected = 1;

	} else if (isdigit(spec[0])) {
		/* All characters must be a digit! */
		int i;
		for (i=0; spec[i]; i++) {
			if (!isdigit(spec[i])) {
				printf("Illegal passcode number!\n");
				goto error;
			}
		}


		/* number -- passcode number */
		ret = gmp_sscanf(spec, "%Zd", passcode);
		if (ret != 1) {
			printf("Error while parsing passcode number.\n");
			goto error;
		}

		if (!_is_passcode_in_range(s, passcode)) {
			printf("Passcode number out of range.\n");
			goto error;
		}

		mpz_sub_ui(passcode, passcode, 1);

		/* Add salt as this number came from user */
		ppp_add_salt(s, passcode);

		selected = 1;
	} else if (spec[0] == '['
		   && spec[strlen(spec)-1] == ']') {
		/* [number] -- passcard number */
		ret = gmp_sscanf(spec, "[%Zd]", passcard);
		if (ret != 1) {
			printf("Error while parsing passcard number.\n");
			goto error;
		}

		if (!_is_passcard_in_range(s, passcard)) {
			printf("Passcard out of accessible range.\n");
			goto error;
		}

		selected = 2;
	} else {
		printf("Illegal argument passed to option.\n");
		goto error;
	}

	return selected;
error:
	return 5;
}

/* Authenticate; returns boolean; 1 - authenticated */
int action_authenticate(options_t *options, const cfg_t *cfg)
{
	int retval = 0;

	/* OTP State */
	state *s = NULL;

	if (cfg->allow_shell_auth == 0) {
		printf("Authentication failed (denied by policy).\n");
		return 0;
	}

	if (_init_state(&s, options, 0) != 0) {
		/* This will fail if we're unable to locate home directory */
		print(PRINT_ERROR, "Unable to initialize state.\n");
		return 0; /* False - not authenticated */
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_increment(s);
	switch (retval) {
	case 0:
		/* Everything fine */
		break;

	case STATE_NUMSPACE:
		printf("Authentication failed (Counter overflowed, regenerate key).\n");
		retval = 0;
		goto cleanup;

	case STATE_NON_EXISTENT:
		printf("Authentication failed (user doesn't have a key).\n");
		retval = 0;
		goto cleanup;

	case STATE_NO_USER_ENTRY:
		printf("Authentication failed (user doesn't have entry in db).\n");
		retval = 0;
		goto cleanup;

	default: /* Any other problem - error */
		printf("Authentication failed (state increment error).\n");
		retval = 0;
		goto cleanup;
	}

	retval = ppp_authenticate(s, options->action_arg);
	switch (retval) {
	case 0:
		/* Correctly authenticated */
		printf("Authentication successful.\n");
		retval = 1;
		break;
	case 3:
		printf("Authentication failed (wrong passcode).\n");
		retval = 0;
		break;
	default:
		printf("Authentication failed (ppp_authenticate error).\n");
		retval = 0;
		break;
	}

cleanup:
	if (_fini_state(&s, 0) != 0) {
		/* Should never happen */
		print(PRINT_ERROR, "Error while finalizing state\n");
		retval = 0;
	}

	return retval;
}

static void _update_flags(const options_t *options, const cfg_t *cfg, state *s, int *salted)
{
	assert(options);
	assert(cfg);
	assert(s);

	/* Copy all user-selected values to state
	 * but check if they match policy */

	/* Length of contact/label is ensured in process_cmd_line */
	if (options->contact)
		strcpy(s->contact, options->contact); 
	if (options->label)
		strcpy(s->label, options->label);

	s->flags |= options->flag_set_mask;
	s->flags &= options->flag_clear_mask;

	if (options->set_codelength != -1)
		s->code_length = options->set_codelength;

	if (options->set_alphabet != -1)
		s->alphabet = options->set_alphabet;


	switch (cfg->salt_allow) {
	case 0:
		*salted = 0;
		break;
	case 2:
		*salted = 1;
		break;
	default:
		if (options->flag_set_mask & FLAG_SALTED) 
			*salted = 1;
		if (options->flag_clear_mask & FLAG_SALTED) 
			*salted = 0;
		break;
	}

	if (*salted)
		s->flags |= FLAG_SALTED;
}

/* Generate new key */
int action_key(options_t *options, const cfg_t *cfg)
{
	int retval = 1;

	int remove = options->action == 'k' ? 0 : 1;

	if (remove && 
	    security_is_root() == 0 &&
	    cfg->allow_key_removal == 0) {
		printf("Key removal denied by policy.\n");
		return 1;
	}

	int ret;
	state s;
	int salted; /* Do we salt the key? */

	if (state_init(&s, options->username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		return 1;
	}

	/* Check existance of previous key */
	if (state_load(&s) == 0) {

		/* Check regeneration policy */
		if (!remove && 
		    security_is_root() == 0 &&
		    cfg->allow_key_regeneration == 0) {
			printf("Key regeneration denied by policy.\n");
			goto cleanup;
		}

		/* We loaded state correctly, key exists */
		puts(
			"*************************************************\n"
			"* This will irreversibly erase your key, making *\n"
			"*    all already printed passcards worthless!   *\n"
			"*************************************************\n"
		);

		if (_yes_or_no("Are you sure you want to continue?") != 0) {
			printf("Stopping\n");
			goto cleanup;
		}

		/* If we were supposed to remove the key do it now */
		if (remove) {
			ret = state_store(&s, 1);
			if (ret == 0) {
				printf("Key removed!\n");
				retval = 0;
			} else {
				printf("Error while removing key!\n");
				retval = 1;
			}
			goto cleanup;
		}

		/* We are not removing, read flags, update them
		 * with user options and ask if he likes it */

		/* Use default from previous state */
		if (s.flags & FLAG_SALTED)
			salted = 1;
		else 
			salted = 0;

		_update_flags(options, cfg, &s, &salted);

		printf("Your current flags (updated with command line options):\n");
		_show_flags(&s);
		if (_enforced_yes_or_no(
			    "Type 'yes' to use those, or 'no' to start with updated defaults?") == QUERY_NO) {
			printf("Reverting to defaults.\n");
			state_fini(&s);
			state_init(&s, options->username);

			/* Use default salting from config */
			salted = cfg->salt_def;
			_update_flags(options, cfg, &s, &salted);
		}
	} else {
		if (remove) {
			printf("Unable to load your state, nothing to remove.\n");
			goto cleanup;
		}

		if (!remove && 
		    security_is_root() == 0 &&
		    cfg->allow_key_generation == 0) {
			printf("Key generation denied by policy.\n");
			goto cleanup;
		}




		/* Failed, state_load might have changed something in struct, reinit. */
		state_fini(&s);
		state_init(&s, options->username);

		/* Use default salting from config */
		salted = cfg->salt_def;
		_update_flags(options, cfg, &s, &salted);
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
	} while (ret != 0 && ret != 2);

	if (ret != 0) {
		printf("Wiping out key. One-time passwords not enabled.\n");
		goto cleanup;
	}

	ret = state_store(&s, 0); /* This should auto lock */
	if (ret != 0) {
		print(PRINT_ERROR, "Unable to save state.\n");
		print(PRINT_NOTICE, "(%s)\n", ppp_get_error_desc(ret));
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
	int ret;
	int save_state = 0;
	state *s;

	if (options->action == 'A') {
		/* This does not require state. */
		ppp_alphabet_print();
		return 0;
	}

	/* Initialize, lock, read, calculate additional card info... */
	ret = _init_state(&s, options, 1);
	if (ret != 0) {
		return ret;
	}

	switch(options->action) {
	case 'f':
		/* Change flags */
		assert(! (options->flag_set_mask & FLAG_SALTED));
		assert(! (options->flag_clear_mask & FLAG_SALTED));

		s->flags |= options->flag_set_mask;
		s->flags &= ~(options->flag_clear_mask);

		if (options->flag_set_mask || options->flag_clear_mask) {
			save_state = 1;
		}

		if (options->set_codelength > 0) {
			if (s->code_length != options->set_codelength) {
				printf("Warning: Changing codelength invalidates "
				       "already printed passcards.\n"
				       "         If you like, you can switch back "
				       "to your previous settings.\n\n");
				save_state = 1;
			}
			s->code_length = options->set_codelength;
		}

		if (options->set_alphabet >= 0) {
			if (s->alphabet != options->set_alphabet) {
				printf("Warning: Changing alphabet invalidates "
				       "already printed passcards.\n"
				       "         If you like, you can switch back "
				       "to your previous settings.\n\n");
				save_state = 1;
			}
			s->alphabet = options->set_alphabet;
		}

		/* Length of contact/label checked in process_cmd_line */
		if (options->label) {
			strcpy(s->label, options->label);
			save_state = 1;
		}
		
		if (options->contact) {
			strcpy(s->contact, options->contact);
			save_state = 1;
		}

		break;

	case 'p':
	{
		assert(options->action_arg);
		const int len = strlen(options->action_arg);
		unsigned char sha_buf[32];
		if (len == 0) {
			s->spass_set = 0;
			mpz_set_ui(s->spass, 0);
			printf("Turning off static password.\n\n");
		} else {
			/* Change static password */
			/* TODO: Ensure its length/difficulty */
			crypto_sha256((unsigned char *)options->action_arg, len, sha_buf);
			num_from_bin(s->spass, sha_buf, sizeof(sha_buf));
			s->spass_set = 1;
			printf("Static password set.\n\n");
		}

		save_state = 1;
		break;
	}

	case 'L': /* List */
		printf("User    = %s\n", s->username);
		_show_keys(s);

		save_state = 0;
		retval = 0;
		goto cleanup;

	case 'A': /* List alphabets ought be done before */
		assert(0);

	default:
		printf("You should never end up here\n");
		assert(0);
	}

	retval = 0;
cleanup:
	if (retval == 0 && options->action != 'A') {
		printf("Your current flags:\n");
		_show_flags(s);
	}

	/* save_state musn't be true if retval is */
	assert(!(retval && save_state));

	/* Finish state. If retval = 0 and save_state nonzero then save it */
	if (_fini_state(&s, save_state) != 0) {
		retval = 1;
	} else {
		if (save_state)
			printf("Flags updated.\n");
		else
			printf("Flags not changed.\n");
	}
	return retval;
}

int action_print(options_t *options, const cfg_t *cfg)
{
	int retval = 1;
	int ret;

	state *s;

	/* If 1, we will try to update state at the end of function */
	int save_state = 0;

	/* Passcard/code to print */
	mpz_t passcard_num;
	mpz_t passcode_num;

	/* And which to look at: 1 - code, 2 - card */
	int selected = 0; 

	if (options->action == 't' || options->action ==  'l')
		if (security_is_root() == 0 && cfg->allow_passcode_print == 0) {
			printf("Passcode printing denied by policy.\n");
			return 1;
		}

	if (options->action == 's')
		if (security_is_root() == 0 && cfg->allow_skipping == 0) {
			printf("Passcode skipping denied by policy.\n");
			return 1;
		}

	ret = _init_state(&s, options, 1);
	if (ret != 0) {
		return ret;
	}

	/* From this point we must free these two */
	mpz_init(passcard_num);
	mpz_init(passcode_num);

	/* Do we have to just show any warnings? */
	if (options->action == 'w') {
		int e = ppp_get_warning_conditions(s);
		const char *warn;
		while ((warn = ppp_get_warning_message(s, &e)) != NULL) {
			const char *format = "*** OTPasswd Warning: %s\n";
			printf(format, warn);
		}
		retval = 0;
		goto cleanup;
	}


	/* Parse argument */
	selected = _parse_code_spec(s, options->action_arg, passcard_num, passcode_num);
	if ((selected != 1) && (selected != 2)) {
		goto cleanup;
	}

	/*
	 * Parsed! Now print/skip the thing requested
	 */
	if (selected == 2) { /* Card */
		char *card;
		switch (options->action) {
		case 't':
			card = card_ascii(s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup;
			}
			puts(card);
			free(card);
			break;

		case 'l':
			card = card_latex(s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, "Error while printing "
				      "card (not enough memory?)\n");
				goto cleanup;
			}
			puts(card);
			free(card);
			break;

		case 's':
			/* Skip to passcard... */
			ret = ppp_get_passcode_number(s, passcard_num,
						      passcode_num, 'A', 1);
			if (ret != 0) {
				print(PRINT_ERROR,
				      "Error while generating destination passcode\n");
				goto cleanup;
			}

			if (mpz_cmp(s->counter, passcode_num) > 0) {
				printf(
					"**********************************\n"
					"* WARNING: You should never skip *\n"
					"* backwards to reuse your codes! *\n"
					"**********************************\n");
			}

			printf("Skipped to specified passcard.\n");
			mpz_set(s->counter, passcode_num);
			save_state = 1;
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
			ret = ppp_get_passcode(s, passcode_num, passcode);
			if (ret != 0) {
				print(PRINT_ERROR, "Error while calculating passcode\n");
				goto cleanup;
			}
			printf("%s\n", passcode);
			break;

		case 'l':
			printf(
			      "LaTeX parameter works only with"
			      " passcard specification\n");
			break;

		case 's':
			/* Skip to passcode */
			if (mpz_cmp(s->counter, passcode_num) > 0) {
				printf(
					"**********************************\n"
					"* WARNING: You should never skip *\n"
					"* backwards to reuse your codes! *\n"
					"**********************************\n");
			}
			printf("Skipped to specified passcode.\n");
			mpz_set(s->counter, passcode_num);
			save_state = 1;
			break;

		case 'P':
			/* Don't save state after this operation */
			mpz_set(s->counter, passcode_num);
			ppp_calculate(s);
			prompt = ppp_get_prompt(s);
			printf("%s\n", prompt);
			assert(save_state == 0);
			break;
		}
	}

	/* Increment latest_card printed in some circumstances:
	 * 1) "next" argument used with option --text or --latex
	 * Maybe:
	 * When printing latest_card + 1 card?
	 */
	int do_increment = 0;
	if (strcasecmp(options->action_arg, "next") == 0) {
		if (options->action == 'l' || options->action == 't')
			do_increment = 1;
	}

	/* Increment "latest_card" in state if appropriate  */
	if (do_increment) {
		/* If current code is further than s->latest_card
		 * Then ignore this setting and start printing
		 * from current_card */
		if (mpz_cmp(s->current_card, s->latest_card) > 0) {
			/* Set next to current, or current + 5 for LaTeX */
			if (options->action == 'l') {
				mpz_add_ui(s->latest_card, s->current_card, 5);
			} else {
				mpz_set(s->latest_card, s->current_card);
			}
		} else {
			/* Increment by 1 or by 6 for LaTeX */
			mpz_add_ui(
				s->latest_card,
				s->latest_card,
				options->action == 'l' ? 6 : 1);
		}
		save_state = 1;
	}

	retval = 0;

cleanup:
	mpz_clear(passcode_num);
	mpz_clear(passcard_num);

	/* If anything failed save_state should be zero */
	assert((save_state == 0) || (save_state && (retval == 0)));

	ret = _fini_state(&s, save_state);
	if (ret != 0) {
		retval = ret;
		if (save_state) {
			printf("Error while saving state! Changes not written.\n");
		} else {
			printf("Error while finalizing state. (No changes to write)\n");
		}
	}
	return retval;
}
