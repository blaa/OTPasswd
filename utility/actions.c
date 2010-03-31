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
#include "nls.h"

#ifndef PROG_VERSION
#define PROG_VERSION _("v0.6-dev")
#endif

#include <stdio.h>
#include <string.h>

#include <assert.h>

/* libotp header */
#define PPP_INTERNAL
#include "ppp.h"

/* Utility headers */
#include "actions.h"
#include "actions_helpers.h"
#include "security.h"

/* Authenticate; returns boolean; 1 - authenticated */
int action_authenticate(options_t *options)
{
	cfg_t *cfg = cfg_get();
	int retval = 0;

	/* OTP State */
	state *s = NULL;

	if (cfg->shell_auth == CONFIG_DISALLOW) {
		printf(_("Authentication failed (denied by policy).\n"));
		return 0;
	}

	if (ah_init_state(&s, options, 0) != 0) {
		/* This will fail if we're unable to locate home directory */
		print(PRINT_ERROR, _("Unable to initialize state.\n"));
		return 0; /* False - not authenticated */
	}

	/* Using locking load state, increment counter, and store new state */
	retval = ppp_increment(s);
	switch (retval) {
	case 0:
		/* Everything fine */
		break;

	case STATE_NUMSPACE:
		printf(_("Authentication failed (Counter overflowed, regenerate key).\n"));
		retval = 0;
		goto cleanup;

	case STATE_NON_EXISTENT:
		printf(_("Authentication failed (user doesn't have a key).\n"));
		retval = 0;
		goto cleanup;

	case STATE_NO_USER_ENTRY:
		printf(_("Authentication failed (user doesn't have entry in db).\n"));
		retval = 0;
		goto cleanup;

	case PPP_ERROR_POLICY:
		printf(_("Authentication failed (policy error).\n"));
		retval = 0;
		goto cleanup;

	default: /* Any other problem - error */
		printf(_("Authentication failed (state increment error).\n"));
		retval = 0;
		goto cleanup;
	}

	retval = ppp_authenticate(s, options->action_arg);
	switch (retval) {
	case 0:
		/* Correctly authenticated */
		printf(_("Authentication successful.\n"));
		retval = 1;
		break;
	case 3:
		printf(_("Authentication failed (wrong passcode).\n"));
		retval = 0;
		break;
	default:
		printf(_("Authentication failed (ppp_authenticate error).\n"));
		retval = 0;
		break;
	}

cleanup:
	if (ah_fini_state(&s, 0) != 0) {
		/* Should never happen */
		print(PRINT_ERROR, _("Error while finalizing state\n"));
		retval = 0;
	}

	return retval;
}

/* Generate new key */
/* FIXME: This function needs rewriting to use PPP.c interface
 * instead of state */
int action_key(options_t *options)
{
	cfg_t *cfg = cfg_get();
	int retval = 1;

	int remove = options->action == OPTION_KEY ? 0 : 1;

	if (remove && 
	    security_is_privileged() == 0 &&
	    cfg->key_removal == CONFIG_DISALLOW) {
		printf(_("Key removal denied by policy.\n"));
		return 1;
	}

	int ret;
	state s;

	if (state_init(&s, options->username) != 0) {
		print(PRINT_ERROR, _("Unable to initialize state\n"));
		return 1;
	}

	/* Check existance of previous key */
	if (state_load(&s) == 0) {

		/* Check regeneration policy */
		if (!remove && 
		    security_is_privileged() == 0 &&
		    cfg->key_regeneration == CONFIG_DISALLOW) {
			printf(_("Key regeneration denied by policy.\n"));
			goto cleanup;
		}

		if (s.flags & FLAG_DISABLED) {
			printf(_("Your current state is disabled. Cannot regenerate "
			         "until you remove the disabled flag.\n"));
			goto cleanup;
		}

		/* We loaded state correctly, key exists */
		puts(
			"*************************************************\n"
			"* This will irreversibly erase your key, making *\n"
			"*    all already printed passcards worthless!   *\n"
			"*************************************************\n"
		);

		if (ah_yes_or_no(_("Are you sure you want to continue?")) != 0) {
			printf(_("Stopping\n"));
			goto cleanup;
		}

		/* If we were supposed to remove the key do it now */
		if (remove) {
			if (state_lock(&s) != 0) {
				print(PRINT_ERROR, _("Unable to lock state for removing.\n"));
				goto cleanup;
			}

			ret = state_store(&s, 1);

			if (state_unlock(&s) != 0) {
				print(PRINT_ERROR, _("Unable to unlock state database.\n"));
				/* As we will soon quit don't die here */
			}

			if (ret == 0) {
				printf(_("Key removed!\n"));
				retval = 0;
			} else {
				printf(_("Error while removing key!\n"));
				retval = 1;
			}
			goto cleanup;
		}

		/* We are not removing, read flags, update them
		 * with user options and ask if he likes it */
		ret = ah_update_flags(options, &s, 1);
		if (ret != 0) {
			retval = 1;
			goto cleanup;
		}

		printf(_("This is your previous configuration updated with command line options:\n"));
		ah_show_flags(&s);
		printf(_("\nYou can either use it, or start with default one "
			 "(modified by any --config options).\n"));
		if (ah_enforced_yes_or_no(
			    _("Do you want to keep this configuration?")) == QUERY_NO) {
			printf(_("Reverting to defaults.\n"));
			state_fini(&s);
			state_init(&s, options->username);

			/* Use default salting from config */
			ret = ah_update_flags(options, &s, 1);
			if (ret != 0) {
				retval = 1;
				goto cleanup;
			}


		}
	} else {
		if (remove) {
			printf(_("Unable to load your state, nothing to remove.\n"));
			goto cleanup;
		}

		if (!remove && 
		    security_is_privileged() == 0 &&
		    cfg->key_generation == CONFIG_DISALLOW) {
			printf(_("Key generation denied by policy.\n"));
			goto cleanup;
		}

		/* Failed, state_load might have changed something in struct, reinit. */
		state_fini(&s);
		state_init(&s, options->username);

		/* Use default salting from config */
		ret = ah_update_flags(options, &s, 1);
		if (ret != 0) {
			retval = 1;
			goto cleanup;
		}
	}

	if (state_key_generate(&s) != 0) {
		print(PRINT_ERROR, _("Unable to generate new key\n"));
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
		ret = ah_yes_or_no(_("Are you ready to start using this one-time passwords?"));
		if (ret == 1) {
			printf(_("Please answer 'yes' or 'no'.\n"));
			continue;
		}
	} while (ret != 0 && ret != 2);

	if (ret != 0) {
		printf(_("Wiping out key. One-time passwords not enabled.\n"));
		goto cleanup;
	}

	/* Lock, store, unlock */
	if (state_lock(&s) != 0) {
		print(PRINT_ERROR, _("Unable to lock state database.\n"));
		goto cleanup;
	}

	ret = state_store(&s, 0);

	if (state_unlock(&s) != 0) {
		print(PRINT_ERROR, _("Unable to unlock state database.\n"));
		/* As we will soon quit don't die here */
	}

	if (ret != 0) {
		print(PRINT_ERROR, _("Unable to save state.\n"));
		print(PRINT_NOTICE, "(%s)\n", ppp_get_error_desc(ret));
		goto cleanup;
	}

	printf(_("Key stored! One-time passwords enabled for this account.\n"));
	retval = 0;

cleanup:
	state_fini(&s);
	return retval;
}

int action_license(options_t *options)
{
	printf(
		_("OTPasswd - One-Time Password Authentication System.\n"
		  "Version %s \n"
		  "Copyright (C) 2009, 2010 Tomasz bla Fortuna <bla@thera.be>\n"
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
		  "along with this program in a LICENSE file.\n"),
		  PROG_VERSION
	);
	return 0;
}

int action_spass(options_t *options)
{
	const cfg_t *cfg = cfg_get();

	char **err_list;
	int i;
	int ret;

	if (cfg->spass_change != CONFIG_ALLOW && !security_is_privileged()) {
		printf(_("Modification of a static password denied by the policy.\n"));
		return 1;
	}

	/* This must be done when the state is NOT locked */
	const char *pass = ah_get_pass();
	if (!pass) {
		print(PRINT_ERROR, _("No password returned\n"));
		return 1;
	}

	i = strlen(pass);

	state *s;
	ret = ah_init_state(&s, options, 1);
	if (ret != 0) {
		return ret;
	}

	ret = 1;
	if (i == 0) {
		err_list = ppp_spass_set(s, NULL,
		                         PPP_CHECK_POLICY);
		if (err_list && err_list[0]) {
			for (i=0; err_list[i]; i++)
				puts(_(err_list[i]));
			goto cleanup;
		}
		printf(_("Turned static password off.\n"));
	} else {
		/* Ensure password length/difficulty */
		err_list = ppp_spass_set(s, pass,
		                         PPP_CHECK_POLICY);
		if (err_list && err_list[0]) {
			for (i=0; err_list[i]; i++)
				puts(_(err_list[i]));
			goto cleanup;
		}
		printf(_("Static password set.\n"));
	}

	ret = 0;

cleanup:
	if (ret == 0) {
		/* Save */
		if (ah_fini_state(&s, 1) != 0)
			ret = 1;
	} else {
		/* Do not save */
		ah_fini_state(&s, 0);
	}

	return ret;
}

/* Update flags based on mask which are stored in options struct */
int action_flags(options_t *options)
{
	int retval = 1;
	int ret;
	int save_state = 0;
	state *s;

	cfg_t *cfg = cfg_get();

	if (options->action == OPTION_ALPHABETS) {
		/* This does not require state. */
		ppp_alphabet_print();
		return 0;
	}

	/* Initialize, lock, read, calculate additional card info... */
	ret = ah_init_state(&s, options, 1);
	if (ret != 0) {
		return ret;
	}

	switch(options->action) {
	case OPTION_CONFIG:
		ret = ah_update_flags(options, s, 0);
		if (ret != 0) {
			retval = ret;
			goto cleanup;
		}

		if (options->flag_set_mask || options->flag_clear_mask ||
		    options->set_codelength || options->set_alphabet ||
		    options->label || options->contact) {
			save_state = 1;
		}
		break;

	case OPTION_INFO: /* State info */
		if (security_is_privileged())
			printf(_("* User    = %s\n"), s->username);
		printf(_("* Your current state:\n"));
		ah_show_state(s);
		printf(_("\n* Your current flags:\n"));
		ah_show_flags(s);

		save_state = 0;
		retval = 0;
		goto cleanup;

	case OPTION_INFO_KEY: /* Key info */
		if (cfg->key_print == CONFIG_ALLOW || security_is_privileged()) {
			if (security_is_privileged())
				printf(_("User    = %s\n"), s->username);
			ah_show_keys(s);
			retval = 0;
		} else {
			printf(_("Printing key denied by policy!\n"));
			retval = 1;
		}
		save_state = 0;

		goto cleanup;


	default:
	case OPTION_ALPHABETS:
		/* List alphabets ought be done before */
		printf(_("Program error. You should never end up here.\n"));
		assert(0);
		retval = 1;
		goto cleanup;
	}

	retval = 0;
cleanup:
	/* save_state musn't be true if retval is */
	assert(!(retval && save_state));

	/* Finish state. If retval = 0 and save_state nonzero then save it */
	if (ah_fini_state(&s, save_state) != 0) {
		retval = 1;
	} else {
		/* If we were supposed to change something print the result... */
		if (options->action != OPTION_INFO && options->action != OPTION_INFO_KEY) {
			if (save_state)
				printf(_("Configuration updated.\n"));
			else
				printf(_("Configuration not changed.\n"));
		}
	}
	return retval;
}

int action_print(options_t *options)
{
	cfg_t *cfg = cfg_get();
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

	if (options->action == OPTION_TEXT || options->action == OPTION_LATEX)
		if (security_is_privileged() == 0 && cfg->passcode_print == CONFIG_DISALLOW) {
			printf(_("Passcode printing denied by policy.\n"));
			return 1;
		}

	if (options->action == OPTION_SKIP)
		if (security_is_privileged() == 0 && cfg->skipping == CONFIG_DISALLOW) {
			printf(_("Passcode skipping denied by policy.\n"));
			return 1;
		}

	ret = ah_init_state(&s, options, 1);
	if (ret != 0) {
		return ret;
	}

	/* From this point we must free these two */
	mpz_init(passcard_num);
	mpz_init(passcode_num);

	/* Do we have to just show any warnings? */
	if (options->action == OPTION_WARN) {
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
	selected = ah_parse_code_spec(s, options->action_arg, passcard_num, passcode_num);
	if ((selected != 1) && (selected != 2)) {
		goto cleanup;
	}

	/*
	 * Parsed! Now print/skip the thing requested
	 */
	if (selected == 2) { /* Card */
		char *card;
		switch (options->action) {
		case OPTION_TEXT:
			card = card_ascii(s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, _("Error while printing "
				      "card (not enough memory?)\n"));
				goto cleanup;
			}
			puts(card);
			free(card);
			break;

		case OPTION_LATEX:
			card = card_latex(s, passcard_num);
			if (!card) {
				print(PRINT_ERROR, _("Error while printing "
				      "card (not enough memory?)\n"));
				goto cleanup;
			}
			puts(card);
			free(card);
			break;

		case OPTION_SKIP:
			/* Skip to passcard... */
			ret = ppp_get_passcode_number(s, passcard_num,
						      &passcode_num, 'A', 1);
			if (ret != 0) {
				print(PRINT_ERROR,
				      _("Error while generating destination passcode\n"));
				goto cleanup;
			}

			ret = mpz_cmp(s->counter, passcode_num);
			if (ret > 0) {
				/* Skipping backwards */
				if (cfg->backward_skipping == CONFIG_ALLOW
				    || security_is_privileged()) {
					/* Allowed or root */
					printf(_("**********************************\n"
					         "* WARNING: You should never skip *\n"
					         "* backwards to reuse your codes! *\n"
					         "**********************************\n"));
				} else {
					printf(_("Skipping backwards denied by policy.\n"));
					break;
				}
			} else if (ret == 0) {
				printf(_("Ignoring skip to the current passcode.\n"));
				break;
			}

			printf(_("Skipped to specified passcard.\n"));
			mpz_set(s->counter, passcode_num);
			save_state = 1;
			break;

		case OPTION_PROMPT:
			print(PRINT_ERROR, _("Option requires passcode as argument\n"));
			break;
		}
	} else {
		char passcode[17];
		const char *prompt;
		switch (options->action) {
		case OPTION_TEXT:
			/* ppp_get_passcode wants internal
			 * passcodes (with salt) */
			ret = ppp_get_passcode(s, passcode_num, passcode);
			if (ret != 0) {
				print(PRINT_ERROR, _("Error while calculating passcode\n"));
				goto cleanup;
			}
			printf("%s\n", passcode);
			break;

		case OPTION_LATEX:
			printf(_("LaTeX parameter works only with"
			         " passcard specification\n"));
			break;

		case OPTION_SKIP:
			/* Skip to passcode */
			ret = mpz_cmp(s->counter, passcode_num);
			if (ret > 0) {
				/* Skipping backwards */
				if (cfg->backward_skipping == CONFIG_ALLOW
				    || security_is_privileged()) {
					/* Allowed or root */
					printf(_("**********************************\n"
					         "* WARNING: You should never skip *\n"
					         "* backwards to reuse your codes! *\n"
					         "**********************************\n"));
				} else {
					printf(_("Skipping backwards denied by policy.\n"));
					break;
				}
			} else if (ret == 0) {
				printf(_("Ignoring skip to the current passcode.\n"));
				break;
			}

			printf(_("Skipped to specified passcode.\n"));
			mpz_set(s->counter, passcode_num);
			save_state = 1;
			break;

		case OPTION_PROMPT:
			/* Don't save state after this operation */
			mpz_set(s->counter, passcode_num);
			ppp_calculate(s);
			ppp_get_str(s, PPP_FIELD_PROMPT, &prompt);
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
		if (options->action == OPTION_LATEX || 
		    options->action == OPTION_TEXT)
			do_increment = 1;
	}

	/* Increment "latest_card" in state if appropriate  */
	if (do_increment) {
		/* If current code is further than s->latest_card
		 * Then ignore this setting and start printing
		 * from current_card */
		if (mpz_cmp(s->current_card, s->latest_card) > 0) {
			/* Set next to current, or current + 5 for LaTeX */
			if (options->action == OPTION_LATEX) {
				mpz_add_ui(s->latest_card, s->current_card, 5);
			} else {
				mpz_set(s->latest_card, s->current_card);
			}
		} else {
			/* Increment by 1 or by 6 for LaTeX */
			mpz_add_ui(
				s->latest_card,
				s->latest_card,
				options->action == OPTION_LATEX ? 6 : 1);
		}
		save_state = 1;
	}

	retval = 0;

cleanup:
	mpz_clear(passcode_num);
	mpz_clear(passcard_num);

	/* If anything failed save_state should be zero */
	assert((save_state == 0) || (save_state && (retval == 0)));

	ret = ah_fini_state(&s, save_state);
	if (ret != 0) {
		retval = ret;
		if (save_state) {
			printf(_("Error while saving state! Changes not written.\n"));
		} else {
			printf(_("Error while finalizing state. (No changes to write)\n"));
		}
	}
	return retval;
}
