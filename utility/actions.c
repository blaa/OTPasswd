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

#include <stdio.h>
#include <string.h>

#include <assert.h>

/* agent interface */
#include "agent_interface.h"
#include "print.h"

/* Utility headers */
#include "actions.h"
#include "actions_helpers.h"
#include "cards.h"

/** Executed before any other actions */
int action_init(options_t *options, agent **a)
{
	int ret;

	assert(a && *a == NULL);
	assert(options);

	/* 1) Connect to agent */
	ret = agent_connect(a, "./agent_otp");
	if (ret != 0) {
		printf("Unable to connect to agent: (%d) ", ret);
		puts(agent_strerror(ret));
		return 1;
	}

	/* 2) Change username if required */	
	if (options->username) {
		ret = agent_set_user(*a, options->username);
		if (ret != 0) {
			printf("Error while setting user: %s (%d)\n", 
			       agent_strerror(ret), ret);
			return ret;
		}
	}

	/* 3) Load state, as most of actions do it anyway */
	ret = agent_state_load(*a);
	switch (ret) {
	case STATE_NON_EXISTENT:
	case STATE_NO_USER_ENTRY:
		options->user_has_state = 0;
		break;
	case AGENT_OK:
		options->user_has_state = 1;
		break;
	default:
		printf(_("Error while loading user state: %s (%d)\n"), 
		       agent_strerror(ret), ret);
		return ret;
	}

	/* TODO: Check if this state is correct, like, 
	 * can it still generate passcodes? */
	return 0;
}

int action_fini(agent *a)
{
	int ret;
	assert(a);
	ret = agent_disconnect(a);
	if (ret != 0) { 
		print(PRINT_WARN, "Error while disconnecting from agent\n");
	}
	return ret;
}


/* Authenticate; returns boolean; 1 - authenticated */
int action_authenticate(const options_t *options, agent *a)
{
	int retval = 0;

	retval = agent_authenticate(a, options->action_arg);
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
		printf(_("Authentication failed with internal error.\n"));
		printf(_("Agent error: %s\n"), agent_strerror(retval));
		retval = 0;
		goto cleanup;
	}

cleanup:
	return retval;
}

/* Remove key */
int action_key_remove(const options_t *options, agent *a)
{
	int ret;
	if (options->user_has_state == 0) {
		printf(_("Unable to load your state, nothing to remove.\n"));
		return 1;
	}

	/* TODO: Pre-check policy */
	/* TODO: Check enforcement! This will render account unusable of enforcement is enabled */

	puts(
		"*********************************************************\n"
		"* This will irreversibly erase your current key, making *\n"
		"*    all already printed passcards worthless!           *\n"
		"*********************************************************\n"
	);

	if (ah_yes_or_no(_("Are you sure you want to continue?")) != 0) {
		printf(_("Stopping\n"));
		return 1;
	}

	ret = agent_state_drop(a);
	if (ret != 0) {
		printf(_("Error while dropping state! %s (%d)\n"), 
		       agent_strerror(ret), ret);
		return ret;
	}

	ret = agent_key_remove(a);
	if (ret == 0) {
		printf(_("Key removed!\n"));
		return 0;
	} else {
		printf(_("Error while removing key! %s (%d)\n"), 
		       agent_strerror(ret), ret);
		return ret;
	}
}

/* Generate new key */
int action_key_generate(const options_t *options, agent *a)
{
	int retval = 1;

	/* TODO: pre-verify policy (DISABLE) and die if impossible */

	/*
	printf(_("Your current state is disabled. Cannot regenerate "
	"until you remove the disabled flag.\n")); */

	/* printf(_("Key regeneration denied by policy.\n")); */

	/* Check existance of previous key */
	if (options->user_has_state) {
		/* TODO: pre-verify policy (REGENERATION) and die if impossible */

		puts(
			"*********************************************************\n"
			"* This will irreversibly erase your current key, making *\n"
			"*    all already printed passcards worthless!           *\n"
			"*********************************************************\n"
		);

		if (ah_yes_or_no(_("Are you sure you want to continue?")) != 0) {
			printf(_("Stopping\n"));
			retval = 1;
			goto cleanup;
		}

		/* TODO: Read user flags, update with flags passed via command line, ask
		 * if he likes it */
		/* printf(_("This is your previous configuration updated with command line options:\n"));
		   ah_show_flags(&s);
		printf(_("\nYou can either use it, or start with default one "
			 "(modified by any --config options).\n"));

		if (ah_enforced_yes_or_no(
			    _("Do you want to keep this configuration?")) == QUERY_NO) {
			printf(_("Reverting to defaults.\n"));

			// Use default salting from config 
			ret = ah_update_flags(options, &s, 1);
			if (ret != 0) {
				retval = 1;
				goto cleanup;
			}
		*/

		/* Drop current state */
		retval = agent_state_drop(a);
		if (retval != 0) {
			printf(_("Error while dropping state: %s (%d)"), 
			       agent_strerror(retval), retval);
			goto cleanup;
		}
	} else {
		/* TODO: pre-verify policy (DISABLE) and die if impossible */
		/*
		if (!remove && 
		    security_is_privileged() == 0 &&
		    cfg->key_generation == CONFIG_DISALLOW) {
			printf(_("Key generation denied by policy.\n"));
			goto cleanup;
		}
		*/
		/* Not loaded */

	}

	/* Create new state */
	retval = agent_state_new(a);
	if (retval != 0) {
		printf(_("Error while creating new state: %s (%d)"), 
		       agent_strerror(retval), retval);
		goto cleanup;
	}

	/* Set flags */
	retval = ah_set_options(a, options);
	if (retval != 0) {
		print(PRINT_ERROR, _("Unable to set required flags: %s (%d)\n"), 
		      agent_strerror(retval), retval);
		goto cleanup;
	}


	/* Display user flags */
	printf(_("Your current set of flags:\n"));
	retval = ah_show_flags(a);
	if (retval != 0) {
		goto cleanup;
	}

	printf("\n\n");

	/* Generate the key */
	printf(_("HINT: To generate key we need to gather lots of random data.\n"
		 "To make this process faster you can move your mouse or cause\n"
		 "some network or disc activity\n"));

	retval = agent_key_generate(a);
	if (retval != 0) {
		print(PRINT_ERROR, _("Unable to generate new key: %s (%d)\n"), 
		      retval, agent_strerror(retval));
		goto cleanup;
	}
	
	printf(_("Key generated successfully.\n"));

	puts(
		"\n"
		"*****************************************************\n"
		"* Print following passcard or at least make a note  *\n"
		"* with a few first passcodes so you won't loose     *\n"
		"* ability to log into your system!                  *\n"
		"*****************************************************\n"
	);

	char *card = card_ascii(a, num_i(1));
	puts(card);
	free(card);

	do {
		retval = ah_yes_or_no(_("Are you ready to start using this "
		                        "one-time passwords?"));
		if (retval == 1) {
			printf(_("Please answer 'yes' or 'no'.\n"));
			continue;
		}
	} while (retval != 0 && retval != 2);

	if (retval != 0) {
		printf(_("Wiping out key. User state left unchanged.\n"));
		goto cleanup;
	}

	/* Lock, store, unlock */
	retval = agent_state_store(a);
	if (retval != 0) {
		printf(_("Unable to store new key: %s (%d)\n"),
		       agent_strerror(retval), retval);
		goto cleanup;
	}

	printf(_("Key stored! One-time passwords enabled for this account.\n"));

	retval = 0;
cleanup:
	return retval;
}

int action_spass(const options_t *options, agent *a)
{
	int i;
	int errors;

	/* This must be done when the state is NOT locked */
	const char *pass = ah_get_pass();
	if (!pass) {
		print(PRINT_ERROR, _("No password returned\n"));
		return 1;
	}

	i = strlen(pass);

	if (i == 0) {
		errors = agent_set_spass(a, NULL, 1);
		if (agent_is_agent_error(errors)) {
			printf(_("Agent error while setting password: %s\n"), agent_strerror(errors));
			return errors;
		}

		agent_print_spass_errors(errors);
		return errors ? PPP_ERROR : 0;
	} else {
		errors = agent_set_spass(a, pass, 0);
		if (agent_is_agent_error(errors)) {
			printf(_("Agent error while setting password: %s\n"), agent_strerror(errors));
			return errors;
		}

		agent_print_spass_errors(errors);
		return errors ? PPP_ERROR : 0;
	}
}

/* Update flags based on mask which are stored in options struct */
int action_info(const options_t *options, agent *a)
{
	int retval = 1;

	if (options->action == OPTION_ALPHABETS) {
		/* This does not require state. */
		int id;
		const char *alphabet;
		printf(_("Alphabet list ([-] means \"denied by policy\"): \n"));
		for (id = 0; ; id++) {
			alphabet = NULL;
			retval = agent_get_alphabet(a, id, &alphabet);
			if (retval == PPP_ERROR_RANGE) {
				/* That's it */
				break;
			} else if (retval == PPP_ERROR_POLICY) {
				printf("ID=%d [-] %s\n", id, alphabet);
			} else if (retval == 0) {
				printf("ID=%d [+] %s\n", id, alphabet);
			} else {
				print(PRINT_ERROR, "Error while querying for alphabet string.\n");
				return retval;
			}
		}

		return 0;
	}

	if (options->username)
		printf(_("* User    = %s\n"), options->username);


	/* Initialize, lock, read, calculate additional card info... */
	switch(options->action) {
	case OPTION_INFO: /* State info */
		printf(_("* Your current state:\n"));
		retval = ah_show_state(a);

		if (retval != 0) {
			print(PRINT_ERROR, _("Error while printing state information.\n"));
			goto cleanup;
		}

		printf(_("\n* Your current flags:\n"));
		retval = ah_show_flags(a);

		if (retval != 0) {
			print(PRINT_ERROR, _("Error while printing state flags.\n"));
			goto cleanup;
		}


		retval = 0;
		goto cleanup;

	case OPTION_INFO_KEY: /* Key info */
		retval = ah_show_keys(a, options);
		if (retval != 0) {
			print(PRINT_ERROR, _("Error while printing user key data.\n"));
		}
		goto cleanup;


	default:
	case OPTION_ALPHABETS:
		/* List alphabets ought to be done before */
		printf(_("Program error. You should never end up here.\n"));
		assert(0);
		retval = 1;
		goto cleanup;
	}

	retval = 0;
cleanup:
#if 0
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
#endif
	return retval;
}



int action_print(const options_t *options, agent *a)
{
	int ret;

	/* Passcard/code to print */
	num_t item = num_i(0);

	/* And which to look at. */
	int selected;

	/* Do we have to just show any warnings? */
	if (options->action == OPTION_WARN) {
/*		int e = ppp_get_warning_conditions(s);
		const char *warn;
		while ((warn = ppp_get_warning_message(s, &e)) != NULL) {
			const char *format = "*** OTPasswd Warning: %s\n";
			printf(format, warn);
		}
*/
		printf(_("Not implemented.\n"));
		return 0;
	}


	/* Parse argument */
	selected = ah_parse_code_spec(a, options->action_arg, &item);
	if ((selected != PRINT_CODE) && (selected != PRINT_CARD)) {
		return selected;
	}

	/*
	 * Parsed! Now print the thing requested
	 */
	if (selected == PRINT_CARD) { /* Card */
		char *card;
		switch (options->action) {
		case OPTION_TEXT:
			card = card_ascii(a, item);
			if (!card)
				goto cleanup;
			puts(card);
			free(card);
			break;

		case OPTION_LATEX:
			card = card_latex(a, item);
			if (!card)
				goto cleanup;
			puts(card);
			free(card);
			break;

		case OPTION_PROMPT:
			printf(_("Option requires passcode as argument\n"));
			break;
		}
	} else {
		char *prompt;
		char passcode[17];
		switch (options->action) {
		case OPTION_TEXT:
			ret = agent_get_passcode(a, item, passcode);
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

		case OPTION_PROMPT:
			ret = agent_get_prompt(a, item, &prompt);
//			ret = agent_get_str(a, PPP_FIELD_PROMPT, &prompt);
			if (ret != AGENT_OK || prompt == NULL) {
				printf(_("Error while retrieving prompt: %s\n"), agent_strerror(ret));
				goto cleanup;
			} else {
				printf("%s\n", prompt);
				free(prompt);
			}
			break;
		}
	}

	/* Increment latest_card printed in some circumstances:
	 * 1) "next" argument used with option --text or --latex
	 * Maybe:
	 * When printing latest_card + 1 card?
	 */
#if 0
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
#endif

	ret = 0;

cleanup:
	return ret;
}



/* Update flags based on mask which are stored in options struct */
int action_config(const options_t *options, agent *a)
{

	/* Initialize, lock, read, calculate additional card info... */
/*      TODO 
        ret = ah_update_flags(options, s, 0);
        if (ret != 0) {
                retval = ret;
                goto cleanup;
        }

	if (options->flag_set_mask || options->flag_clear_mask ||
	    options->set_codelength || options->set_alphabet ||
	    options->label || options->contact) {
		save_state = 1;
		} */

	printf(_("Unimplemented!"));
	return 1;
}



int action_skip(const options_t *options, agent *a)
{
	int ret;

	/* Passcard/code to print */
	num_t item = num_i(0);

	/* And which to look at: PRINT_CODE / PRINT_CARD*/
	int selected = 0; 


	/* Parse argument */
	selected = ah_parse_code_spec(a, options->action_arg, &item);
	if ((selected != PRINT_CODE) && (selected != PRINT_CARD)) {
		return selected;
	}


	if (selected == PRINT_CARD) { /* Card */
		/* Convert card number to code number */
		num_t passcode_num = num_i(0);

		ret = ah_get_passcode_number(a, item, &passcode_num, 'A', 1);
		if (ret != 0) {
			print(PRINT_ERROR,
			      _("Error while generating destination passcode\n"));
			return ret;
		}
		item = passcode_num;
	} 

	/* Now in 'item' there's a passcode number for sure; common skip: */
	ret = agent_skip(a, item);

	switch (ret) {
	case 0:
		printf(_("Skipped to specified passcode.\n"));
		break;

	case PPP_ERROR_RANGE:
		printf(_("Specified passcode is larger than maximal possible.\n"));
		break;

	case PPP_ERROR_SKIP_BACKWARDS:
		printf(_("You can't skip backwards and re-use already used up passcodes.\n"));
		break;


	case PPP_ERROR_POLICY:
		printf(_("Skipping denied by policy.\n"));
		break;
		
	default:
		printf("Agent error: %s (%d)\n", agent_strerror(ret), ret);
		break;
	}



	return ret;
}


