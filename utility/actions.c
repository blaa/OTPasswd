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
	ret = agent_connect(a, NULL);
	if (ret != 0) {
		/* Message already printed */
		return ret;
	} else {
		print(PRINT_NOTICE, _("Connected to agent\n"));
	}

	/* 2) Change username if required */	
	if (options->username) {
		ret = agent_set_user(*a, options->username);
		if (ret != 0) {
			printf(_("Error while setting user: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			print(PRINT_NOTICE, "Switched to user %s\n", options->username);
		}
	}

	/* 3) Load state, as most of actions do it anyway (getters etc.) */
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

	if (options->user_has_state == 0) {
		printf(_("Authentication failed (user has no state).\n"));
		return 0;
	}

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

	case AGENT_ERR_POLICY:
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
		printf(_("Your state was eaten by Grue, nothing to remove.\n"));
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
		printf(_("Error while removing key: %s\n"), 
		       agent_strerror(ret));
		return ret;
	}
}

/* Generate new key */
int action_key_generate(const options_t *options, agent *a)
{
	int retval = 1;
	int flags = 0; 

	/* Pre-verify whatever you can */
	if (options->user_has_state) {
		retval = agent_flag_get(a, &flags);
		if (retval != 0) {
			print(PRINT_ERROR, _("Unable to read flags: %s\n"), 
			      agent_strerror(retval));
			goto cleanup;
		}

		/* Drop current state */
		retval = agent_state_drop(a);
		if (retval != 0) {
			printf(_("Error while dropping state: %s\n"), 
			       agent_strerror(retval));
			goto cleanup;
		}
	}

	/* Create new state */
	retval = agent_state_new(a);
	if (retval != 0) {
		printf(_("Unable to generate new state:\n"));

		switch (retval) {
		case AGENT_ERR_POLICY_REGENERATION:
			printf(_("Policy denies key regeneration.\n"));
			break;

		case AGENT_ERR_POLICY_GENERATION:
			printf(_("Policy denies key generation. Ask administrator to create you state.\n"));
			break;

		case AGENT_ERR_POLICY_DISABLED:
			printf(_("You currently have state but it was disabled.\n"));
			break;
		default:
			printf(_("Error: %s\n"), agent_strerror(retval));
			break;
		case 0:
			assert(0);
		}
		goto cleanup;
	}

	/* Set flags */
	retval = ah_set_options(a, options);
	if (retval != 0) {
		switch (retval) {
		case AGENT_ERR_POLICY_DISABLED:
			printf(_("Policy denies toggling the DISABLE flag.\n"));
			break;
		case AGENT_ERR_POLICY_SALT:
			printf(_("Policy denies toggling the SALT flag.\n"));
			break;
		case AGENT_ERR_POLICY_SHOW:
			printf(_("Policy denies toggling the SHOW flag.\n"));
			break;

		default:
			printf(_("Error while setting flags: %s\n"), 
			       agent_strerror(retval));
			break;
		case 0:
			assert(0);
		}
		goto cleanup;
	}


	/* Check existance of previous key */
	if (options->user_has_state) {
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
		_("\n"
		"*****************************************************\n"
		"* Print following passcard or at least make a note  *\n"
		"* with a few first passcodes so you won't loose     *\n"
		"* ability to log into your system!                  *\n"
		"*****************************************************\n")
	);

	char *card = card_ascii(a, num_i(1));
	puts(card);
	free(card);

	/* Update LATEST CARD */
	retval = agent_update_latest_card(a, num_i(1));
	if (retval != AGENT_ERR_REQ_ARG && retval != 0) {
		/* Not updated, and not fine */
		print(PRINT_ERROR, 
		      _("Error while updating latest"
			" card entry: %s\n"), 
		      agent_strerror(retval));
		goto cleanup;
	}

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

	if (options->user_has_state == 0) {
		printf(_("You really need to create some state first (see -k option).\n"));
		return 1;
	}

	/* This must be done when the state is NOT locked */
	const char *pass;

	if (options->spass == NULL) {
		pass = ah_get_pass();
		if (!pass) {
			print(PRINT_ERROR, _("No password returned\n"));
			return 1;
		}
	} else {
		pass = options->spass;
	}

	i = strlen(pass);

	if (i == 0) {
		errors = agent_set_spass(a, NULL, 1);
		if (agent_is_agent_error(errors)) {
			printf(_("Agent error while unsetting password: %s\n"), agent_strerror(errors));
			return errors;
		}

		agent_print_spass_errors(errors);
		return errors==PPP_ERROR_SPASS_UNSET  ? 0 : PPP_ERROR;
	} else {
		errors = agent_set_spass(a, pass, 0);
		if (agent_is_agent_error(errors)) {
			printf(_("Agent error while setting password: %s\n"), 
			       agent_strerror(errors));
			return errors;
		}

		agent_print_spass_errors(errors);
		return errors==PPP_ERROR_SPASS_SET  ? 0 : PPP_ERROR;
	}
}

int action_warnings(const options_t *options, agent *a)
{
	int ret;
	int warnings;
	int failures;


	if (options->user_has_state == 0) {
		printf(_("Warning: You've got no state. Create on with -k option.\n"));
		return 1;
	}

	ret = agent_get_warnings(a, &warnings, &failures);
	if (ret != 0) {
		printf(_("Agent error while reading warnings: %s\n"), 
		       agent_strerror(ret));
		return ret;
	}

	if (warnings == 0)
		print(PRINT_NOTICE, _("No warnings.\n"));
	else
		agent_print_ppp_warnings(warnings, failures);
	return 0;
}


/* Update flags based on mask which are stored in options struct */
int action_info(const options_t *options, agent *a)
{
	int retval = 1;

	if (options->action != OPTION_ALPHABETS && options->user_has_state == 0) {
		printf(_("For your information: You've got no state created (see -k option).\n"));
		return 1;
	}

	if (options->action == OPTION_ALPHABETS) {
		/* This does not require state. */
		int id;
		const char *alphabet;
		printf(_("Alphabet list ([-] means \"denied by the policy\"): \n"));
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
		if (retval == AGENT_ERR_POLICY) {
			printf(_("Printing the key is denied by the policy.\n"));
		} else if (retval != 0) {
			printf(_("Error while printing user key: %s\n"), 
			       agent_strerror(retval));
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
	return retval;
}



int action_print(const options_t *options, agent *a)
{
	int ret = 1;

	/* Passcard/code to print */
	num_t item = num_i(0);

	/* And which to look at. */
	int selected;

	if (options->user_has_state == 0) {
		printf(_("You've got no state created! Unable to print passcodes (see -k option).\n"));
		return 1;
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
			if (!card) {
				ret = 1;
				goto cleanup;
			}
			puts(card);
			free(card);

			/* Got some card; update LATEST CARD */
			ret = agent_update_latest_card(a, item);
			if (ret != AGENT_ERR_REQ_ARG && ret != 0) {
				/* Not updated, and not fine */
				print(PRINT_ERROR, 
				      _("Error while updating latest"
					" card entry: %s\n"), 
				      agent_strerror(ret));
				goto cleanup;
			}

			break;

		case OPTION_LATEX:
			card = card_latex(a, item);
			if (!card) {
				ret = 1;
				goto cleanup;
			}
			puts(card);
			free(card);

			/* Got some card; update LATEST CARD */
			item = num_add_i(item, 6);
			ret = agent_update_latest_card(a, item);
			if (ret != AGENT_ERR_REQ_ARG) {
				/* Not updated, and not fine */
				print(PRINT_ERROR, 
				      _("Error while updating latest"
					" card entry: %s\n"), 
				      agent_strerror(ret));
				goto cleanup;
			}
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

	ret = 0;
cleanup:
	return ret;
}



/* Update flags based on mask which are stored in options struct */
int action_config(const options_t *options, agent *a)
{
	int ret; 

	if (options->label) {
		ret = agent_set_str(a, PPP_FIELD_LABEL, options->label);
		if (ret != AGENT_OK) {
			printf(_("Error while setting label: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Label set.\n"));
		}
	}

	if (options->contact) {
		ret = agent_set_str(a, PPP_FIELD_CONTACT, options->contact);
		if (ret != AGENT_OK) {
			printf(_("Error while setting contact: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Contact set.\n"));
		}
	}

	if (options->set_alphabet != -1) {
		ret = agent_set_int(a, PPP_FIELD_ALPHABET, options->set_alphabet);
		if (ret != AGENT_OK) {
			printf(_("Unable to select alphabet: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Alphabet selected.\n"));
			printf(_("WARNING: This invalidates your previously "
				 "printed passcards.\n"));
		}

	}

	if (options->set_codelength != -1) {
		ret = agent_set_int(a, PPP_FIELD_CODE_LENGTH, options->set_codelength);
		if (ret != AGENT_OK) {
			printf(_("Unable to set code length: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Code length set.\n"));
			printf(_("WARNING: This invalidates your previously "
				 "printed passcards.\n"));
		}

	}

	/* Two flags: FLAG_SHOW, FLAG_DISABLED */
	if (options->flag_set_mask) {
		ret = agent_flag_add(a, options->flag_set_mask);
		if (ret != AGENT_OK) {
			printf(_("Unable to enable required flags: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Flags set.\n"));
		}
	}

	if (options->flag_clear_mask) {
		ret = agent_flag_clear(a, options->flag_clear_mask);
		if (ret != AGENT_OK) {
			printf(_("Unable to disable required flags: %s\n"), 
			       agent_strerror(ret));
			return ret;
		} else {
			printf(_("Flags cleared.\n"));
		}
	}

	return 0;
}

int action_skip(const options_t *options, agent *a)
{
	int ret;

	/* Passcard/code to print */
	num_t item = num_i(0);

	/* And which to look at: PRINT_CODE / PRINT_CARD*/
	int selected = 0; 

	if (options->user_has_state == 0) {
		printf(_("You have skipped state creation. (see -k option).\n"));
		return 1;
	}

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

	case AGENT_ERR_POLICY:
	case PPP_ERROR_POLICY:
		printf(_("Skipping denied by the policy.\n"));
		break;
		
	default:
		printf("Agent error: %s (%d)\n", agent_strerror(ret), ret);
		break;
	}

	return ret;
}


