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
#include <string.h>
#include <ctype.h>

/* For ah_get_pass turning echo off */
#include <termios.h>
#include <unistd.h>

#include "print.h"

/* For options_t struct */
#include "actions.h" 
#include "actions_helpers.h"
#include "security.h"
#include "nls.h"

int ah_yes_or_no(const char *msg)
{
	char buf[20];
	fputs(msg, stdout);
	fputs(_(" (yes/no): "), stdout);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		/* End of file? */
		printf("\n");
		return 1;
	}

	/* Strip \n */
	buf[strlen(buf) - 1] = '\0';

	if (strcasecmp(buf, _("yes")) == 0) {
		printf("\n");
		return QUERY_YES;
	} else if (strcasecmp(buf, _("no")) == 0) {
		return QUERY_NO;
	}

	/* Incomprehensible answer */
	return QUERY_OBSCURE;
}

int ah_enforced_yes_or_no(const char *msg)
{
	int ret;
	do {
		ret = ah_yes_or_no(msg);
		if (ret == QUERY_OBSCURE) {
			printf(_("Please answer 'yes' or 'no'.\n"));
			continue;
		}
	} while(ret != QUERY_YES && ret != QUERY_NO);

	return ret;
}

const char *ah_get_pass(void)
{
	struct termios t;
	static char buf[128], buf2[128];
	char *res = NULL;
	int copy = -1;

	/* Turn off echo */
	if (tcgetattr(0, &t) != 0) {
		print(PRINT_ERROR, _("Unable to turn off characters visibility!\n"));
		return NULL;
	}
	
	copy = t.c_lflag;
	t.c_lflag &= ~ECHO;

	if (tcsetattr(0, 0, &t) != 0) {
		print(PRINT_ERROR, _("Unable to turn off characters visibility!\n"));
		return NULL;
	}
	
	/* Ask question */
	printf(_("Static password: "));
	res = fgets(buf, sizeof(buf), stdin);
	if (res == NULL) {
		print(PRINT_ERROR, "Unable to read static password\n");
		goto cleanup;
	}
	printf("\n");

	printf(_("Repeat password: "));
	res = fgets(buf2, sizeof(buf2), stdin);
	if (res == NULL) {
		print(PRINT_ERROR, "Unable to read static password\n");
		goto cleanup;
	}
	printf("\n");

	if (strcmp(buf, buf2) == 0)
		res = buf;
	else {
		printf(_("Sorry passwords do not match.\n"));
		res = NULL;
	}

	const int len = strlen(buf);
	if (len != 0) {
		/* Strip \n */
		buf[len-1] = '\0';
	}

cleanup:
	/* Turn echo back on */
	t.c_lflag = copy;
	if (tcsetattr(0, 0, &t) != 0) {
		print(PRINT_ERROR, _("WARNING: Unable to turn on characters visibility!\n"));
	}

	return res;
}


int ah_show_state(agent *a)
{
	int ret;
	num_t current_card, unsalted_counter, latest_card, 
		max_card, max_code;
	const char *which = NULL;

	if ((ret = agent_get_num(a, &current_card, PPP_FIELD_CURRENT_CARD)) != 0) {
		which = "current card";
		goto error;
	}

	if ((ret = agent_get_num(a, &current_card, PPP_FIELD_UNSALTED_COUNTER)) != 0) {
		which = "counter";
		goto error;
	}

	if ((ret = agent_get_num(a, &current_card, PPP_FIELD_UNSALTED_COUNTER)) != 0) {
		which = "counter";
		goto error;
	}


	printf(_("Current card        = "));
	num_print_dec(current_card);
	printf("\n");

	/* Counter */
	printf(_("Current code        = "));
	num_print_dec(unsalted_counter);
	printf("\n");

	ppp_get_mpz(s, PPP_FIELD_LATEST_CARD, &tmp);
	printf(_("Latest printed card = "));
	num_print_dec(tmp);
	printf("\n");

	ppp_get_mpz(s, PPP_FIELD_MAX_CARD, &tmp);
	printf(_("Max card            = "));
	num_print_dec(tmp);
	printf("\n");

	ppp_get_mpz(s, PPP_FIELD_MAX_CODE, &tmp);
	printf(_("Max code            = "));
	num_print_dec(tmp);
	printf("\n");

	return 0;
error:
	print(PRINT_ERROR, "Error while reading state data: %s (%d)\n",
	      agent_strerror(ret), ret);
	return ret;
}

int ah_show_flags(agent *a)
{
	int ret;

	int flags = -1;
	int codelength = -1;
	int alphabet = -1;
	const char *label = NULL;
	const char *contact = NULL;

	/*** Query agent for required data ***/
	ret = agent_flag_get(a);
	if (ret != 0) {
		print(PRINT_ERROR, _("Unable to read flags: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}
	flags = agent_hdr_get_arg_int(a);

	/* const num_t r_num = agent_hdr_get_arg_num(a);
	   const char *r_str = agent_hdr_get_arg_str(a);
	*/
	


	/* Display flags */
	if (flags & FLAG_SHOW)
		printf(_("show=on "));
	else
		printf(_("show=off "));

	if (flags & FLAG_DISABLED)
		printf(_("disabled=on "));
	else
		printf(_("disabled=off "));

	printf(_("alphabet=%d "), alphabet);
	printf(_("codelength=%d "), code_length);

	if (flags & FLAG_SALTED)
		printf(_("(salt=on)\n"));
	else
		printf(_("(salt=off)\n"));


	if (label && strlen(label) > 0) {
		printf(_("Passcard label=\"%s\", "), label);
	} else {
		printf(_("No label, "));
	}

	if (contact && strlen(contact) > 0) {
		printf(_("contact=\"%s\".\n"), contact);
	} else {
		printf(_("no contact information.\n"));
	}

	if (s->spass_set) {
		printf(_("Static password is set.\n"));
	} else {
		printf(_("Static password is not set.\n"));
	}

	/* Verify policy and inform user what's wrong, so he can fix it. */
#if 0
	if (ppp_verify_alphabet(alphabet) != 0) {
		printf(_("WARNING: Current alphabet setting is "
		       "inconsistent with the policy!\n"));
	}

	if (ppp_verify_code_length(code_length) != 0) {
		printf(_("WARNING: Current passcode length setting is "
		       "inconsistent with the policy!\n"));
	}

	/* Show */
	if (flags & FLAG_SHOW && cfg->show == CONFIG_DISALLOW) {
		printf(_("WARNING: Show flag is enabled, but policy "
		       "denies it's use!\n"));
	}

	if (!(flags & FLAG_SHOW) && cfg->show == CONFIG_ENFORCE) {
		printf(_("WARNING: Show flag is disabled, but policy "
		       "enforces it's use!\n"));
	}

	/* Salted */
	if (flags & FLAG_SALTED && cfg->salt == CONFIG_DISALLOW) {
		printf(_("WARNING: Key is salted, but policy "
		       "denies such configuration. Regenerate key!\n"));

	}

	if (!(flags & FLAG_SALTED) && cfg->salt == CONFIG_ENFORCE) {
		printf(_("WARNING: Key is not salted, but policy "
		       "denies such configuration. Regenerate key!\n"));
	}
#endif
}

void ah_show_keys(const state *s)
{
	assert(s->codes_on_card > 0);

	/* Print key in LSB as PPPv3 likes */
	printf(_("Key     = ")); crypto_print_hex(s->sequence_key, 32);

	/* This prints data MSB */
	/* gmp_printf(_("Key     = %064ZX\n"), s->sequence_key); */
	printf(_("Counter = "));
	num_print_hex(s->counter, 1);
	printf("\n");
}

#if 0

int ah_update_flags(options_t *options, state *s, int generation)
{
	int ret;
	cfg_t *cfg = cfg_get();
	assert(options);
	assert(cfg);
	assert(s);

	/* User tries to change salt when he has key generated? */
	if ((generation == 0) && 
	    (options->flag_set_mask & FLAG_SALTED || 
	     options->flag_clear_mask & FLAG_SALTED)) {
		printf(_("Salt configuration can be changed only during key creation.\n"));
		return 1;
	}

	/* Tries to disable/enable himself when not allowed? */
	if (cfg->disabling == CONFIG_DISALLOW) {
		if (options->flag_set_mask & FLAG_DISABLED ||
		    options->flag_clear_mask & FLAG_DISABLED) {
			printf(_("Changing a \"disable\" flag disallowed by policy.\n"));
			return 1;
		}
	}

	/* Check policy of salt */
	switch (cfg->salt) {
	case CONFIG_DISALLOW:
		if (options->flag_set_mask & FLAG_SALTED) {
			printf(_("Policy disallows salted keys.\n"));
			return 1;
		}
		break;
	case CONFIG_ENFORCE:
		if (options->flag_clear_mask & FLAG_SALTED) {
			printf(_("Policy enforces salted keys.\n"));
			return 1;
		}
		break;
	case CONFIG_ALLOW:
	default:
		break;
	}

	/* Check policy of show */
	switch (cfg->show) {
	case CONFIG_DISALLOW:
		if (options->flag_set_mask & FLAG_SHOW) {
			printf(_("Policy disallows showing entered passcodes.\n"));
			return 1;
		}
		break;
	case CONFIG_ENFORCE:
		if (options->flag_clear_mask & FLAG_SHOW) {
			printf(_("Policy enforces entered passcode visibility.\n"));
			return 1;
		}
		break;
	case CONFIG_ALLOW:
	default:
		break;
	}

	/* Copy all user-selected values to state
	 * but check if they match policy */

	/* Length of contact/label is ensured in process_cmd_line */
	if (options->contact) {
		ret = ppp_set_str(s, PPP_FIELD_CONTACT, options->contact,
				  security_is_privileged() ? 0 : PPP_CHECK_POLICY);

		switch (ret) {
		case PPP_ERROR_ILL_CHAR:
			printf(_("Contact contains illegal characters.\n"
			         "Only alphanumeric + \" -+.@_*\" are allowed.\n"));
			return ret;

		case PPP_ERROR_TOO_LONG:
			printf(_("Contact can't be longer than %d "
			         "characters\n"), STATE_CONTACT_SIZE-1);
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Contact changing denied by policy.\n"));
			return ret;

		case 0:
			break;
		default:
			printf(_("Unexpected error while setting contact information.\n"));
			return 1;
		}
	}

	if (options->label) {
		ret = ppp_set_str(s, PPP_FIELD_LABEL, options->label,
				  security_is_privileged() ? 0 : PPP_CHECK_POLICY);
		switch (ret) {
		case PPP_ERROR_ILL_CHAR:
			printf(_("Label contains illegal characters.\n"
			         "Only alphanumeric + \" -+.@_*\" are allowed.\n"));
			return ret;

		case PPP_ERROR_TOO_LONG:
			printf(_("Label can't be longer than %d "
			       "characters\n"), STATE_LABEL_SIZE-1);
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Label changing denied by policy.\n"));
			return ret;

		case 0:
			break;

		default:
			printf(_("Unexpected error while setting label information.\n"));
			return 1;
		}
	}

	/* Code length + alphabet */
	if (options->set_codelength != -1) {
		ret = ppp_set_int(s, PPP_FIELD_CODE_LENGTH, options->set_codelength, 1);
		switch (ret) {
		case PPP_ERROR_RANGE:
			printf(_("Passcode length must be between 2 and 16.\n"));
			return ret;

		case PPP_ERROR_POLICY:
			printf(_("Setting passcode length denied by policy.\n"));
			return ret;
		case 0:
			break;
		default: 
			printf(_("Unexpected error while setting code length.\n"));
			return 1;
		}

		printf(_("Warning: Changing codelength invalidates "
		       "already printed passcards.\n"
		       "         If you like, you can switch back "
		       "to your previous settings.\n\n"));
	}

	if (options->set_alphabet != -1) {
		ret = ppp_set_int(s, PPP_FIELD_ALPHABET, options->set_alphabet, 1);
		switch (ret) { 
		case PPP_ERROR_RANGE:
			printf(_("Illegal alphabet ID specified. See "
			       "-f alphabet-list\n"));
			return ret;
		case PPP_ERROR_POLICY:
			printf(_("Alphabet denied by policy. See "
			       "-f alphabet-list\n"));
			return ret;
		case 0:
			
			break;
		default:
			printf(_("Unexpected error while setting code length.\n"));
			return 1;
		} 

		printf(_("Warning: Changing alphabet invalidates "
		       "already printed passcards.\n"
		       "         If you like, you can switch back "
		       "to your previous settings.\n\n"));
	}

	/* Change flags */
	ppp_flag_add(s, options->flag_set_mask);
	ppp_flag_del(s, options->flag_clear_mask);
	return 0;
}

/* Parse specification of passcode or passcard from "spec" string
 * Result save to passcode (and return 1) or to passcard (and return 2)
 * any other return value means error 
 */
int ah_parse_code_spec(const state *s, const char *spec, num_t *passcard, num_t *passcode)
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
		mpz_set(*passcode, s->counter);
	} else if (strcasecmp(spec, "[current]") == 0) {
		/* Current passcode */
		selected = 2;
		mpz_set(*passcard, s->current_card);
	} else if ((strcasecmp(spec, "next") == 0) ||
		   (strcasecmp(spec, "[next]") == 0)) {
		/* Next passcard. */
		selected = 2;

		/* Set passcard to latest_card + 1, but if 
		 * current code is further than s->latest_card
		 * then start printing from current_card */
		if (mpz_cmp(s->current_card, s->latest_card) > 0) {
			mpz_set(*passcard, s->current_card);
		} else {
			mpz_add_ui(*passcard, s->latest_card, 1);
		}
	} else if (isascii(spec[0]) && isalpha(spec[0])) {
		/* Format: CRR[number]; TODO: allow RRC[number] */
		char column;
		int row;
		char number[41];
		ret = sscanf(spec, "%c%d[%40[^]]s]", &column, &row, number);
		column = toupper(column);
		if (ret != 3 || (column < OPTION_ALPHABETS || column > 'J')) {
			printf(_("Incorrect passcode specification. (%d)\n"), ret);
			goto error;
		}

		ret = num_import(passcard, number, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Incorrect passcard specification (%s).\n"), number);
			goto error;
		}

		if (!ah_is_passcard_in_range(s, *passcard)) {
			printf(_("Passcard number out of range. "
			         "First passcard has number 1.\n"));
			goto error;
		}

		/* ppp_get_passcode_number adds salt as needed */
		ret = ppp_get_passcode_number(s, *passcard, passcode, column, row);
		if (ret != 0) {
			printf(_("Error while parsing passcard description.\n"));
			goto error;
		}

		selected = 1;

	} else if (isdigit(spec[0])) {
		/* All characters must be a digit! */
		int i;
		for (i=0; spec[i]; i++) {
			if (!isdigit(spec[i])) {
				printf(_("Illegal passcode number!\n"));
				goto error;
			}
		}

		/* number -- passcode number */
		ret = num_import(passcode, spec, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Error while parsing passcode number.\n"));
			goto error;
		}

		if (!ah_is_passcode_in_range(s, *passcode)) {
			printf(_("Passcode number out of range.\n"));
			goto error;
		}

		mpz_sub_ui(*passcode, *passcode, 1);

		/* Add salt as this number came from user */
		ppp_add_salt(s, passcode);

		selected = 1;
	} else if (spec[0] == '[' && spec[strlen(spec)-1] == ']') {
		/* [number] -- passcard number */

		/* Erase [,] characters */
		char number[41] = {0};
		ret = sscanf(spec, "[%40[^]s]", number);
		if (ret != 1) {
			printf("Strange error while parsing passcard number.\n");
			goto error;
		}

		ret = num_import(passcard, number, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Error while parsing passcard number (%s).\n"), number);
			goto error;
		}

		if (!ah_is_passcard_in_range(s, *passcard)) {
			printf(_("Passcard out of accessible range.\n"));
			goto error;
		}

		selected = 2;
	} else {
		printf(_("Illegal argument passed to option.\n"));
		goto error;
	}

	return selected;
error:
	return 5;
}


#endif
