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

#include "ppp_common.h"
#include "agent_interface.h"

/* For options_t struct */
#include "actions.h" 
#include "actions_helpers.h"
#include "security.h"
#include "nls.h"

#include "crypto.h" /* crypto_print_hex */

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
		print(PRINT_ERROR, _("Unable to turn off character visibility!\n"));
		return NULL;
	}
	
	copy = t.c_lflag;
	t.c_lflag &= ~ECHO;

	if (tcsetattr(0, 0, &t) != 0) {
		print(PRINT_ERROR, _("Unable to turn off character visibility!\n"));
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
	int failures, recent_failures;
	const char *which = NULL;

	if ((ret = agent_get_num(a, PPP_FIELD_CURRENT_CARD, &current_card)) != 0) {
		which = "current card";
		goto error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_UNSALTED_COUNTER, &unsalted_counter)) != 0) {
		which = "counter";
		goto error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_LATEST_CARD, &latest_card)) != 0) {
		which = "latest card";
		goto error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_MAX_CARD, &max_card)) != 0) {
		which = "max card";
		goto error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_MAX_CODE, &max_code)) != 0) {
		which = "max code";
		goto error;
	}

	if ((ret = agent_get_int(a, PPP_FIELD_FAILURES, &failures)) != 0) {
		which = "failures";
		goto error;
	}

	if ((ret = agent_get_int(a, PPP_FIELD_RECENT_FAILURES, &recent_failures)) != 0) {
		which = "recent failures";
		goto error;
	}


	printf(_("Current card        = "));
	num_print_dec(current_card);
	printf("\n");

	printf(_("Current code        = "));
	num_print_dec(unsalted_counter);
	printf("\n");

	printf(_("Latest printed card = "));
	num_print_dec(latest_card);
	printf("\n");

	printf(_("Max card            = "));
	num_print_dec(max_card);
	printf("\n");

	printf(_("Max code            = "));
	num_print_dec(max_code);
	printf("\n");

	printf(_("All auth failures   = %d\n"), failures);
	printf(_("Recent failures     = %d\n"), recent_failures);

	return 0;
error:
	print(PRINT_ERROR, "Error while reading field %s: %s (%d)\n",
	      which, agent_strerror(ret), ret);
	return ret;
}

int ah_show_flags(agent *a)
{
	int ret;

	int flags = -1;
	int code_length = -1;
	int alphabet = -1;
	char *label = NULL;
	char *contact = NULL;

	/*** Query agent for required data ***/
	ret = agent_flag_get(a, &flags);
	if (ret != 0) {
		print(PRINT_ERROR, _("Unable to read flags: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}

	if ((ret = agent_get_int(a, PPP_FIELD_CODE_LENGTH, &code_length)) != 0) {
		print(PRINT_ERROR, _("Unable to read code length: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}

	if ((ret = agent_get_int(a, PPP_FIELD_ALPHABET, &alphabet)) != 0) {
		print(PRINT_ERROR, _("Unable to read alphabet id: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}

	if ((ret = agent_get_str(a, PPP_FIELD_CONTACT, &contact)) != 0) {
		print(PRINT_ERROR, _("Unable to read contact: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}

	if ((ret = agent_get_str(a, PPP_FIELD_LABEL, &label)) != 0) {
		print(PRINT_ERROR, _("Unable to read label: %s (%d)\n"), 
		      agent_strerror(ret), ret);
		goto cleanup;
	}
	


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
	printf(_("code_length=%d "), code_length);

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
/* TODO 
	if (s->spass_set) {
		printf(_("Static password is set.\n"));
	} else {
		printf(_("Static password is not set.\n"));
	}
*/


	ret = 0;
cleanup:
	if (contact)
		free(contact);
	if (label)
		free(label);

	return ret;
}


int ah_show_keys(agent *a, const options_t *options)
{
	unsigned char key[32];
	num_t counter;
	int ret;

	if ((ret = agent_get_key(a, key)) != 0) {
		goto sanitize;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_COUNTER, &counter)) != 0) {
		goto sanitize;
	}

	/* Print key in LSB as PPPv3 likes */
	printf(_("Key     = ")); crypto_print_hex(key, 32);

	/* This prints data MSB */
	printf(_("Counter = "));

	num_print_hex(counter, 1);
	printf("\n");

	ret = 0;

sanitize:
	memset(key, 0, sizeof(key));
	assert(sizeof(key) == 32);
	counter = num_ii(0,0);
	return ret;
}


int ah_set_options(agent *a, const options_t *options)
{
	int retval;
	const char *what = NULL;

	/* Set flags */
	if (options->flag_set_mask != 0) {
		retval = agent_flag_add(a, options->flag_set_mask);
		if (retval != 0) {
			what = "adding flag";
			goto error;
		}
	}

	if (options->flag_clear_mask != 0) {
		retval = agent_flag_clear(a, options->flag_clear_mask);
		if (retval != 0) {
			what = "clearing flag";
			goto error;
		}
	}

	/* Set code length */
	if (options->set_codelength != -1) {
		print(PRINT_NOTICE, "Trying to set code length.\n");
		retval = agent_set_int(a, PPP_FIELD_CODE_LENGTH, options->set_codelength);
		if (retval != 0) {
			what = "code length";
			goto error;
		}

	}
	/* Set alphabet */
	if (options->set_alphabet != -1) {
		print(PRINT_NOTICE, "Trying to set alphabet to %d.\n", options->set_alphabet);
		retval = agent_set_int(a, PPP_FIELD_ALPHABET, options->set_alphabet);		
		if (retval != 0) {
			what = "alphabet";
			goto error;
		}
	}

	/* Set contact */
	if (options->contact) {
		print(PRINT_NOTICE, "Trying to set contact.\n");
		retval = agent_set_str(a, PPP_FIELD_CONTACT, options->contact);
		if (retval != 0) {
			what = "contact";
			goto error;
		}
	}

	/* Set label */
	if (options->label) {
		print(PRINT_NOTICE, "Trying to set label.\n");
		retval = agent_set_str(a, PPP_FIELD_LABEL, options->label);
		if (retval != 0) {
			what = "label";
			goto error;
		}
	}

	return 0;
error:
	print(PRINT_WARN, _("Unable to set required option (%s): %s\n"), 
	      what, agent_strerror(retval));
	return retval;

}


/* Parse specification of passcode or passcard from "spec" string
 * Result returned as item. Code returned from function 
 * (PRINT_CODE or PRINT_CARD) determines what was decoded.
 */
int ah_parse_code_spec(agent *a, const char *spec, num_t *item)
{
	int ret;
	int selected;

	num_t current_card, unsalted_counter, latest_card, 
		max_card, max_code;

	int has_passcard_mark = 0, has_row_mark = 0, i;
	const int length = strlen(spec);

	const char *which = NULL;

	/* This data is needed to perform all conversions */
	if ((ret = agent_get_num(a, PPP_FIELD_CURRENT_CARD, &current_card)) != 0) {
		which = "current card";
		goto agent_error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_UNSALTED_COUNTER, &unsalted_counter)) != 0) {
		which = "counter";
		goto agent_error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_LATEST_CARD, &latest_card)) != 0) {
		which = "latest card";
		goto agent_error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_MAX_CARD, &max_card)) != 0) {
		which = "max card";
		goto agent_error;
	}

	if ((ret = agent_get_num(a, PPP_FIELD_MAX_CODE, &max_code)) != 0) {
		which = "max code";
		goto agent_error;
	}


	/* Has it got [ or ]? */
	for (i = 0; i < length; i++) {
		if (spec[i] == '[' || spec[i] == ']')
			has_passcard_mark = 1;

		/* This will detect also current/next etc. so validate after eliminating those options */
		if (isascii(spec[i]) && isalpha(spec[i]))
			has_row_mark++;
	}

	/* Multiple alphas are not a row mark */
	if (has_row_mark != 1)
		has_row_mark = 0;


	/* Determine what user wants to print(or skip) and parse it to
	 * either passcode number or passcard number. Remember what was
	 * read to selected so later we can print it
	 */
	if (strcasecmp(spec, "current") == 0) {
		/* Current passcode */
		selected = PRINT_CODE;
		*item = unsalted_counter;
	} else if (strcasecmp(spec, "[current]") == 0) {
		/* Current passcard */
		selected = PRINT_CARD;
		*item = current_card;
	} else if ((strcasecmp(spec, "next") == 0) ||
		   (strcasecmp(spec, "[next]") == 0)) {
		/* Next passcard. */
		selected = PRINT_CARD;

		/* Set passcard to latest_card + 1, but if 
		 * current code is further than s->latest_card
		 * then start printing from current_card */
		if (num_cmp(current_card, latest_card) > 0) {
			*item = current_card;
		} else {
			*item = num_add_i(latest_card, 1);
		}
	} else if (has_row_mark == 0 && isdigit(spec[0])) {
		/* Passcode given as integer */
		/* All characters must be a digit! */
		int i;
		for (i=0; spec[i]; i++) {
			if (!isdigit(spec[i])) {
				printf(_("Illegal passcode number!\n"));
				goto error;
			}
		}

		/* number -- passcode number */
		ret = num_import(item, spec, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Error while parsing passcode number.\n"));
			goto error;
		}

		if (num_cmp(num_i(1), *item) > 0) {
			ret = 1;
			printf(_("Passcode number out of range.\n"));
			goto error;
		}

		*item = num_sub_i(*item, 1);

		selected = PRINT_CODE;
	} else if (spec[0] == '[' && spec[length-1] == ']') {
		/* [number] -- passcard number */

		/* Erase [,] characters */
		char number[41] = {0};
		ret = sscanf(spec, "[%40[^]s]", number);
		if (ret != 1) {
			printf(_("Strange error while parsing passcard number.\n"));
			goto error;
		}

		ret = num_import(item, number, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Error while parsing passcard number (%s).\n"), number);
			goto error;
		}

		if (num_cmp(num_i(1), *item) > 0) {
			ret = 1;
			printf(_("Passcode number out of range.\n"));
			goto error;
		}

		selected = PRINT_CARD;


		/* ALL other possibilities including [] are used up. Two are left */
	} else if (has_passcard_mark) {
		char column;
		int row;
		char number[41];
		num_t card = num_i(0);

		if (isascii(spec[0]) && isalpha(spec[0])) {
			/* Format: CRR[number] */
			ret = sscanf(spec, "%c%d[%40[^]]s]", &column, &row, number);
		} else if (isdigit(spec[0])) {
			/* Format: RRC[number] */
			ret = sscanf(spec, "%d%c[%40[^]]s]", &row, &column, number);
		} else {
			printf(_("Incorrect passcode specification.\n"));
			goto error;
		}

		column = toupper(column);
		if (ret != 3 || (column < OPTION_ALPHABETS || column > 'J')) {
			printf(_("Incorrect passcode specification. (%d)\n"), ret);
			goto error;
		}

		ret = num_import(&card, number, NUM_FORMAT_DEC);
		if (ret != 0) {
			printf(_("Incorrect passcard specification (%s).\n"), number);
			goto error;
		}

		if (num_cmp(num_i(1), card) > 0) {
			ret = 1;
			printf(_("Passcard numbering starts with 1.\n"));
			goto error;
		}

		ret = ah_get_passcode_number(a, card, item, column, row);
		if (ret != 0) {
			print(PRINT_ERROR, _("Error while deciphering passcode specification\n"));
			return ret;
		}

		selected = PRINT_CODE;
	} else {
		printf(_("Illegal argument passed to option.\n"));
		goto error;
	}

	return selected;

error:
	return -1;

agent_error:
	print(PRINT_ERROR, "Error while reading field %s: %s\n",
	      which, agent_strerror(ret));
	return 5;
}



int ah_get_passcode_number(agent *a, const num_t passcard, num_t *passcode, char column, char row)
{
	int ret;
	int codes_in_row, codes_on_card;
	
	const char *which = NULL;

	/* This data is needed to perform all conversions */
	if ((ret = agent_get_int(a, PPP_FIELD_CODES_ON_CARD, &codes_on_card)) != 0) {
		which = "codes on card";
		goto error;
	}

	if ((ret = agent_get_int(a, PPP_FIELD_CODES_IN_ROW, &codes_in_row)) != 0) {
		which = "codes in row";
		goto error;
	}


	if (column < 'A' || column >= 'A' + codes_in_row) {
		printf(_("Column out of possible range!\n"));
		return 1;
	}

	if (row < 1 || row > 10) {
		printf(_("Row out of range!\n"));
		return 1;
	}

	/* Start with calculating first passcode on card */
	/* passcode = (passcard-1)*codes_on_card + salt */
	*passcode = num_sub_i(passcard, 1);
	*passcode = num_mul_i(*passcode, codes_on_card);

	/* Then add location on card */
	*passcode = num_add_i(*passcode, (row - 1) * codes_in_row);
	*passcode = num_add_i(*passcode, column - 'A');

	return 0;

error:
	print(PRINT_ERROR, "Error while reading field %s: %s\n",
	      which, agent_strerror(ret));
	return ret;
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
			       "-c alphabet=list\n"));
			return ret;
		case PPP_ERROR_POLICY:
			printf(_("Alphabet denied by policy. See "
			       "-c alphabet=list\n"));
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


#endif
