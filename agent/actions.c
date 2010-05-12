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

#include <assert.h>

/* libotp header */
#include "ppp.h"

/* Utility headers */
#include "actions.h"
#include "security.h"

/* Generate new key */
int action_key_generate(state *s, const char *username)
{
	cfg_t *cfg = cfg_get();
	int retval = 1;

	int ret;

	assert(s);
	assert(username);

	if (state_init(&s, username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		return 1;
	}

	/* We are not removing, read flags, update them
	 * with user options and ask if he likes it */
	ret = ah_update_flags(options, &s, 1);
	if (ret != 0) {
		retval = 1;
		goto cleanup;
	}

		printf("This is your previous configuration updated with command line options:\n");
		ah_show_flags(&s);
		printf("\nYou can either use it, or start with default one "
			 "(modified by any --config options).\n");
		if (ah_enforced_yes_or_no(
			    "Do you want to keep this configuration?") == QUERY_NO) {
			printf("Reverting to defaults.\n");
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
			printf("Unable to load your state, nothing to remove.\n");
			goto cleanup;
		}

		if (!remove && 
		    security_is_privileged() == 0 &&
		    cfg->key_generation == CONFIG_DISALLOW) {
			printf("Key generation denied by policy.\n");
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
		print(PRINT_ERROR, "Unable to generate new key\n");
		goto cleanup;
	}


	printf("Key stored! One-time passwords enabled for this account.\n");
	retval = 0;

cleanup:
	state_fini(&s);
	return retval;
}



int action_key_store(state **s, const char *username)
{
	/* Lock, store, unlock */
	if (state_lock(&s) != 0) {
		print(PRINT_ERROR, "Unable to lock state database.\n");
		goto cleanup;
	}

	ret = state_store(&s, 0);

	if (state_unlock(&s) != 0) {
		print(PRINT_ERROR, "Unable to unlock state database.\n");
		/* As we will soon quit don't die here */
	}

	if (ret != 0) {
		print(PRINT_ERROR, "Unable to save state.\n");
		print(PRINT_NOTICE, "(%s)\n", ppp_get_error_desc(ret));
		goto cleanup;
	}
}


int action_key_remove(state **s, const char *username)
{
	cfg_t *cfg = cfg_get();
	int retval = 1;

	int ret;
	state s;

	if (state_init(&s, username) != 0) {
		print(PRINT_ERROR, "Unable to initialize state\n");
		return 1;
	}

	/* Check existance of key. Do not remove anything non-existing... */
	if (state_load(&s) == 0) {
	}

		/* We loaded state correctly, key exists */
		puts(
			"*************************************************\n"
			"* This will irreversibly erase your key, making *\n"
			"*    all already printed passcards worthless!   *\n"
			"*************************************************\n"
		);

		if (ah_yes_or_no("Are you sure you want to continue?") != 0) {
			printf("Stopping\n");
			goto cleanup;
		}

		/* If we were supposed to remove the key do it now */
		if (remove) {
			if (state_lock(&s) != 0) {
				print(PRINT_ERROR, "Unable to lock state for removing.\n");
				goto cleanup;
			}

			ret = state_store(&s, 1);

			if (state_unlock(&s) != 0) {
				print(PRINT_ERROR, "Unable to unlock state database.\n");
				/* As we will soon quit don't die here */
			}

			if (ret == 0) {
				printf("Key removed!\n");
				retval = 0;
			} else {
				printf("Error while removing key!\n");
				retval = 1;
			}
			goto cleanup;
		}
}
