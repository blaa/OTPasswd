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

#define PAM_SM_AUTH
#define PAM_SM_SESSION
//#define PAM_SM_ACCOUNT
//#define PAM_SM_PASSWORD
#define _PAM_EXTERN_FUNCTIONS

#include <_pam_macros.h>
#include <pam_modules.h>
#include <pam_misc.h>
#include <pam_ext.h>

/* stat() */
#include <sys/stat.h>
#include <unistd.h>

/* waitpid() */
#include <sys/wait.h>

/* kill() */
#include <signal.h>


#include "print.h"
#include "ppp.h"
#include "pam_helpers.h"

int ph_parse_module_options(options *opt, int argc, const char **argv)
{
	for (; argc-- > 0; argv++) {
		if (strcmp("debug", *argv) == 0)
			opt->debug = 1;
		else if (strcmp("silent", *argv) == 0)
			opt->debug = 1;

#if 0
		} else if (sscanf(*argv, "oob_path=%199s", 
				  opt->oob_path) == 1) {
			/* Ensure path is correct */
			struct stat st;
			if (stat(opt->oob_path, &st) != 0) {
				(void) print(PRINT_ERROR,
					"Unable to access oob sender. "
					"Check oob_path parameter\n");
				goto error;
			}

			if (!S_ISREG(st.st_mode)) {
				(void)print(PRINT_ERROR,
					"oob_path is not a file!\n");
				goto error;
			}

			/* Check permissions */
			if (st.st_mode & S_IXOTH) {
				(void)print(PRINT_WARN, 
					"Others can execute OOB utility\n");
			} else {
				/* That's cool, but can we execute it? */
				const int can_owner = 
					((st.st_mode & S_IXUSR) &&
					 st.st_uid == opt->uid);
				const int can_group =
					((st.st_mode & S_IXGRP) &&
					 st.st_gid == opt->gid);
				if (! (can_owner || can_group) ) {
					/* Neither from group nor from 
					 * owner mode */
					/* TODO: testcase this */
					(void)print(PRINT_ERROR,
						    SECURE_USERNAME 
						    " is unable to execute "
						    "OOB utility!\n");
					goto error;
				}
			}
#endif
		else {
			(void)print(PRINT_ERROR, 
				"Invalid parameter %s\n", *argv);
			goto error;
		}
	}
	return 0;

error:
	(void)print(PRINT_ERROR, "Error while parsing parameters\n");
	return PAM_AUTH_ERR;
}

/* Send out of band message by calling external script 
 * state parameter is generally const, but child will 
 * clean it up */
int ph_out_of_band(const options *opt, state *s)
{
	int retval;
	char current_passcode[17] = {0};
	char contact[STATE_CONTACT_SIZE];

	/* Check if OOB enabled */
	if (opt->oob_path == NULL || opt->oob == 0) {
		(void)print(PRINT_WARN,
			    "Trying OOB when it's not enabled\n");
		return 1;
	}

	/* Gather required data */
	retval = ppp_get_current(s, current_passcode);
	if (retval != 0)
		return retval;

	const char *c = ppp_get_contact(s);
	if (!c || strlen(c) == 0) {
		(void)print(PRINT_WARN,
			    "User without contact data "
			    "required OOB transmission\n");
		return 2;
	}
	/* Copy, as releasing state will remove this data from RAM */
	strncpy(contact, c, sizeof(contact)-1);

	pid_t new_pid;
	new_pid = fork();
	if (new_pid == -1) {
		(void)print(PRINT_ERROR, 
			    "Unable to fork and call OOB utility\n");
		return 1;
	}

	if (new_pid == 0) {
		// dangerous print, remove it 
		(void)print(PRINT_NOTICE,
			    "Executing OOB transmission of %s to %s\n", 
			    current_passcode, contact);

		/* We don't want to leave state in memory! */
		/* TODO/FIXME: What with the locks? */
		retval = ppp_release(s, 0, 0);
		if (retval != 0) {
			(void)print(PRINT_ERROR, "RELEASE FAILED IN CHILD!");
			exit(10);
		}

		/* Drop root */
		retval = setgid(opt->gid);
		if (retval != 0) {
			print_perror(PRINT_ERROR,
				     "UNABLE TO CHANGE GID TO %d\n", opt->gid);
			exit(11);
		}

		retval = setuid(opt->uid);
		if (retval != 0) {
			print_perror(PRINT_ERROR, 
				     "UNABLE TO CHANGE UID TO %d\n", opt->uid);
			exit(12);
		}

		execl(opt->oob_path, opt->oob_path,
		      contact, current_passcode, NULL);

		/* Whoops */
		print_perror(PRINT_ERROR, 
			     "OOB utility execve failed! Program error; "
			     "this should be detected beforehand");
		exit(13);
	}

	/*** Parent ***/
	/* Wait a bit for your child to finish.
	 * If it decides to hang up cheerfully kill it.
	 * Then clean up the bod^C^C garbage.
	 */
	int times;
	int status = 0;
	for (times = 200; times > 0; times--) {
		usleep(7000);
		retval = waitpid(new_pid, &status, WNOHANG);
		if (retval == new_pid)
			break; /* Our child finished */
		if (retval == -1) {
			print_perror(PRINT_ERROR, "waitpid failed");
			return 1;
		}
		if (retval == 0) {
			(void)print(PRINT_NOTICE,  "Waiting for  OOB return\n");
			continue;
		}
	}

	if (times == 0) {
		/* Timed out while waiting for it's merry death */
		(void) kill(new_pid, 9);

		/* waitpid should return immediately now, but just wait to be sure */
		usleep(100);
		(void) waitpid(new_pid, NULL, WNOHANG);
		(void) print(PRINT_ERROR, 
			     "Timed out while waiting for OOB utility "
			     "to die. Fix it!\n");
		return 2;
	}

	(void)print(PRINT_NOTICE, "OOB child returned fast\n");

	if (WEXITSTATUS(status) == 0)
		(void) print(PRINT_NOTICE, "OOB utility successful\n");
	else {
		(void) print(PRINT_WARN, 
			     "OOB utility returned %d\n", 
			     WEXITSTATUS(status));
	}

	return 0;
}


void ph_show_message(pam_handle_t *pamh, int flags, const char *msg)
{
	/* Required for communication with user */
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;

	/* Initialize conversation function */
	pam_get_item(pamh, PAM_CONV, (const void **)&conversation);

	if (!(flags & PAM_SILENT)) {
		/* Tell why */
		message.msg_style = PAM_TEXT_INFO;
		message.msg = msg;
		conversation->conv(
			1,
			(const struct pam_message**)&pmessage,
			&resp, conversation->appdata_ptr);
		if (resp)
			_pam_drop_reply(resp, 1);
	}

}

int ph_handle_load(pam_handle_t *pamh, int flags, int enforced, state *s)
{
	const char enforced_msg[] = "otpasswd: Key not generated, unable to login.";
	const char lock_msg[] = "otpasswd: Unable to lock user state file.";
	const char numspace_msg[] =
		"otpasswd: Passcode counter overflowed or state "
		"file corrupted. Regenerate key.";

	switch (ppp_increment(s)) {
	case 0:
		/* Everything fine */
		return 0;

	case STATE_NUMSPACE:
		/* Strange error, might happen, but, huh! */
		ph_show_message(pamh, flags, numspace_msg);
		return PAM_AUTH_ERR;

	case STATE_LOCK_ERROR:
		ph_show_message(pamh, flags, lock_msg);
		return PAM_AUTH_ERR;

	case STATE_DOESNT_EXISTS:
		if (enforced == 0) {
			/* Not enforced - ignore */
			return PAM_IGNORE;
		} else {
			ph_show_message(pamh, flags, enforced_msg);
		}

		/* Fall-throught */

	default: /* Any other problem - error */
		return PAM_AUTH_ERR;
	}

}

struct pam_response *ph_query_user(
	pam_handle_t *pamh, int flags, int show, const char *prompt, const state *s)
{
	/* Required for communication with user */
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;

	/* Initialize conversation function */
	pam_get_item(pamh, PAM_CONV, (const void **)&conversation);

	/* Echo on if enforced by "show" option or enabled by user
	 * and not disabled by "noshow" option
	 */
	if ((show == 2) || (show == 1 && (ppp_is_flag(s, FLAG_SHOW)))) {
		message.msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		message.msg_style = PAM_PROMPT_ECHO_OFF;
	}

	message.msg = prompt;
	conversation->conv(1, (const struct pam_message **)&pmessage,
			   &resp, conversation->appdata_ptr);

	return resp;
}

/* Initialization stuff */
int ph_init(pam_handle_t *pamh, int argc, const char **argv, options *opt, state **s)
{
	/* User info from PAM */
	const char *user = NULL;

	int retval;

	/* Bootstrap logging */
	print_init(PRINT_NOTICE, 0, 1, NULL);

	/* Parse options */
	retval = ph_parse_module_options(opt, argc, argv);

	/* Close bootstrapped logging */
	print_fini();

	if (retval != 0) {
		return retval;
	}

	/* Initialize internal debugging */
	if (opt->debug) {
		print_init(PRINT_NOTICE, 0, 1, "/tmp/otpasswd_dbg");
		(void)print(PRINT_NOTICE, "otpasswd started\n");
	} else
		print_init(PRINT_ERROR, 0, 1, NULL);

	/* We must know where to look for state file */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS && user) {
		(void)print(PRINT_ERROR, "pam_get_user %s", pam_strerror(pamh,retval));
		goto error;
	}

	if (user == NULL || *user == '\0') {
		(void)print(PRINT_ERROR, "empty_username", pam_strerror(pamh,retval));
		goto error;
	}

	/* Initialize state with given username */
	if (ppp_init(s, user) != 0) {
		/* This will fail if we're unable to locate home directory */
		goto error;
	}

	/* All ok */
	return 0;
error:
	print_fini();
	return PAM_USER_UNKNOWN;
}
