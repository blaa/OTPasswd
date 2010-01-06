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

#include <string.h>
#include <stdlib.h>

/* stat() */
#include <sys/stat.h>
#include <unistd.h>

/* waitpid() */
#include <sys/wait.h>

/* kill() */
#include <signal.h>

#include <pam_modules.h>

/* FreeBSD */
#include <pam_appl.h>

#include "pam_macros.h"

#include "print.h"
#include "num.h"
#include "ppp.h"
#include "pam_helpers.h"

int ph_parse_module_options(int flags, int argc, const char **argv, cfg_t *cfg)
{
	for (; argc-- > 0; argv++) {
		if (strcmp("audit", *argv) == 0)
			cfg->logging = 2;
		else if (strcmp("debug", *argv) == 0)
			cfg->logging = 3;
		else if (strcmp("silent", *argv) == 0)
			cfg->silent = 1;
		else {
			print(PRINT_ERROR, 
				"Invalid parameter %s\n", *argv);
		}
	}

	if (flags & PAM_SILENT) {
		cfg->silent = 1;
	}

	return 0;
}

int ph_out_of_band(const cfg_t *cfg, state *s)
{
	int retval;
	char current_passcode[17] = {0};
	char contact[STATE_CONTACT_SIZE];

	/* We musn't have lock on state when running this function */

	/* Check if OOB enabled */
	if (cfg->oob_path == NULL || cfg->oob == 0) {
		print(PRINT_WARN,
			    "Trying OOB when it's not enabled\n");
		return 1;
	}

	/* Ensure cfg->oob_path is correct */
	{
		struct stat st;
		if (stat(cfg->oob_path, &st) != 0) {
			print(PRINT_ERROR,
				     "Unable to access oob sender. "
				     "Check oob_path parameter\n");
			return 2;
		}
		
		if (!S_ISREG(st.st_mode)) {
			print(PRINT_ERROR,
				    "oob_path is not a file!\n");
			return 2;
		}

		if ( (S_ISUID & st.st_mode) || (S_ISGID & st.st_mode) ) {
			print(PRINT_ERROR,
				    "oob_path is SUID or SGID!\n");
			return 2;
		}
		
		/* Check permissions */
		if (st.st_mode & S_IXOTH) {
			print(PRINT_WARN, 
				    "Others can execute OOB utility\n");
		} else {
			/* That's cool, but can we execute it? */
			const int can_owner = 
				((st.st_mode & S_IXUSR) &&
				 st.st_uid == cfg->oob_uid);
			const int can_group =
				((st.st_mode & S_IXGRP) &&
				 st.st_gid == cfg->oob_gid);
			if (! (can_owner || can_group) ) {
				/* Neither from group nor from 
				 * owner mode */
				/* TODO: testcase this check */
				print(PRINT_ERROR,
					    "UID %d is unable to execute "
					    "OOB utility!\n", cfg->oob_uid);
				return 2;
			}
		}
	}

	/* Gather required data */
	retval = ppp_get_current(s, current_passcode);
	if (retval != 0)
		return retval;

	const char *c;
	retval = ppp_get_str(s, PPP_FIELD_CONTACT, &c);
	if (retval != 0 || !c || strlen(c) == 0) {
		print(PRINT_WARN,
			    "User without contact data "
			    "required OOB transmission\n");
		return 2;
	}
	/* Copy, as releasing state will remove this data from RAM */
	strncpy(contact, c, sizeof(contact)-1);

	pid_t new_pid;
	new_pid = fork();
	if (new_pid == -1) {
		print(PRINT_ERROR, 
			    "Unable to fork and call OOB utility\n");
		return 1;
	}

	if (new_pid == 0) {
		// TODO/FIXME: dangerous print, remove it 
		print(PRINT_NOTICE,
			    "Executing OOB transmission of %s to %s\n", 
			    current_passcode, contact);

		/* We don't want to leave state in memory! */
		/* TODO/FIXME: What with the locks? DB may unlock
		 * data if it was locked. */
		retval = ppp_release(s, 0, 0);
		// ppp_fini(s);
		if (retval != 0) {
			print(PRINT_ERROR, "RELEASE FAILED IN CHILD!");
			exit(10);
		}

		/* Drop root */
		retval = setgid(cfg->oob_gid);
		if (retval != 0) {
			print_perror(PRINT_ERROR,
				     "UNABLE TO CHANGE GID TO %d\n", cfg->oob_gid);
			exit(11);
		}

		retval = setuid(cfg->oob_uid);
		if (retval != 0) {
			print_perror(PRINT_ERROR, 
				     "UNABLE TO CHANGE UID TO %d\n", cfg->oob_uid);
			exit(12);
		}

		execl(cfg->oob_path, cfg->oob_path,
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
			print(PRINT_NOTICE,  "Waiting for  OOB return\n");
			continue;
		}
	}

	if (times == 0) {
		/* Timed out while waiting for it's merry death */
		kill(new_pid, 9);

		/* waitpid should return immediately now, but just wait to be sure */
		usleep(100);
		waitpid(new_pid, NULL, WNOHANG);
		print(PRINT_ERROR, 
			     "Timed out while waiting for OOB utility "
			     "to die. Fix it!\n");
		return 2;
	}

	print(PRINT_NOTICE, "OOB child returned fast\n");

	if (WEXITSTATUS(status) == 0)
		print(PRINT_NOTICE, "OOB utility successful\n");
	else {
		print(PRINT_WARN, 
			     "OOB utility returned %d\n", 
			     WEXITSTATUS(status));
	}

	return 0;
}

void ph_show_message(pam_handle_t *pamh, const cfg_t *cfg, const char *msg)
{
	/* Required for communication with user */
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;

	/* If silent enabled - don't print any messages */
	if (cfg->silent)
		return;


	/* Initialize conversation function */
	pam_get_item(pamh, PAM_CONV, (const void **)&conversation);

	/* Set message config, and show it. */
	message.msg_style = PAM_TEXT_INFO;
	message.msg = msg;
	conversation->conv(
		1,
		(const struct pam_message**)&pmessage,
		&resp, conversation->appdata_ptr);

	/* Drop any reply */
	if (resp)
		_pam_drop_reply(resp, 1);
}

int ph_increment(pam_handle_t *pamh, const cfg_t *cfg, const char *username, state *s)
{
	const char *enforced_msg = "OTPasswd: Key not generated, unable to login.";
	const char *lock_msg = "OTPasswd: Unable to lock state file.";
	const char *numspace_msg =
		"OTPasswd: Passcode counter overflowed or state "
		"file corrupted. Regenerate key.";
	const char *invalid_msg =
		"OTPasswd: Your state is invalid. "
		"Contact administrator.";
	const char *disabled_msg = 
		"OTPasswd: Your state is disabled. Unable to authenticate. "
		"Contact administrator.";
	const char *policy_msg = 
		"OTPasswd: Your state is inconsistent with "
		"system policy. Contact administrator.";

	switch (ppp_increment(s)) {
	case 0:
		/* Everything fine */
		return 0;

	case STATE_NUMSPACE:
		/* Strange error, might happen, but, huh! */
		ph_show_message(pamh, cfg, numspace_msg);
		print(PRINT_WARN,
		      "User \"%s\" runned out of passcodes.\n", username);
		return PAM_AUTH_ERR;

	case STATE_LOCK_ERROR:
		ph_show_message(pamh, cfg, lock_msg);
		print(PRINT_WARN, "Lock error while authenticating user");
		return PAM_AUTH_ERR;

	case STATE_NON_EXISTENT:
		/* TODO: Fail only if db=user? This shouldn't happen on GLOBAL. */
		if (cfg->enforce == 1 && cfg->db == CONFIG_DB_USER)
			goto enforced_fail;

		/* Otherwise we are just not configured correctly
		 * or we are not enforcing. */
		print(PRINT_WARN, 
		      "OTPasswd ignored. User \"%s\" not configured.\n",
		      username);
		return PAM_IGNORE;

	case STATE_NO_USER_ENTRY:
		if (cfg->enforce == 1)
			goto enforced_fail;

		print(PRINT_WARN, 
		      "OTPasswd ignored. User \"%s\" not configured.\n",
		      username);

		return PAM_IGNORE;

	case PPP_ERROR_POLICY:
		print(PRINT_ERROR, "State of \"%s\" contains data "
		      "contradictory to current policy. Update state.\n",
		      username);
		ph_show_message(pamh, cfg, policy_msg);
		return PAM_AUTH_ERR;

	case PPP_ERROR_RANGE:
		print(PRINT_ERROR,
		      "State of \"%s\" contains invalid data.\n",
		      username);

		ph_show_message(pamh, cfg, invalid_msg);
		return PAM_AUTH_ERR;

	case PPP_ERROR_DISABLED:
		if (cfg->enforce) {
			print(PRINT_WARN, 
			      "Authentication failure; user \"%s\" state "
			      "is disabled\n", username);

			ph_show_message(pamh, cfg, disabled_msg);
			return PAM_AUTH_ERR;
		} else {
			/* Not enforcing */
			print(PRINT_WARN, 
			      "Authentication ignored; user \"%s\" state "
			      "is disabled\n", username);

			return PAM_IGNORE;
		}

	default: /* Any other problem - error */
		return PAM_AUTH_ERR;
	}

enforced_fail:
	print(PRINT_WARN, 
	      "Authentication failed because of enforcement;"
	      " user \"%s\"\n", username);
	ph_show_message(pamh, cfg, enforced_msg);
	return PAM_AUTH_ERR;


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
	if (pam_get_item(pamh, PAM_CONV, (const void **)&conversation) != PAM_SUCCESS)
		return NULL;

	/* Echo on if enforced by "show" option or enabled by user
	 * and not disabled by "noshow" option
	 */
	if (show) {
		message.msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		message.msg_style = PAM_PROMPT_ECHO_OFF;
	}

	message.msg = prompt;

	conversation->conv(1, (const struct pam_message **)&pmessage,
			   &resp, conversation->appdata_ptr);

	return resp;
}

int ph_init(pam_handle_t *pamh, int flags, int argc, const char **argv,
            cfg_t **cfg, state **s, const char **username)
{
	/* User info from PAM */
	const char *user = NULL;

	int retval;

	/* Set safe umask */
	umask(077);

	/* Bootstrap logging */
	print_init(PRINT_NOTICE, 0, 1, NULL);

	/* Ensure GMP frees memory safely */
	num_init();

	/* Load default options + ones defined in config file */
	*cfg = cfg_get();

	if (!*cfg) {
		print(PRINT_ERROR, "Unable to read config file\n");
		retval = PAM_SERVICE_ERR;
		goto error;
	}

	/* Parse additional options passed to module */
	retval = ph_parse_module_options(flags, argc, argv, *cfg);

	if (retval != 0) {
		goto error;
	}


	/* Initialize correctly internal debugging */
	int log_level = PRINT_NOTICE;
	switch ((*cfg)->logging) {
	case 0: log_level = PRINT_NONE; break;
	case 1: log_level = PRINT_ERROR; break;
	case 2: log_level = PRINT_WARN; break;
	case 3: log_level = PRINT_NOTICE; break;
	default:
		print(PRINT_ERROR,
		      "This should never happen. "
		      "Illegal cfg->logging value\n");
	}

	/* Close bootstrapped logging */
	print_fini();

	print_init(log_level, 0, 1, NULL);
	print(PRINT_NOTICE, "otpasswd started\n");

	/* We must know the user of whom we must find state data */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS && user) {
		print(PRINT_ERROR, "pam_get_user %s", pam_strerror(pamh,retval));
		retval = PAM_USER_UNKNOWN;
		goto error;
	}

	if (user == NULL || *user == '\0') {
		print(PRINT_ERROR, "empty_username", pam_strerror(pamh,retval));
		retval = PAM_USER_UNKNOWN;
		goto error;
	}

	/* Initialize state with given username */
	retval = ppp_init(s, user); 
	if (retval != 0) {
		/* This will fail if, for example, we're 
		 * unable to locate home directory */
		retval = PAM_USER_UNKNOWN;
		goto error;
	}

	/* Read username back. Our local state-bound copy */
	retval = ppp_get_str(*s, PPP_FIELD_USERNAME, username);
	if (retval != 0 || !**username) {
		print(PRINT_ERROR, "Internal error: Unable to"
		      " read username data from state.\n");
		retval = PAM_AUTH_ERR;
		goto error;
	}

	/* All ok */
	return 0;
error:
	print_fini();
	return retval;
}

void ph_fini(state *s)
{
	ppp_fini(s);
	print(PRINT_NOTICE, "otpasswd finished\n");
	print_fini();
}
