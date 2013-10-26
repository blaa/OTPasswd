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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <assert.h>

/* agent communication */
#include "agent_private.h"
#include "request.h"

/* libotp header */
#include "ppp.h"

/* Utility headers */
#include "security.h"
#include "testcases.h"
#include "nls.h"

/* Show any config validation errors */
int do_verify_config(void)
{
	int ret;
	cfg_t *cfg = NULL;
	state *s = NULL;

	(void) print_init(PRINT_NOTICE | PRINT_STDOUT, NULL);
	locale_init(); /* Only place where agent uses NLS */

	printf(_("Config file verification...\n"));
	cfg = cfg_get();
	if (!cfg) {
		printf(_("Error while loading config file.\n"));
		return 1;
	}
	printf(_("1) Config loaded correctly.\n"));

        if (cfg->db == CONFIG_DB_UNCONFIGURED) {
		printf(_("ERROR: DB option in config file is not set.\n"));
                return 2;
        } 
	printf(_("2) DB option is set.\n"));
	
	/* Verify permissions according to mode */
	ret = cfg_permissions();
	switch (ret) {
	default:
	case PPP_ERROR:
		printf(_("ERROR: Generic error while validating config file "
		         "permissions. (%d)\n"), ret);
		return 3;

	case PPP_ERROR_CONFIG_OWNERSHIP:
		printf(_("ERROR: Config file must be owned by root.\n"));
		return 4;
	case PPP_ERROR_CONFIG_PERMISSIONS:
		printf(_("ERROR: In selected mode config file should not be readable"
		         " by others.\n"));
		return 5;
	case 0:
		printf(_("3) Config file ownership and file mode is correct.\n"));
	}

	printf("4) SSHD, if used, should have ChallengeResponseAuthentication\n"
	       "   and UsePAM configured to 'yes' in sshd_config. Currently:\n");
	system("egrep 'UsePAM|ChallengeResponseAuthentication[ \t]+(yes|no)' /etc/ssh/sshd_config");

	if (cfg->db != CONFIG_DB_GLOBAL) {
		printf(_("5) Your selected DB option doesn't require further checks. "
		         "Everything is fine.\n"));
		return 0;
	}

	if (security_is_privileged() == 0) {
		printf(_("ERROR: To correctly validate GLOBAL DB configuration you have "
		         "to run this option as root.\n"));
		return 6;
	}


	printf(_("\n\nGlobal DB selected. Trying to initialize PPP and read state data "
	         "to see if DB exists.\n"));

	ret = ppp_init(PRINT_STDOUT, NULL);
	if (ret != 0) {
		printf(_("ERROR: ppp_init: %s\n"), ppp_get_error_desc(ret));
		ppp_fini();
		return 6;
	}
	print_config(PRINT_STDOUT | PRINT_NOTICE);

	printf(_("ppp_init OK\n"));


	ret = ppp_state_init(&s, "root");
	if (ret != 0) {
		printf(_("ERROR: Unable to create state: %s\n"), ppp_get_error_desc(ret));
		return 7;
	}
	printf(_("ppp_state_init OK\n"));

	ret = ppp_state_load(s, PPP_DONT_LOCK);
	switch (ret) {
	case 0:
		printf(_("5) State loaded\n"));
		break;

	case STATE_NON_EXISTENT:
	case STATE_NO_USER_ENTRY:
		printf(_("5) No state loaded, but no other errors. That's fine\n"));
		break;

	default:
		printf(_("ERROR: Error while trying to load state: %s\n"), ppp_get_error_desc(ret));
		printf(_("Check if you have %s\n"), cfg->global_db_path);
		ppp_state_fini(s);
		return 8;
	}	

	if (ret == 0) {
		ret = ppp_state_release(s, 0);
		if (ret != 0) {
			printf(_("ERROR while releasing state: %s\n"), 
				ppp_get_error_desc(ret));
			ppp_state_fini(s);
			return 9;
		}
	}

	ppp_state_fini(s);
	return 0;
}


/* Testcase function should be run only if we're not 
 * a SUID program or when we are run by root.
 * Also we should be connected to the terminal and
 * not to a pipe
 */
int do_testcase(int fast)
{
	cfg_t *cfg;
	int retval;
	int tmp;
	int failed = 0;

	printf("*** Running testcases\n");

	/* Init ppp for testcases */
	retval = ppp_init(PRINT_STDOUT, NULL);
	if (retval != 0) {
		(void) puts(ppp_get_error_desc(retval));
		printf("Testcasing failed:\n");
		printf("OTPasswd not correctly installed.\n");
		printf("Consult installation manual for detailed information.\n");
		ppp_fini();
		return 1;
	}
			
	/* Will succeed, as ppp_init suceeded */
	cfg = cfg_get();
	if (!cfg) {
		printf("FATAL: Unable to read config file.\n");
		return 1;
	}

	/* Change DB info so we won't overwrite anything
	 * important */
	strcpy(cfg->user_db_path, ".otpasswd_testcase");
	strcpy(cfg->global_db_path, "/tmp/otshadow_testcase");
	cfg->db = CONFIG_DB_USER;

	tmp = num_testcase(fast);
	failed += tmp;
	if (tmp)
		printf("******\n*** %d num testcases failed\n******\n", tmp);

	tmp = config_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d config testcases failed\n******\n", tmp);

	tmp = spass_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d static pass testcases failed\n*****", tmp);


	tmp = state_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d state testcases failed\n******\n", tmp);

	tmp = crypto_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d crypto testcases failed\n******\n", tmp);
	/*
	tmp = card_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d card testcases failed\n******\n", tmp);
	*/
	printf("******\n*** TODO: move card testcases to utility?\n******\n");

	tmp = ppp_testcase(fast);
	failed += tmp;
	if (tmp)
		printf("******\n*** %d ppp testcases failed\n******\n", tmp);


	if (failed) {
		printf(("***********************************************\n"
		        "*         !!! %d testcases failed !!!         *\n"
		        "* Don't use this release until this is fixed! *\n"
		        "* Note: Testcases should be run with default  *\n"
		        "* conpilation options and config.             *\n"
		        "* If unsure, reinstall and rerun --check      *\n"
		        "***********************************************\n"),
		       failed);
		retval = 1;
	} else {
		printf(("**********************************\n"
		        "* All testcases seem successful. *\n"
		        "**********************************\n"));
		retval = 0;
	}

	ppp_fini();
	return retval;
}

/** Marks end of initialization (succeeded or not) */
int send_init_reply(agent *a, int status, int error_code) 
{
	agent_hdr_set_status(a, status);
	agent_hdr_set_int(a, error_code, 0);
	agent_hdr_set_type(a, AGENT_REQ_INIT);
	return agent_hdr_send(a);
}

static int main_loop(agent *a)
{
	int ret;

	ret = send_init_reply(a, 0, 0);
	if (ret != 0) {
		(void) print(PRINT_ERROR, "Initial reply error; agent_hdr_send returned %d\n", ret);
		goto end;
	}

	print(PRINT_NOTICE, "\n*** Agent correctly initialized. Looping.\n");
	for (;;) {
		ret = request_handle(a);

		/* Correct quit message? */
		if (ret == AGENT_REQ_DISCONNECT) {
			print(PRINT_ERROR, "Agent finishing gracefully.\n");
			ret = 0;
			goto end;
		}

		/* Error */
		if (ret != 0) {
			print(PRINT_ERROR, "Agent finishing with error %d\n", ret);
			goto end;
		}
	}

end:
	if (agent_disconnect(a) != 0) {
		print(PRINT_WARN, "Errors while disconnecting agent.\n");
	}

	print(PRINT_NOTICE, "Agent closed.\n");
	ppp_fini();
	return ret;
}

int main(int argc, char **argv)
{
	int ret, error_desc = 0;
	char *username = NULL;
	agent *a = NULL;
	cfg_t *cfg = NULL;

	/* 1) Init safe environment, store current uids, etc. */
	security_init();

	if (security_is_tty_detached() == 0 || argc > 1) {
		/* We have stdout */
		/* Check if we should run testcases. */
		if (argc >= 2 && strcmp(argv[1], "--testcase") == 0) {
			if (security_is_suid() == 0 || security_is_privileged()) {
				int fast = 0;
				/* Support --fast for valgrind.
				 * Statistical tests will fail then, but will get run
				 */
				if (argc == 3 && strcmp(argv[2], "--fast") == 0) {
					fast = 1;
				}

				/* We're not suid or we are root already */
				return do_testcase(fast);
			}
		}

		if (argc == 2 && strcmp(argv[1], "--check-config") == 0) {
			if (!security_is_suid() || security_is_privileged()) {
				/* We're not suid or we are root already */
				return do_verify_config();
			}
		}

		printf("FATAL: This program should not be used like this.\n"
		       "Use appropriate interface instead (like otpasswd).\n\n");

		if (!security_is_suid()) {
			printf("Since this program is not SUID you can run\n"
			       "a set of testcases with --testcase option and check\n"
			       "config file propriety with --check-config\n");
		} else {
			if (security_is_privileged()) {
				printf("Since you're running this program as root you can\n"
				       "run a set of testcases with --check option and check\n"
				       "config file propriety with --check-config\n");

			} else {
				printf("Since this program is SUID-root only root can run it's\n"
				       "internal testcases or validate configuration file.\n");
			}
		}
		exit(EXIT_FAILURE);
	}

	/* After this point we:
	 * a) Have no controlling terminal. 
	 * b) Can be SUID root (run by root or normal user)
	 */

	/* Initialize agent struct so we can sent information
	 * about initialization errors */
	ret = agent_server(&a);
	if (ret != AGENT_OK) {
		print(PRINT_ERROR, "Unable to start agent server: %s\n", agent_strerror(ret));
		return 1;
	}

	/* This will allocate username */
	username = security_get_calling_user();
	if (!username) {
		print(PRINT_ERROR, "Unable to locate current user\n");
		ret = AGENT_ERR_INIT_USER;
		goto init_error;
	}

	agent_hdr_init(a, 0);

	ret = agent_set_user(a, username);
	if (ret != 0) {
		print(PRINT_ERROR, "Error while setting user: %s\n", agent_strerror(ret));
		free(username);
		goto init_error;
	}
	free(username);
	username = NULL;

	/***
	 * Initialization
	 * Now, try to read config file, init printing, ppp etc.
	 ***/
#if DEBUG
#warning OTPasswd Agent compiled with DEBUG option. Will leave DEBUG info in /tmp/OTPAGENT_TESTLOG
	ret = ppp_init(0, "/tmp/OTPAGENT_TESTLOG");
#else
	ret = ppp_init(PRINT_SYSLOG, NULL);
#endif
	if (ret != 0) {
		print(PRINT_ERROR, ppp_get_error_desc(ret));
		print(PRINT_ERROR, "OTPasswd not correctly installed.\n");
		print(PRINT_ERROR, "Consult installation manual for detailed information.\n");

		error_desc = ret;
		ret = AGENT_ERR_INIT_CONFIGURATION;
		goto init_error;
	}
	print_config(PRINT_NOTICE);

	/* Will succeed, as ppp_init suceeded */
	cfg = cfg_get();

	/* If DB is global, mysql or ldap, agent must be SUID root. 
	 * We can't detect this easily if we are run by root. So, 
	 * treat root as run by suid.
	 */
	if (cfg->db != CONFIG_DB_USER &&
	    security_is_suid() == 0 && 
	    security_is_privileged() == 0) {
		/* Something is wrong. We are not SUID/privileged
		 * and DB is not "USER" so we won't be able to reach it */
		print(PRINT_ERROR,
		      "Database type set to global, MySQL or LDAP, yet program "
		      "is not a SUID root.\n");
		ret = AGENT_ERR_INIT_PRIVILEGES;
		goto init_error;
	}


	/* 4) We must drop permissions now.
	 * If DB=user - drop to the user who called us.
	 * If DB=global - drop to cfg->user_uid
	 */
	switch (cfg->db) {
	case CONFIG_DB_GLOBAL:
		/* Drop root permanently to the cfg->user_uid 
		 * We do this even if we are run as root. */
		security_permanent_switch(cfg->user_uid, cfg->user_gid);
		break;
		
	case CONFIG_DB_MYSQL:
	case CONFIG_DB_LDAP:
	case CONFIG_DB_USER:
		/* Drop permanently back to the user who called us */
		if (!security_is_privileged()) {
			/* We don't drop if we are root, so the --user
			 * option will work. */
			security_permanent_drop();
		}
		break;
	}

	/* Agent loop */
	return main_loop(a);


init_error:
	ret = send_init_reply(a, ret, error_desc);
	if (ret != 0) {
		print(PRINT_ERROR, "Additional error while sending back failure reason: %s.\n",
		      agent_strerror(ret));
	}
	ret = agent_disconnect(a);
	if (ret != 0) {
		print(PRINT_ERROR, "Additional error while disconnecting from agent.\n",
		      agent_strerror(ret));
	}

	ppp_fini();
	return 1;
}
