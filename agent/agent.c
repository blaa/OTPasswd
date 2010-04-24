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

/* libotp header */
#include "ppp.h"

/* Utility headers */
#include "security.h"
#include "actions.h"
#include "testcases.h"


/* Testcase function should be run only if we're not 
 * a SUID program or when we are run by root.
 * Also we should be connected to the terminal and
 * not to a pipe
 */
int do_testcase(void)
{
	cfg_t *cfg;
	int retval;
	int tmp;
	int failed = 0;

	printf("*** Running testcases\n");

	/* Init ppp for testcases */
	retval = ppp_init(PRINT_STDOUT, NULL);
	if (retval != 0) {
		puts(ppp_get_error_desc(retval));
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

	tmp = num_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d num testcases failed\n******\n", tmp);

	tmp = config_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d config testcases failed\n******\n", tmp);

	tmp = state_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d state testcases failed\n******\n", tmp);

	tmp = crypto_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d crypto testcases failed\n******\n", tmp);

	tmp = card_testcase();
	failed += tmp;
	if (tmp)
		printf("******\n*** %d card testcases failed\n******\n", tmp);

	tmp = ppp_testcase();
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


int perform_action(int argc, char **argv, options_t *options, cfg_t *cfg)
{
	int retval;

	/* Reconfigure printing subsystem; -v might be passed */
	switch (cfg->pam_logging) {
	case 0: print_config(PRINT_STDOUT | PRINT_NONE); break;
	case 1: print_config(PRINT_STDOUT | PRINT_ERROR); break;
	case 2: print_config(PRINT_STDOUT | PRINT_WARN); break; 
	case 3: print_config(PRINT_STDOUT | PRINT_NOTICE); break; 
	default:
		assert(0);
		retval = 1;
		goto cleanup;
	}

	/* Perform action */
	switch (options->action) {
	case 0:
		printf(("No action specified. Try passing -k, -s, -t or -l\n\n"));
		retval = 1;
		goto cleanup;
/*
	case OPTION_KEY:
	case OPTION_REMOVE:
		retval = action_key(options);
		break;

	case OPTION_SPASS:
		retval = action_spass(options);
		break;

	case OPTION_ALPHABETS:
	case OPTION_CONFIG:
	case OPTION_INFO:
	case OPTION_INFO_KEY:
		retval = action_flags(options);
		break;

	case OPTION_AUTH:
		ret = action_authenticate(options);
		if (ret == 0)
			retval = 1;
		else
			retval = 0;
		break;
	case OPTION_VERSION:
		retval = action_license(options);
		break;

	case OPTION_WARN:
	case OPTION_SKIP:
	case OPTION_TEXT:
	case OPTION_LATEX:
	case OPTION_PROMPT:
		retval = action_print(options);
		break;
*/
	default:
		printf(("Program error. You shouldn't end up here.\n"));
		assert(0);
		retval = 1;
		goto cleanup;
	}


cleanup:
	free(options->action_arg);
	free(options->label);
	free(options->contact);
	free(options->username);
	ppp_fini();
	return retval;
}


int do_loop(void) 
{
	int ret;

	/* Everything seems fine; send message that we're ready */
	agent *a = agent_server();
	if (!a) {
		print(PRINT_ERROR, "Unable to start agent server\n");
		return 1;
	}

	ret = agent_hdr_set(a, 0, 0, NULL, NULL);
	assert(ret == 0);

	ret = agent_query(a, AGENT_REQ_INIT);
	assert(ret == 0);

	for (;;) {
//		ret = agent_hdr_recv(a);
		
		/* Wait for request, perform it and reply */
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	cfg_t *cfg = NULL;

	/* 1) Init safe environment, store current uids, etc. */
	security_init();

	if (!security_is_tty_detached()) {
		/* We have stdout */
		if (!security_is_privileged()) {
			/* And we are not root */
			printf("FATAL: This program should not be used like this.\n"
			       "Use appropriate interface instead (like otpasswd).\n");
			exit(EXIT_FAILURE);
		}
		
		if (argc == 2 && strcmp(argv[1], "--check") == 0) {
			return do_testcase();
		} else {
			printf("FATAL: This program should not be used like this.\n"
			       "Use appropriate interface instead (like otpasswd)\n"
			       "\n"
			       "Since you're running this program as root you can \n"
			       "run a set of testcases with --check option\n");

			exit(EXIT_FAILURE);
		}
	}


	/* After this point we:
	 * a) Have no controlling terminal. 
	 * b) Can be SUID root (run by root or normal user)
	 */


	/***
	 * Initialization
	 * Now, try to read config file, init printing, ppp etc.
	 ***/

	/* TODO/FIXME: Reply our caller frame with error description on initial failure 
	 */

	/* TODO, FIXME: Remove log from here! */
	ret = ppp_init(0, "/tmp/OTPAGENT_TESTLOG");
	if (ret != 0) {
		print(PRINT_ERROR, ppp_get_error_desc(ret));
		print(PRINT_ERROR, "OTPasswd not correctly installed.\n");
		print(PRINT_ERROR, "Consult installation manual for detailed information.\n");
		ppp_fini();
		return 1;
	}

	/* Will succeed, as ppp_init suceeded */
	cfg = cfg_get();

	/* If DB is global, mysql or ldap, utility must be SUID root. 
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
		ppp_fini();
		return 1;
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
		/* FIXME: User won't be able to ptrace us 
		   rather and get passwords... */
		if (!security_is_privileged()) {
			/* We don't drop if we are root, so the --user
			 * option will work. */
			security_permanent_drop();
		}
		break;
	}

	/* Agent loop */
	return do_loop();
}
