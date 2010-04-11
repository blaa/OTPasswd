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
 *
 **********************************************************************/

#include <stdlib.h>
#include <unistd.h>

#define DEBUG 1

#include "agent_interface.h"
#include "agent_private.h"



int agent_connect(agent *a, const char *agent_executable))
{
	int ret = 1;
	int i;
	/* in[1]  - stdout of agent;  
	 * out[0] - stdin of agent; 
	 * in/out - naming from perspective of parent
	 */
	int in[2] = {-1, -1};
	int out[2] = {-1, -1};
	pid_t pid;
	assert(a);

	if (pipe(in) != 0)
		goto cleanup;
		
	if (pipe(out) != 0)
		goto cleanup1;

	/* Verify that agent executable exists */
	if (agent_executable == NULL)
		agent_executable = "./agent_otpasswd";
	

	pid = fork();

	if (pid == 0) {
		/* Prepare pipes */
		close(in[0]);
		close(out[1]);
		close(0);
		close(1);
		close(2);
		/* fd 1 - stdout, fd 0 - stdin */
		dup(out[0]);
		dup(in[1]);

		/* Execute agent */
		execl(agent_executable, NULL);

		/* Failure */
		exit(1);
	}
	close(in[1]);
	close(out[0]);

	a->in = in[0];
	a->out = out[1];

	/* TODO: Handle some signal? */

	return 0;

cleanup1:
	if (in[0] != -1) close(in[0]);
	if (in[1] != -1) close(in[1]);
	if (out[0] != -1) close(out[0]);
	if (out[1] != -1) close(out[1]);

cleanup:
	return ret;

}

int agent_disconnect(agent *a)
{
	/* Send quit message */
	/* Close descriptors  */
	/* Wait for child to close? */
	
	
}


/* Config query:
 * ret = agent_config_query_int(agent *a, int field, int *reply);
 * ret = agent_config_query_str(agent *a, int field, char **reply); 
 */

int agent_testcase(void)
{
	int ret;
	int failures = 0;
	/* Create some messages and check if they are parsed accordingly */
	

	agent a;

	ret = agent_connect(&a, NULL);
	if (ret != 0) {
		printf("Unable to connect to agent. (err=%d)\n", ret);
		failures++;
		goto end;
	}

	// superuser only: agent_set_user(a, "user");

	/* Gets all information possible about state. Should be done 
	 * before generating key to ask user about some details. */
	ret = agent_status(a, AGENT_STATE);
	/* Check ret */
	
	/* Interface for generating key */
	int flags = agent_get_int(a, AGENT_FLAGS);




	num_t value;
	ret = agent_get_num(ar, AGENT_NUM_LATEST_CARD, value);
	/* ret might be: AGENT_OK, AGENT_ERR_POLICY, AGENT_PPP_ERROR */



	agent_disconnect(&a);

cleanup1:
	agent_disconnect(&a);
end:
	return failures;
}
