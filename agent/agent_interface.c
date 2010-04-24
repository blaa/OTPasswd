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
#include <sys/select.h>


#define DEBUG 1

#include "agent_private.h"

/* For passing errors from certain functions */
static int agent_errno;

agent *agent_connect(const char *agent_executable)
{
	int ret = 1;
	/* in[1]  - stdout of agent;  
	 * out[0] - stdin of agent; 
	 * in/out - naming from perspective of parent
	 */
	int in[2] = {-1, -1};
	int out[2] = {-1, -1};
	pid_t pid;
	agent *a;

	a = malloc(sizeof(*a));
	if (!a) {
		agent_errno = AGENT_ERR_MEMORY;
		return NULL;
	}

	a->hdr.protocol_version = AGENT_PROTOCOL_VERSION;
	a->error = 0;

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
		execl(agent_executable, agent_executable, NULL);

		/* Failure */
		exit(1);
	}
	close(in[1]);
	close(out[0]);

	a->in = in[0];
	a->out = out[1];

	/* TODO: Handle some signal? */
	agent_errno = 0;
	return a;

cleanup1:
	if (in[0] != -1) close(in[0]);
	if (in[1] != -1) close(in[1]);
	if (out[0] != -1) close(out[0]);
	if (out[1] != -1) close(out[1]);

cleanup:
	agent_errno = ret;
	free(a);
	return NULL;
}


int agent_disconnect(agent *a)
{
	int ret = 0;
	/* Send quit message */

	/* Wait for child to close? */

	/* Close descriptors  */
	if (a->in != -1)
		ret += close(a->in);
	if (a->out != -1)
		ret += close(a->out);

	/* Free memory */
	free(a);

	return ret;
}

const char *agent_strerror(void)
{
	return NULL;
}

int agent_read(const int fd, void *buf, const size_t len) 
{
	int ret;
	ret = read(fd, buf, len);
	assert(ret == len);

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	if (select(fd+1, &rfds, NULL, NULL, NULL) == -1) {
		perror("select");
		return 1;
	}

	return ret;
}

#define _send(field)	  \
	do { \
		ret = write(fd, &a->hdr.field, sizeof(a->hdr.field)); \
		if (ret != sizeof(a->hdr.field)) \
			return 1; \
        } while (0);

#define _recv(field)						      \
	do {							      \
		ret = agent_read(fd, &a->hdr.field, sizeof(a->hdr.field));          \
		if (ret != sizeof(a->hdr.field))			      \
			return 1;				      \
        } while (0);

int agent_send_header(const agent *a) 
{
	const int fd = a->out;
	ssize_t ret = 1;

	_send(protocol_version);
	_send(type);
	_send(status);
	_send(int_arg);
	_send(num_arg);

	if (write(fd, a->hdr.str_arg, sizeof(a->hdr.str_arg)) != sizeof(a->hdr.str_arg)) {
		return 1;
	}

	return 0;
}

int agent_recv_header(agent *a) 
{
	const int fd = a->in;
	ssize_t ret = 1;
	
	_recv(protocol_version);
	_recv(type);
	_recv(status);
	_recv(int_arg);
	_recv(num_arg);

	if (read(fd, a->hdr.str_arg, sizeof(a->hdr.str_arg)) != sizeof(a->hdr.str_arg)) {
		return 1;
	}
	return 0;
}



int agent_query(agent *a, int request)
{
	/* Prepare header struct; 
	 * don't touch alternate parameters */
	a->hdr.type = request;
	if (agent_send_header(a) != 0) {
		a->error = 1;
		return 1;
	}


	/* Might hang? */
	if (agent_recv_header(a) != 0) {
		a->error = 1;
		return 1;
	}


	return a->hdr.status;
}


int agent_key_generate(agent *a)
{
	return agent_query(a, AGENT_REQ_KEY_GENERATE);
}

int agent_key_remove(agent *a)
{
	return agent_query(a, AGENT_REQ_KEY_REMOVE);
}

int agent_key_store(agent *a)
{
	return agent_query(a, AGENT_REQ_KEY_STORE);
}

int agent_flag_set(agent *a, int flag)
{
	return agent_query(a, AGENT_REQ_FLAG_SET);
}

int agent_flag_clear(agent *a, int flag)
{
	return agent_query(a, AGENT_REQ_FLAG_CLEAR);
}

int agent_flag_check(agent *a, int flag)
{
	return agent_query(a, AGENT_REQ_FLAG_CHECK);
}


int agent_read_state(agent *a)
{
	return agent_query(a, AGENT_REQ_READ_STATE);
}

/*
int agent_get_key(const agent *a, char *key)
{
}

int agent_get_num(const agent *a, num_t *key, int type)
{
}

int agent_get_int(agent *a, int field, int *reply)
{
}

int agent_get_passcode(const agent *a, int field, char **reply) 
{
}
*/







/* Config query:
 * ret = agent_config_query_int(agent *a, int field, int *reply);
 * ret = agent_config_query_str(agent *a, int field, char **reply); 
 */

int agent_testcase(void)
{
	int ret;
	int failures = 0;
	/* Create some messages and check if they are parsed accordingly */

	agent *a = NULL;

	a = agent_connect(NULL);
	if (a == NULL) {
		printf("Unable to connect to agent.\n");
		puts(agent_strerror());
		failures++;
		goto end;
	}

	// superuser only: agent_set_user(a, "user");

	/* Gets all information possible about state. Should be done 
	 * before generating key to ask user about some details. */
	ret = agent_read_state(a);
	/* Check ret */
	
	/* Interface for generating key */
//	int flags = agent_get_int(a, AGENT_FLAGS);




//	num_t value;
//	ret = agent_get_num(ar, AGENT_NUM_LATEST_CARD, value);
	/* ret might be: AGENT_OK, AGENT_ERR_POLICY, AGENT_PPP_ERROR */




//cleanup1:
	agent_disconnect(a);
end:
	return failures;
}
