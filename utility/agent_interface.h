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
 * DESC: 
 * Interface between SUID agent and UI program. Can and should be used
 * for creation of GUI interfaces also.
 **********************************************************************/

#ifndef _AGENT_H_
#define _AGENT_H_

/*
 * Data is transferred via pipe. Client program has a 
 * pair of descriptors used for communication and agent
 * has it hooked up to the stdin/stdout.
 *
 * 1) Data files may never be locked during transmission
 * 2) Communication is request/reply based and never initiated
 *    by agent.
 * 3) Therefore operations should be atomic and possibly simple
 *    If something can be done in three request it might be ok
 *    to split it.
 * 4) Protocol must be trivial too parse; use static sizes
 *    whereever possible 
 * 5) Some operations like key generation require multiple 
 *    request/replies, therefore agent connection must be
 *    persistent between requests.
 * 6) Request must allow localization. Therefore passcard
 *    generation, alphabet list generation etc. must be done
 *    at the frontend side. Agent at minimum must return 
 *    single passcodes.
 */


/*
 * Possible operations and it's arguments:
 * 1. Key
 *  a) Generate key
 *     Salted / not salted, alphabet, codelength
 *  b) Remove key

 * 2. Configuration
 *  c) Enable/disable flags:
 *     show, salt (during key generation)
 *  x) Select/list alphabet
 *  x) Select passcode length
 *  x) Enable/disable otpasswd for account
 *  a) Set contact 
 *  b) Set label

 *  f) Configure static password
 * 2. Passcode:
 *  a) Skip
 *  b) Authenticate
 *  c) Return required passcode
 *  d) Return passcard
 *
 * x. Informational
 *  c) Return generic user information 
 *  d) Return key/counter information
 *
 * 10) Miscellenous:
 *  a) Return current warnings
 *  b) Return prompt
 *
 */

#define AGENT_PATH "agent_otpasswd"
#define AGENT_PROTOCOL_VERSION 0


/* Maximal size of any transferred argument. 255 should be
 * more then enough as label/contact don't exceed 80 bytes.
 * The only thing which will be limited is static password size 
 */
#define AGENT_ARG_MAX 255

struct agent_header {
	/* Ensures both executables are having the same
	 * version */
	int protocol_version;

	/* Request type + Reply type */
	int type;

	/* Length of a request argument.
	 * This can be a password, contact, label etc.
	 */
	char argument[AGENT_ARG_MAX];

	/* Bytes in 'data' element */
	int bytes;
	/* Alternatively number of items (structs) in data */
	int items;
	void *data;
};

struct agent_reply_alphabet {
	int id;
	int policy_accepted;
	char chars[AGENT_ARG_MAX];
};

/* Reply containing warnings or error code + description */
struct agent_reply_string {
	int type;
	int code;
	char data[AGENT_ARG_MAX];
};

typedef struct {
	/* Descriptors used for connection */
	int in, out;

	/* Child PID */
	pid_t pid;

	struct agent_header hdr;
} agent;

extern int agent_connect(agent *a);
extern int agent_disconnect(agent *a);


void agent_set(agent *ag


#endif
