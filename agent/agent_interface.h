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

#ifndef _AGENT_INTERFACE_H_
#define _AGENT_INTERFACE_H_

/*
 * Data is transferred via pipe. Client program has a 
 * pair of descriptors used for communication and agent
 * has it hooked up to the stdin/stdout.
 *
 * 1) Data files may never be locked during transmission
 * 2) Communication is request/reply based and never initiated
 *    by agent.
 * 3) Therefore operations must be atomic.
 * 4) User interface should be possibly as high-level as possible 
 *    so writting future interfaces will be simple.
 * 5) Protocol must be trivial too parse; use static buffer sizes
 *    everywhere.
 * 6) Some operations like key generation require multiple 
 *    request/replies, therefore agent connection must be
 *    persistent between requests.
 * 7) Request must allow localization. Therefore passcard
 *    generation, alphabet list generation etc. must be done
 *    at the frontend side. Agent at minimum must return 
 *    single passcodes.
 */


/*
 * Agent keeps in memory single copy of state
 * either loaded by status query or fresh generated.
 *
 * Possible operations and it's arguments:
 * 1. Key
 *  a) Generate key
 *     Parameters: flags: Salted / not salted, alphabet, codelength
 *     - Create new state and generate key
 *     - Keep state in memory, in reply return first passcard
 *     - if next action is "Save" - (lock, save, unlock), otherwise dispose of it.
 *  b) Remove key
 *     - Lock state
 *     - remove user entry
 *     - Unlock state
 *     Warnings about enforced OTP should be made by UI
 * 2. Status
 *    - Lock state file
 *    - Read user state
 *    - Unlock state file
 *    - Put information available (check policy) into struct
 *    - dispose of user state
 *    - send reply
 *    Gives access to:
 *    key, counter, alphabet, flags, last_passcard...
 *    Agent client caches this information until disconnect 
 * 3. String query 
 *    a) Query passcode (given unsalted passcode number)
 *    b) Query passcard (given passcard number)
 *    c) Query passpage (returns LaTeX)
 *    d) Query current prompt
 *    e) Query warnings
 *
 * 4. Configuration
 *  c) Enable/disable flags:
 *     show, salt (during key generation)
 *  x) Select/list alphabet
 *  x) Select passcode length
 *  x) Enable/disable otpasswd for account
 *  a) Set contact 
 *  b) Set label

 *  f) Configure static password
 * 5. Skip
 *  a) Passcode
 *  b) Passcard
 * 6. Authenticate
 *
 * 10) Miscellenous:
 *  a) Return current warnings
 *  b) Return prompt
 *
 */

#define AGENT_PATH "agent_otpasswd"
#define AGENT_PROTOCOL_VERSION 0


/* Anonymous struct */
typedef struct agent agent;


/* Basic routines */
extern int agent_connect(agent *a);
extern int agent_disconnect(agent *a);

/*** Actions ***/
/* TODO: Return passcard? */
/** Generate key, but do not store it on disc. */
extern int agent_key_generate(agent *a, int flags);

/** Stores previously generated key */
extern int agent_key_store(agent *a);

/** Remove user state; warnings about otp enforcements are due to UI */
extern int agent_key_remove(agent *a);

/** Status query */
extern int agent_status_update(agent *a);
extern int agent_get_key(const agent *a, num_t *key);


/* Config query */
extern int agent_config_query_int(agent *a, int field, int *reply);
extern int agent_config_query_str(agent *a, int field, char **reply); 



void agent_set(agent *a);


#endif
