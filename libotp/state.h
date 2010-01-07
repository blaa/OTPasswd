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

#ifndef _STATE_H_
#define _STATE_H_

#include <gmp.h>
#include <time.h>
#include "ppp_common.h"

/*** Config ***/
#define STATE_FILENAME ".otpasswd"

/* Base for storing big numbers inside STATE_FILENAME */
#define STATE_BASE	16


/*** State ***/
typedef struct {
	/* 128 bit counter pointing at the next passcode
	 * which will be used for authentication */
	mpz_t counter;

	/* User secret sequence key */
//	mpz_t sequence_key;
	unsigned char sequence_key[32];

	/* Furthest printed passcode
	 * used for warnings */
	mpz_t latest_card;

	/* Number of bytes used for passcode (2 - 16) */
	unsigned int code_length;

	/* Alphabet selected */
	unsigned int alphabet;
	
	/* User flags */
	unsigned int flags;

	/* Static password (spass) */
	mpz_t spass;
	int spass_set; /* Bool: 0 - not set, 1 - set */

	/* Timestamp of the last change of static password */
	time_t spass_time;

	/* Card label (might be zeroed, then hostname is used) */
	char label[STATE_LABEL_SIZE];

	/* Phone number... ANY info used for informing a user
	 * for example an email, or - a phone number... */
	char contact[STATE_CONTACT_SIZE];

	/* Number of all failures */
	unsigned int failures;

	/* Failures since last correct login */
	unsigned int recent_failures;

	/* UNIX timestamp of latest channel usage */
	time_t channel_time;

	/*** Temporary / not-saved data ***/
	char *prompt; /* Keep it here so we can safely dispose of it */

	/* Salt helper. Initialized in state_init.
	 * counter & salt_mask = salt
	 * counter & code_mask = user passcode number
	 */
	mpz_t salt_mask;
	mpz_t code_mask;

	/* Card information, calculated once for
	 * simplicity by ppp_calculate and stored here.
	 * (codes_on_card>0) can be checked to ensure this values
	 * are correct.
	 */
	mpz_t current_card;		/* Card with current code */
	mpz_t max_card;			/* Last available passcard (from 1) */
	mpz_t max_code;			/* Last code from last passcard (from 1) */
	unsigned int codes_on_card;
	unsigned int codes_in_row;
	unsigned char current_row;	/* 1 - 10 */
	unsigned char current_column;	/* A ... */

	/* Not necessarily part of a user state,
	 * this is data used for storing/restoring
	 * state information.
	 */
	char *username;		/* user who called utility or does auth */

	/* DB lock status.-1 value means state is not locked
	 * while all other values mean that it's locked
	 * and can have some other db_ related information
	 * (like descriptor of opened lock file) */
	int lock;	
} state;


/* Initializes state structure. Must be called before
 * any else function from this set
 * If username is given we determine user home directory
 * using specified username, if it's NULL - we lookup environment
 */
extern int state_init(state *s, const char *username);

/* Deinitializes state struct; should clear
 * any secure-relevant data and free the memory */
extern void state_fini(state *s);

/* Generate new key */
extern int state_key_generate(state *s);

/* Validate contact / label data */
extern int state_validate_str(const char *str);


/************************************
 * Following functions are just
 * interfaces to db_* family
 ************************************/

/* Locking state file */
extern int state_lock(state *s);
extern int state_unlock(state *s);

/* Load/Store state from/to file database. */
extern int state_load(state *s);
/* If remove == 1, remove user state */
extern int state_store(state *s, int remove);



#endif
