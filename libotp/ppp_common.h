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

#ifndef _PPP_COMMON_H_
#define _PPP_COMMON_H_

/* Size of fields */
#define STATE_LABEL_SIZE 30
#define STATE_CONTACT_SIZE 60
#define STATE_SPASS_SIZE 40 /* Hexadecimal SHA256 (64 bytes) of static password + SALT (16) */
#define STATE_MAX_FIELD_SIZE 80
#define STATE_ENTRY_SIZE 512 /* Maximal size of a valid state entry (single line)
			      * 32 (username) + 64 (key) + 32 (counter) + 60 (contact)
			      * + 64 (static) + 32 latest + 20 (failures + recent failures) +
			      * + 32 (timestamp) + 2 (codelength) + 5 (flags)
			      * === 343 (+ separators < 512)
			      */

#define ROWS_PER_CARD 10

/* We must distinguish between locking problems (critical)
 * and non-existant state file (usually not critical).
 *
 * Depending on db used and enforce option sometimes we
 * should ignore OTP login and sometimes we should hard-fail.
 */
enum ppp_errors {
	/* Warning: agent_strerror checks ranges of this values */
	STATE_NOMEM = 100,

	/*** ALWAYS FAIL ***/
	/* Error while locking (existing) state file */
	STATE_LOCK_ERROR = 110,

	/* Error while parsing - state invalid */
	STATE_PARSE_ERROR,

	/* Counter too big. Key should be regenerated */
	STATE_NUMSPACE,

	/* File exists, but we're unable to open/read/write
	 * state file (not a file, permissions might be wrong).
	 */
	STATE_IO_ERROR,

	/* User doesn't exists in Unix database
	 * but was required because of home directory */
	STATE_NO_SUCH_USER,

	/*** NOT ALWAYS FATAL */
	/* State doesn't exist.
	 * If enforce = 0 - ignore OTP.
	 */
	STATE_NON_EXISTENT,

	/* State exists, is readable, but doesn't have
	 * user entry. Always causes ignore if enforce=0
	 */
	STATE_NO_USER_ENTRY,

	/*** PPP Errors ***/

	/* Generic error. Should not happen usually. */
	PPP_ERROR = 1000,

	/* Action denied by policy */
	PPP_ERROR_POLICY,

	/* Input too long */
	PPP_ERROR_TOO_LONG,

	/* Input contains illegal characters */
	PPP_ERROR_ILL_CHAR,

	/* Value out of range */
	PPP_ERROR_RANGE,

	/* User disabled, while trying some 
	 * action like authentication */
	PPP_ERROR_DISABLED,


	/* SPass related */
	PPP_ERROR_SPASS_INCORRECT,

	/*** Errors which can happen only during initialization */

	/* Unable to read config file */
	PPP_ERROR_CONFIG,

	/* DB option in config not set. */
	PPP_ERROR_NOT_CONFIGURED,

	/* Config not owned by root */
	PPP_ERROR_CONFIG_OWNERSHIP,

	/* Incorrect config permissions
	 * Probably o+r/g+r and LDAP/MySQL selected */
	PPP_ERROR_CONFIG_PERMISSIONS,
};

enum ppp_flags {
	FLAG_SHOW = 1,
	/* User disabled by administrator */
	FLAG_DISABLED = 2,
	FLAG_SALTED = 4,

	/* FLAG_SKIP removed */
	/* FLAG_ALPHABET_EXTENDED removed */
};

/* Warning conditions which may happen */
enum ppp_warning {
	PPP_WARN_OK = 0,		/* No warning condition */
	PPP_WARN_LAST_CARD = 1,		/* User on last printed card */
	PPP_WARN_NOTHING_LEFT = 2,	/* Used up all printed passcodes */
	PPP_WARN_RECENT_FAILURES = 4,	/* There were some failures */	
};


/* Flag-like options to some ppp functions */
enum ppp_options {
	/* Turn on policy checking */
	PPP_CHECK_POLICY = 1,

	/* Update state data in database */
	PPP_STORE = 2,

	/* Unlock state DB */
	PPP_UNLOCK = 4,

	/* Remove previously loaded user state file */
	PPP_REMOVE = 8,

	/* Do not keep lock when loading. */
	PPP_DONT_LOCK = 16,

};


/* For getters / setters. Identifies some fields in state */
enum {
	PPP_FIELD_FAILURES = 1,		/* unsigned int */
	PPP_FIELD_RECENT_FAILURES,	/* unsigned int */
	PPP_FIELD_CODE_LENGTH,		/* unsigned int */
	PPP_FIELD_ALPHABET,		/* unsigned int */
	PPP_FIELD_FLAGS,		/* unsigned int */

	PPP_FIELD_COUNTER, 		/* mpz */
	PPP_FIELD_UNSALTED_COUNTER, 	/* mpz */
	PPP_FIELD_LATEST_CARD,		/* mpz */
	PPP_FIELD_CURRENT_CARD,		/* mpz */
	PPP_FIELD_MAX_CARD,		/* mpz */
	PPP_FIELD_MAX_CODE,		/* mpz */
	

	PPP_FIELD_USERNAME,		/* char * */
	PPP_FIELD_PROMPT,		/* char * */
	PPP_FIELD_CONTACT,		/* char * */
	PPP_FIELD_LABEL,		/* char * */
};



#endif

