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
#define STATE_STATIC_SIZE 64 /* Hexadecimal SHA256 of static password */
#define STATE_MAX_FIELD_SIZE 64
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
enum errors {
	STATE_NOMEM = 40,

	/*** ALWAYS FAIL ***/
	/* Error while locking (existing) state file */
	STATE_LOCK_ERROR = 50,

	/* Error while parsing - state invalid */
	STATE_PARSE_ERROR = 51,

	/* Counter too big. Key should be regenerated */
	STATE_NUMSPACE = 52,

	/* File exists, but we're unable to open/read/write
	 * state file (not a file, permissions might be wrong).
	 */
	STATE_IO_ERROR = 53,

	/* User doesn't exists in Unix database
	 * but was required because of home directory */
	STATE_NO_SUCH_USER = 54,

	/*** NOT ALWAYS FATAL */
	/* State doesn't exist.
	 * If enforce = 0 - ignore OTP.
	 */
	STATE_NON_EXISTENT = 55,

	/* State exists, is readable, but doesn't have
	 * user entry. Always causes ignore if enforce=0
	 */
	STATE_NO_USER_ENTRY = 56,
};


enum flags {
	FLAG_SHOW = 1,
	/* FLAG_SKIP removed */
	/* FLAG_ALPHABET_EXTENDED removed */
	FLAG_SALTED = 8,
};

#endif
