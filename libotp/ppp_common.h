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
	PPP_NOMEM = 40,

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


	/*** NOT ALWAYS FATAL */
	/* State doesn't exist.
	 * If enforce = 0 - ignore OTP.
	 */
	STATE_NON_EXISTENT = 54,		

	/* State exists, is readable, but doesn't have
	 * user entry. Always causes ignore if enforce=0
	 */
	STATE_NO_USER_ENTRY = 55,
};


enum flags {
	FLAG_SHOW = 1,
	/* FLAG_SKIP removed */
	FLAG_ALPHABET_EXTENDED = 4,
	FLAG_NOT_SALTED = 8,
};

#endif
