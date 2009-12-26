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
 * and non-existant state file (usually not critical) */
enum errors {
	PPP_NOMEM = 40,
	STATE_LOCK_ERROR = 45,
	STATE_PARSE_ERROR = 46,
	STATE_DOESNT_EXISTS = 47,	/* or it not a regular file */
	STATE_PERMISSIONS = 48,		/* Insufficient possibly */
	STATE_NUMSPACE = 49,		/* Counter too big */
	STATE_RANGE = 50,		/* For example negative key */
	STATE_INVALID = 51,		/* State invalid in some other way */
};


enum flags {
	FLAG_SHOW = 1,
	/* FLAG_SKIP removed */
	FLAG_ALPHABET_EXTENDED = 4,
	FLAG_NOT_SALTED = 8,
};

#endif
