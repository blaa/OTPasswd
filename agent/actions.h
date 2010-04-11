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
 *   Set of functions performing tasks specified on command line.
 *   All are called from otpasswd.c. One function can realize more
 *   then one command line option.    
 **********************************************************************/

#ifndef _ACTIONS_H_
#define _ACTIONS_H_

#include "config.h"

/* Constants used for parsing input data.
 * Shared between otpasswd.c and _actions. */
enum {
	OPTION_KEY      = 'k',
	OPTION_REMOVE   = 'r',
	OPTION_SKIP     = 's',
	OPTION_TEXT     = 't',
	OPTION_LATEX    = 'l',
	OPTION_PROMPT   = 'P',
	OPTION_AUTH     = 'a',
	OPTION_WARN     = 'w',

	OPTION_INFO     = 'i',
	OPTION_INFO_KEY = 'I',
	OPTION_CONFIG   = 'c',
	OPTION_SPASS    = 'p',
	OPTION_USER     = 'u',
	OPTION_VERBOSE  = 'v',
	OPTION_CHECK    = 'x',
	OPTION_VERSION  = 'Q',
	OPTION_HELP     = 'h',

	/* Other which aren't user UI options */
	OPTION_ALPHABETS = 'A',
};

/* Struct holding "user CLI request" information */
typedef struct {
	char action;
	char *action_arg;
	char *label;
	char *contact;

	char *username;

	unsigned int flag_set_mask;
	unsigned int flag_clear_mask;
	int set_codelength;
	int set_alphabet;
} options_t;


/* Configures user state, prints state information (-c -i) */
extern int action_flags(options_t *options);

/* Sets user static password. */
extern int action_spass(options_t *options);

/* Print author, license and quit. */
extern int action_license(options_t *options);

/* Generates/Regenerates new key (-k) */
extern int action_key(options_t *options);

/* Command line authentication (-a) */
extern int action_authenticate(options_t *options);

/* Print passcode or passcard or skip (-t -l -s) */
extern int action_print(options_t *options);

#endif
