/**********************************************************************
 * otpasswd -- One-time password manager and PAM module.
 * Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define CONFIG_PATH		"/etc/security/otpasswd.conf"
#define CONFIG_MAX_LINE_LEN	200
#define CONFIG_DEF_DB_GLOBAL	"/etc/otshadow"
#define CONFIG_DEF_DB_USER	".otpasswd"
#define CONFIG_PATH_LEN		100
#define CONFIG_SQL_LEN		50

enum CONFIG_DB_TYPE {
	CONFIG_DB_GLOBAL = 0,
	CONFIG_DB_USER = 1,
	/* Feature database backends */
	CONFIG_DB_MYSQL = 2,
	CONFIG_DB_LDAP = 3,
};

typedef struct {
	/*** 
	 * General configuration 
	 ***/

	int db;

	/* Location of global database file */
	char global_db_path[CONFIG_PATH_LEN];

	/* Location of user database file */
	char user_db_path[CONFIG_PATH_LEN];

	/* Not implemented sql data */
	char sql_host[CONFIG_SQL_LEN];
	char sql_database[CONFIG_SQL_LEN];
	char sql_user[CONFIG_SQL_LEN];
	char sql_pass[CONFIG_SQL_LEN];

	/***
	 * PAM Configuration
	 ***/

	/* Enforced makes any user without key
	 * fail to login */
	int enforce;

	/* Do we allow dont-skip? 0 - yes */
	int secure;

	/* Turns on increased debugging (into syslog) */
	int debug;

	/* 0 - no retry
	 * 1 - retry with new passcode
	 * 2 - retry with the same passcode
	 * Will always retry 3 times...
	 */
	int retry;

	/* Shall we echo entered passcode?
	 * 1 - user selected
	 * 0 - (noshow) echo disabled
	 * 2 - (show) echo enabled
	 */
	int show;

	/* 0 - OOB disabled
	 * 1 - OOB on request
	 * 2 - OOB on request; request requires password
	 * 3 - OOB sent during all authentication sessions
	 */
	int oob;

	/* Out-Of-Band script path */
	/* Ensure that size of this field matches sscanf in _parse_options */
	char oob_path[CONFIG_PATH_LEN];

	/* Parameters determined from the environment and
	 * not options themselves  */
	int uid, gid; /* uid, gid of a safe, non-root user who can run OOB script */

	/***
	 * Policy configuration
	 ***/
	/* Implemented */

	/* Not-implemented */
	int allow_key_generation;
	int allow_skipping;
	int allow_passcode_print;
	int allow_key_print;
	int def_passcode_length;
	int min_passcode_length;
	int max_passcode_length;
	int def_alphabet_length;
	int min_alphabet_length;
	int max_alphabet_length;
	int allow_salt;
} options;

/* Set all fields to default values */
extern void config_defaults(options *opt);

/* Parse config file and set fields in struct 
 * config_path might be NULL to read default config.
 */
extern int config_parse(options *opt, const char *config_path);




#endif