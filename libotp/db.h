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

#ifndef _DB_H_
#define _DB_H_

/*
 * Each database has 4 functions used to access it.
 * Two for locking/unlocking, one for loading user info
 * from DB, and one for updating/storing user info into
 * the database. They must be splitted like this because it's
 * common to perform actions like this:
 *
 * 1. Lock database so no one will change it for a while
 * 2. Read state from database
 * 3. Do some operation on state
 * 4. Update state information in db
 * 5. Unlock db.
 */

/*** File based DB. ***/

/* Locking state file */
extern int db_file_lock(state *s);
extern int db_file_unlock(state *s);

/* Load/Store state from/to file database. */
extern int db_file_load(state *s);
extern int db_file_store(state *s);


/*** MySQL DB. ***/

/* Locking state file */
extern int db_mysql_lock(state *s);
extern int db_mysql_unlock(state *s);

/* Load/Store state from/to file database. */
extern int db_mysql_load(state *s);
extern int db_mysql_store(state *s);

/*** LDAP DB. ***/

/* Locking state file */
extern int db_ldap_lock(state *s);
extern int db_ldap_unlock(state *s);

/* Load/Store state from/to file database. */
extern int db_ldap_load(state *s);
extern int db_ldap_store(state *s);

#endif
