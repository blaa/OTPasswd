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
 *   Performs secure environment initialization, manages rights 
 *   and capabilities. Other function query environment for our
 *   configuration (are we suid, run by root etc.)
 **********************************************************************/

#ifndef _SECURITY_H_
#define _SECURITY_H_

/* For uid_t */
#include <sys/types.h>
#include <unistd.h>

/** Init environment for SUID program */
extern void security_init(void);

/** Pernamently drop rights back to the user who called us */
extern void security_permanent_drop(void);

/** Pernamently switch user to given uid/gid */
extern void security_permanent_switch(uid_t uid, uid_t gid);

/** Are we SUID? Check ones defined in argument. */
extern int security_is_suid();

/** Are we run by root? */
extern int security_is_privileged();

/** Are we connected (in any way) to some tty? */
extern int security_is_tty_detached(void);

/** Parse user specification (name or UID) ensure it exists */
extern char *security_parse_user(const char *spec);

/** Get username of the user who ran current process */
extern char *security_get_calling_user(void);

#endif
