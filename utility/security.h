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

#ifndef _SECURITY_H_
#define _SECURITY_H_

/* Init environment for SUID/SGID program */
extern void security_init(void);

/* Temporary drop our effective rights */
extern void security_temporal_drop(void);

/* Pernamently drop rights */
extern void security_permanent_drop(void);

/* Restore rights which were dropped temporarily */
extern void security_restore(void);

#endif
