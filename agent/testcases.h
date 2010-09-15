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
 *   Internal testcases of OTPasswd. Used not only to test correct
 *   system behaviour, but also as a hooks to various routines which
 *   might be checked this way for memory leaks using valgrind.
 **********************************************************************/

#ifndef _TESTCASES_H_
#define _TESTCASES_H_

/* Testcases used in utility */

extern int crypto_testcase(void);
extern int num_testcase(void);
extern int card_testcase(void);
extern int state_testcase(void);
extern int spass_testcase(void);
extern int ppp_testcase(void);
extern int config_testcase(void);


#endif
