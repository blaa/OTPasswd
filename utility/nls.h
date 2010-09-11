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
 *   GetText interface.
 **********************************************************************/

#ifndef _NLS_H_
#define _NLS_H_

#if USE_NLS
#	include <libintl.h>
#	include <locale.h>
#	define _(t) gettext(t)

static inline void locale_init(void)
{
	(void) setlocale(LC_ALL, "");
	(void) bindtextdomain("otpasswd", "/usr/share/locale");
	(void) textdomain("otpasswd");
}

#else

#	define _(t) (t)

static inline void locale_init(void)
{
	/* Empty */
}
#endif

#endif
