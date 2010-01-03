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

#include "print.h"
#include "state.h"
#include "db.h"
#include "config.h"

int db_mysql_lock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_mysql_unlock(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}


int db_mysql_load(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}

int db_mysql_store(state *s)
{
	print(PRINT_ERROR, "Unimplemented\n");
	return 1;
}
