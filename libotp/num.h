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

#ifndef _NUM_H_
#define _NUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <assert.h>

static inline void num_from_bin(mpz_t num, const unsigned char *data, const size_t length)
{
	/* Store data as LSB - to match pppv3 */
	mpz_import(num, 1, 1, length, -1 /* LSB to match ppp behaviour */ , 0, data);
}

static inline void num_to_bin(const mpz_t num, unsigned char *data, const size_t length)
{
	size_t size = 1;
	/* Handle 0 numbers; otherwise nothing would be written to data */
	if (mpz_cmp_si(num, 0) == 0)
		memset(data, 0, length);
	else 
		(void) mpz_export(data, &size, 1, length, -1, 0, num);
	assert(size == 1);
}

static inline void num_print(const mpz_t num, const int base)
{
	char *result = mpz_get_str(NULL, base, num);
	(void) puts(result);
	free(result);
}

/* This function set's GMP memory allocation routines 
 * to safer versions which cleanup deallocated memory */
extern void num_init(void);

#endif
