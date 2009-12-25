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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "print.h"
#include "num.h"

/* All functions are inline currently and testcase
 * was moved away to testcases.c */

static void *allocate_function(size_t alloc_size)
{
	void *tmp = malloc(alloc_size);
	if (!tmp) {
		print(PRINT_ERROR, "Not enough memory!\n");
		exit(EXIT_FAILURE);
	}
	return tmp;
}

static void free_function(void *ptr, size_t size)
{
	memset(ptr, 0, size);
	free(ptr);
}

static void *reallocate_function(void *ptr, size_t old_size, size_t new_size)
{
	const size_t copy_size = old_size < new_size ? old_size : new_size;
	void *new_ptr = allocate_function(new_size);
	memcpy(new_ptr, ptr, copy_size);
	free_function(ptr, old_size);
	return new_ptr;
}

void num_init(void)
{
	mp_set_memory_functions(allocate_function,
				reallocate_function,
				free_function);
}
