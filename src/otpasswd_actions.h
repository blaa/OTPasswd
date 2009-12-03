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

#ifndef _OTPASSWD_ACTIONS_H_
#define _OTPASSWD_ACTIONS_H_

typedef struct {
	int log_level;
	char action;
	char *action_arg;

	unsigned int flag_set_mask;
	unsigned int flag_clear_mask;
	int set_codelength;
} options_t;

extern void action_flags(options_t *options);
extern void action_license(options_t *options);
extern void action_key(options_t *options);
extern int action_authenticate(options_t *options);
extern void action_print(options_t *options);

#endif
