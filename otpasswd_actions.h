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

/* options = {
	.log_level = PRINT_WARN,
	.action = 0,
	.action_arg = NULL,

	.flag_set_mask = 0,
	.flag_clear_mask = 0,
	.set_codelength = 0
};

*/

#endif
