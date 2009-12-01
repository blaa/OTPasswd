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
