#ifndef _PAM_MACROS_H_
#define _PAM_MACROS_H_

/* These macros came from a Linux-PAM distribution */

/*
 * All kind of macros used by PAM, but usable in some other
 * programs too.
 * Organized by Cristian Gafton <gafton@redhat.com>
 */


/* PAM Macros for compatibility are included here */
#define _pam_overwrite(x)        \
do {                             \
     register char *__xx__;      \
     if ((__xx__=(x)))           \
          while (*__xx__)        \
               *__xx__++ = '\0'; \
} while (0)

#define _pam_drop_reply(/* struct pam_response * */ reply, /* int */ replies) \
do {                                              \
    int reply_i;                                  \
                                                  \
    for (reply_i=0; reply_i<replies; ++reply_i) { \
        if (reply[reply_i].resp) {                \
            _pam_overwrite(reply[reply_i].resp);  \
            free(reply[reply_i].resp);            \
        }                                         \
    }                                             \
    if (reply)                                    \
        free(reply);                              \
} while (0)

#endif
