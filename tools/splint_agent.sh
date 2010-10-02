#!/bin/sh

BASE="-commentchar %"
INCLUDES="-Ilibotp -Icommon -I/usr/include/security"

SILENCE_ON_STRONG='-unqualifiedtrans -formatconst -nullpass -usereleased -compdef -mustfreefresh -predboolint -boolops'
CHECKING="$SILENCE_ON_STRONG -fcnuse  +ignorequals -initallelements -unrecog -globs +posixlib +skip-posix-headers"

AGENT="agent/agent.c agent/agent_private.c agent/security.c agent/agent_interface.c agent/request.c"
PAM="pam/pam_helpers.c pam/pam_otpasswd.c"
LIBOTP="libotp/config.c libotp/db_file.c libotp/db_ldap.c libotp/db_mysql.c libotp/ppp.c libotp/state.c"
UTILITY="utility/actions_helpers.c utility/actions.c utility/cards.c utility/otpasswd.c"
COMMON=" common/crypto.c common/num.c common/print.c"

SOURCE="$AGENT $PAM"



echo "Command is:" splint $@ $BASE $INCLUDES $CHECKING $SOURCE
echo 'Try with -weak first'

splint $@ $BASE $INCLUDES $CHECKING $SOURCE
