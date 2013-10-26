#!/bin/bash

# Executed before tests (ctest) - backs up user state file

cat <<EOF

*******************************************
OTPasswd state can be overwritten by tests!
      Will try to back it up for you
*******************************************

EOF
echo -en '\a'

sleep 1

if [ -f "$HOME/.otpasswd.backup" ]; then
    echo
    echo "ERROR, unable to continue:"
    echo ".otpasswd.backup already exists. Previous testcase unfinished?"
    echo "Move manually .otpasswd.backup to .otpasswd or remove it"
    echo "if there's no valuable data."
    echo
    exit 1
fi

if [ -f "$HOME/.otpasswd" ]; then
    echo "OTPasswd state file exists. Moving it to ~/.otpasswd.backup"
    mv $HOME/.otpasswd $HOME/.otpasswd.backup
else
    echo 'No state file found - not backing up'
fi


cat <<EOF

Tests should be run with english locale, DB setting in database must equal
'user'. OTPasswd will try to run from source directory only when compiled in
DEBUG mode - otherwise it will fail.

EOF

exit 0
