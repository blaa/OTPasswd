#!/bin/bash

# Executed after tests (ctest) - restores user state data

if [ ! -f "$HOME/.otpasswd.backup" ]; then
	echo '* No state to restore - ignoring'
	exit 0
fi

if [ -f "$HOME/.otpasswd" ]; then
	echo "ERROR: $HOME/.otpasswd exists - will not restore from $HOME/.otpasswd.backup"
        echo "You've got two state files .otpasswd and .otpasswd.backup"
        exit 1
fi


mv $HOME/.otpasswd.backup $HOME/.otpasswd
rm -f $HOME/.otpasswd_testcase


cat <<EOF

*******************************************
            State file restored
*******************************************
EOF


