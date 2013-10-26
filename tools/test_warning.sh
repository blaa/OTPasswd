#!/bin/bash

# Used by ctest

if [[ "$NO_WARNING" == "1" ]]; then
	echo "No warning for tests"
	exit 0
fi
cat <<EOF

THIS TESTS WILL MODIFY YOUR STATE INFORMATION. 
DO NOT RUN THEM ON THE USER WHICH HAS USABLE KEY DATA!

Ctrl-C to stop!

Starting in 7 seconds. 

Tests should be run with english locale, DB setting in database must equal
'user'. OTPasswd will try to run from source directory when compiled in DEBUG mode
otherwise will fail.

Set NO_WARNING=1 to test faster
EOF

sleep 7
