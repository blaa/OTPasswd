#!/bin/bash

# $1 - contact
# $2 - passcode
# $3 - current column... (in future)
# $4 - current row... (in future)

# Passcode with extended alphabet can contain 
# ' " ~ etc. Keep it safe!

# Warning - contact data is settable by user. Make sure
# to SANITIZE it correctly! If it's a phone number you can 
# check it with regular expression

# Exemplary simple OOB utility. (Polish 'Plus' operator internet gateway)
# Change it before using.
# Contacts are phone numbers in format "48xxxyyyzzz"

SENDMAIL=/usr/sbin/sendmail # Update to match your system. 

# Sanitize contact data
echo "$1" | egrep '^[0-9]+$' > /dev/null 
if [ $? != 0 ]; then
	echo "Contact data is not a valid phone number"
	exit 1
fi

# Send email
TO="<$1@text.plusgsm.CHANGEME.pl>"
echo -en "To:$TO\nFrom: OTP <Ted@SETME.be>\nSubject: OTP password\n\nPasscode = $2\n" | $SENDMAIL "$TO" 

# Tests.
# whoami >> /tmp/OOB_TEST
# echo "CONTACT '$1' CODE '$2'" >> /tmp/OOB_TEST

exit 0
