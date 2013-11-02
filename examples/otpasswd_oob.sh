#!/bin/bash

# OTPasswd OOB external script EXAMPLE.
# It won't work by itself.

# If you receive emails on your mobile you might want to send an email
# here; that's pretty much simpliest thing you might want to do.

# $1 - contact data set by user (sanitize!)
# $2 - requested passcode 
# Not yet implemented / reserved
# $3 - passcode column (in future)
# $4 - passcode row (in future)
# $5 - passcode passcard (in future)

# Passcode with extended alphabet can contain 
# ' " ~ etc. Keep it safe!

# Warning - contact data is settable by user. Make sure
# to SANITIZE it correctly! If it's a phone number you can 
# check it with regular expression

# Example for Polish 'PLUS' operator via Internet SMS gateway.
# Contacts are phone numbers in format "48xxxyyyzzz"

SENDMAIL=/usr/sbin/sendmail

##
# Sanitize contact data
echo "$1" | egrep '^[0-9]+$' > /dev/null 
if [ $? != 0 ]; then
	echo "Contact data is not a valid phone number"
	exit 1
fi

##
# Send an email
TO="<$1@text.plusgsm.CHANGEME.pl>"
echo -en "To:$TO\nFrom: OTP <Ted@SETME.be>\nSubject: OTP password\n\nPasscode = $2\n" | $SENDMAIL "$TO" 

##
# Tests - if you're unsure if OOB is executed.
# whoami >> /tmp/OOB_TEST
# echo "CONTACT '$1' CODE '$2'" >> /tmp/OOB_TEST


exit 0
