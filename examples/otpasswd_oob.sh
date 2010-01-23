#!/bin/sh

# $1 - contact
# $2 - passcode
# $3 - current column... (in future)
# $4 - current row... (in future)

# Passcode with extended alphabet can contain 
# ' " ~ etc. Keep it safe!

# Exemplary simple OOB utility. (Polish 'Plus' operator internet gateway)
# Change it before using.
# Contacts are phone numbers in format "48xxxyyyzzz"

SENDMAIL=/usr/bin/sendmail # sbin under FreeBSD

TO="<$1@text.plusgsm.pl>"
echo -en "To:$TO\nFrom: OTP <Ted@thera.be>\nSubject: OTP password\n\nPasscode = $2\n" | $SENDMAIL "$TO" 

# Tests.
# whoami >> /tmp/OOB_TEST
# echo "CONTACT '$1' CODE '$2'" >> /tmp/OOB_TEST
