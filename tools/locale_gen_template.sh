#!/bin/bash
xgettext -d otpasswd -s -o po/otpasswd.pot -k_ utility/*.h  utility/*.c

# Create/update translation files
touch po/pl.po
touch po/de.po

# Update original texts / add new
msgmerge -U po/pl.po po/otpasswd.pot
msgmerge -U po/de.po po/otpasswd.pot
