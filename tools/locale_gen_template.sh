#!/bin/sh
# Read all strings in _() from source code
xgettext -d otpasswd -s -o po/otpasswd.pot -k_ */*.h  */*.c

# Create/update translation files
#touch po/pl.po
#touch po/de.po

# Update translations/add new texts
msgmerge -U po/pl.po po/otpasswd.pot
#msgmerge -U po/de.po po/otpasswd.pot

# Use poedit (for example) to translate. 
# Adding new translation might require changes in CMakeLists.txt
