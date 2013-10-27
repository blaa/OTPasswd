#!/bin/bash
if [ ! -e CMakeLists.txt ]; then
	echo "Run this script from main project directory: ./tools/do_pam_tests.sh"
	exit 2
fi

if [ "$(whoami)" != "root" ]; then
	echo "Must be root for this testcase"
	exit 3
fi

echo "You should KNOW WHAT YOU ARE DOING WHEN RUNNING THIS!"
sleep 2
 
echo "This command WILL DESTROY your state!"
echo
echo 'Starting in 5 seconds'
#sleep 5
echo Starting...
#sleep 1


clean_build () {
    ./tools/clean.sh

    cmake -DDEBUG=1 -DPROFILE=1 . || (echo "Config failed"; exit 1)
    make || (echo "Build failed"; exit 1)

    echo '* Building PAM testcase'
    pushd tools
    make pam_test || exit 5
    popd

    echo '* INSTALLING INTO THE SYSTEM'
    cp tools/otpasswd-testcase /etc/pam.d/
    cp agent_otp otpasswd /usr/bin
    cp pam_otpasswd.so /lib/security/
}

#clean_build;
# This should run --check atleast once

echo '* INITIAL SIMPLE TEST'
#ctest .
echo


echo
echo '* TESTING SIMPLE'
# Regenerate state
yes yes | ./otpasswd -v -c salt=on -c alphabet=1 -c codelength=4 -k

# Do some -u tests
./otpasswd -u root -t current
./otpasswd -u 0 -t '[current]'
./otpasswd -u 9000 -t '[current]'

echo '* TESTING VIA PAM'

echo
echo '* TEST 1'
./tools/pam_test root $(./otpasswd -t current)

otpasswd -s 5000 # After last passcode

echo
echo '* TEST 2'
./tools/pam_test root $(./otpasswd -t current)

# Cause funny error:
otpasswd -s 4294967260 # Skip to the last
otpasswd -a 1234 # Use it up!
otpasswd -c show=off

echo
echo "* TEST 3 SHOULDN'T WORK"
./tools/pam_test root $(./otpasswd -t current)

echo
echo "* TEST 4 SHOULDN'T WORK AGAIN"
./tools/pam_test root $(./otpasswd -t current)

# Regenerate safe defaults
yes yes | ./otpasswd -v -c salt=on -c alphabet=1 -c codelength=4 -k

# GCOV version:

# mkdir gcov; cd gcov
#echo "Generating .gcov files"
# Generate .gcov files for all .c files in project (except for pam)
#for i in $(find '../CMakeFiles' -iname "*.gcda"); do b=$(basename $i); echo $b; d=$(dirname $i); gcov -o $d $i; done 

# LCOV version:
#mkdir lcov
#lcov --directory . --capture --output-file otpasswd.info --test-name OTPasswdCoverage
#genhtml --prefix . --output-directory lcov/ --title "OTPasswd coverage test" --show-details otpasswd.info

