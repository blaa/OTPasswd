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
echo 'We will also remove two directories: ./lcov and ./gcov.'
echo
echo 'Starting in 5 seconds'
sleep 5
echo Starting...
sleep 1

rm -rf lcov gcov

make clean
rm -rf CMakeFiles CMakeCache.txt 
cmake -DDEBUG=1 -DPROFILE=1 . || (echo "Config failed"; exit 1)
make || (echo "Build failed"; exit 1)


echo "Installing into the system"
make install || exit 1
cat /etc/otpasswd/otpasswd.conf | sed 's/# DB=/DB=/g' > /etc/otpasswd/otpasswd.conf.2
mv /etc/otpasswd/otpasswd.conf.2 /etc/otpasswd/otpasswd.conf
cp examples/otpasswd-testcase /etc/pam.d/

# additional testcases which will create a state
rm -rf ~/.otpasswd
yes no | ./otpasswd -c salt=off -c codelength=5 -c alphabet=3 -v -c contact=ble -c label=blebla -k
yes yes | ./otpasswd -v -c salt=on -c codelength=6 -c alphabet=2 -c contact=ble -c label=lala -k
yes yes | ./otpasswd -v -r

# Pam tests on safe defaults please.
yes yes | ./otpasswd -v -c salt=on -c alphabet=1 -c codelength=4 -k

# This should run --check atleast once
make test 

echo "Building PAM testcase"
(cd tools; make pam_test) || exit 5

# Regenerate state
yes yes | ./otpasswd -v -c salt=on -c alphabet=1 -c codelength=4 -k

./tools/pam_test root $(./otpasswd -t current)

otpasswd -s 5000 # After last passcode

./tools/pam_test root $(./otpasswd -t current)

# Cause funny error:
otpasswd -s 4294967260 # Skip to the last
otpasswd -a 1234 # Use it up!
otpasswd -c show=off

./tools/pam_test root $(./otpasswd -t current)

# Regenerate safe defaults
yes yes | ./otpasswd -v -c salt=on -c alphabet=1 -c codelength=4 -k

# GCOV version:

# mkdir gcov; cd gcov
#echo "Generating .gcov files"
# Generate .gcov files for all .c files in project (except for pam)
#for i in $(find '../CMakeFiles' -iname "*.gcda"); do b=$(basename $i); echo $b; d=$(dirname $i); gcov -o $d $i; done 

# LCOV version:
mkdir lcov
lcov --directory . --capture --output-file otpasswd.info --test-name OTPasswdCoverage
genhtml --prefix . --output-directory lcov/ --title "OTPasswd coverage test" --show-details otpasswd.info

