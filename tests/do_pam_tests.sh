#!/bin/bash

if [ ! -e CMakeLists.txt ]; then
	echo "Run this script from main project directory: ./tests/do_pam_tests.sh"
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
echo 'Starting in 10 seconds'
sleep 10
echo Starting...
sleep 1

rm -rf lcov gcov

make clean
rm -rf CMakeFiles CMakeCache.txt 
cmake -DDEBUG=1 -DPROFILE=1 . || (echo "Config failed"; exit 1)
make || (echo "Build failed"; exit 1)


echo "Installing into the system"
make install || exit 1
cp examples/otpasswd-testcase /etc/pam.d/

# additional testcases which will create a state
rm -rf ~/.otpasswd
yes no | ./otpasswd -v -k
yes yes | ./otpasswd -v -k

# This should run --check atleast once
make test 

echo "Building PAM testcase"
(cd tests; make pam_test) || exit 5

./tests/pam_test root $(./otpasswd -t current)

# GCOV version:

# mkdir gcov; cd gcov
#echo "Generating .gcov files"
# Generate .gcov files for all .c files in project (except for pam)
#for i in $(find '../CMakeFiles' -iname "*.gcda"); do b=$(basename $i); echo $b; d=$(dirname $i); gcov -o $d $i; done 

# LCOV version:
mkdir lcov
lcov --directory . --capture --output-file otpasswd.info --test-name OTPasswdCoverage
genhtml --prefix . --output-directory lcov/ --title "OTPasswd coverage test" --show-details otpasswd.info

