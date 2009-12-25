#!/bin/bash

echo "This command can modify your state! We will move your"
echo '~/.otpasswd file into ~/.otpasswd_copy and then move it back.'
echo "But we can't help if you have configured global state."
echo 'We will also remove two directories: ./lcov and ./gcov.'
echo
echo 'Starting in 10 seconds'
sleep 10

mv ~/.otpasswd ~/.otpasswd_copy
rm -rf lcov gcov

echo "Rebuilding the project. Will remove 'gcov'/'lcov' directories also in 3 seconds"
sleep 3

if [ ! -e CMakeLists.txt ]; then
	echo "Run this script from main project directory: ./tests/coverage.sh"
	exit 2
fi

rm -rf CMakeFiles CMakeCache.txt 
cmake -DPROFILE=1 . || (echo "Config failed"; exit 1)
make || (echo "Build failed"; exit 1)


# This should run --check atleast once
make test 


# GCOV version:

# mkdir gcov; cd gcov
#echo "Generating .gcov files"
# Generate .gcov files for all .c files in project (except for pam)
#for i in $(find '../CMakeFiles' -iname "*.gcda"); do b=$(basename $i); echo $b; d=$(dirname $i); gcov -o $d $i; done 

# LCOV version:
mkdir lcov
lcov --directory . --capture --output-file otpasswd.info --test-name OTPasswdCoverage
genhtml --prefix . --output-directory lcov/ --title "OTPasswd coverage test" --show-details otpasswd.info



# Restore state
mv ~/.otpasswd_copy ~/.otpasswd
