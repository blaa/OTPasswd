#!/bin/bash

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


rm -rf lcov gcov

# GCOV version:

# mkdir gcov; cd gcov
#echo "Generating .gcov files"
# Generate .gcov files for all .c files in project (except for pam)
#for i in $(find '../CMakeFiles' -iname "*.gcda"); do b=$(basename $i); echo $b; d=$(dirname $i); gcov -o $d $i; done 

# LCOV version:
mkdir lcov
lcov --directory . --capture --output-file otpasswd.info --test-name OTPasswdCoverage
genhtml --prefix . --output-directory lcov/ --title "OTPasswd coverage test" --show-details otpasswd.info
