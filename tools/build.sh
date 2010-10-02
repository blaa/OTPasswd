#!/bin/sh
echo 'This script will build OTPasswd in debug mode!'
echo Cleaning...
make clean
rm -rf ./CMakeFiles ./CMakeCache.txt CTestTestfile.cmake Makefile cmake_install.cmake install_manifest.txt
echo 'Cleaned! hit Control-C to get a clean repos.'
sleep 3
echo Configuring...
cmake -DDEBUG=1 .
make 
