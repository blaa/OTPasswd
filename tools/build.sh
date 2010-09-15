#!/bin/sh
echo Cleaning...
make clean
rm -rf ./CMakeFiles ./CMakeCache.txt CTestTestfile.cmake Makefile cmake_install.cmake install_manifest.txt
echo OK
sleep 1
echo Configuring...
cmake -DDEBUG=1 .
make 
