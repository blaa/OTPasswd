#!/bin/sh
echo Cleaning...
make clean
rm -rf ./CMakeFiles ./CMakeCache.txt
echo OK
sleep 1
echo Configuring...
cmake .
make 
