#!/bin/sh
echo -n Cleaning...
rm -rf ./CMakeFiles ./CMakeCache.txt
echo OK
sleep 1
echo Configuring...
cmake .
make 
