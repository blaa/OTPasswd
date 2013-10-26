#!/bin/bash

# Call from project directory: ./tools/<SCRIPT>

echo
echo '* DISTCLEAN tree'

make clean
rm -rf ./CMakeFiles ./CMakeCache.txt CTestTestfile.cmake Makefile cmake_install.cmake install_manifest.txt Testing .emacs.desktop.lock
find . -iname "#*"; find . -iname "*~*"   

pushd tools
make clean
popd

echo
echo '* YOU MAY WANT TO MANUALLY REMOVE THOSE:'
find . -name "#*"
find . -name "*~*"   
find . -name ".*" -type f

git count-objects
du -sh .git
sleep 1

echo 'END OF LIST'
echo

