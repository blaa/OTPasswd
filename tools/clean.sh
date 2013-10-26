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

exit 0

