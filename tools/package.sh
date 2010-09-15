#!/bin/sh
echo Rebuild to make sure
make clean
rm -rf ./CMakeFiles ./CMakeCache.txt CTestTestfile.cmake Makefile cmake_install.cmake install_manifest.txt Testing
cmake -DDEBUG=0 -DDPROFILE=0 -DNLS=1 . || exit 1
make || exit 1
(cd tools; make || exit 1) || exit 1

echo OK
echo "YOU MAY WANT TO REMOVE THIS:"
find . -iname "#*"; find . -iname "*~*"   
git count-objects
du -sh .git
sleep 1

git gc
git count-objects
du -sh .git

echo Cleaning...
make clean
rm -rf ./CMakeFiles ./CMakeCache.txt CTestTestfile.cmake Makefile cmake_install.cmake install_manifest.txt Testing .emacs.desktop.lock
(cd tools; make clean)


echo "MIGHT COME HANDY:"
echo "tar -jcvf otpasswd-x.x.tar.bz2 otpasswd-x.x"
