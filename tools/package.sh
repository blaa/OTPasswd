#!/bin/sh
# Run us in project dir...
if [ ! -e CMakeLists.txt ]; then
	echo "Run from main project directory"
	exit 1
fi

if [ ! -n "$1" ]; then
	echo "Give version number as first parameter."
	echo "Script will create ../otpasswd-ver then!"
	exit 1;
fi

SOURCEDIR=$(basename $(pwd))
DIR="otpasswd-$1"

cd .. 


echo "Removing $DIR and copying $SOURCEDIR to $DIR"
sleep 1
rm -rf $DIR

cp $SOURCEDIR $DIR -R
cd $DIR

echo Cleaning up
make clean
rm -rf CMakeCache.txt cmake_install.cmake CTestTestfile.cmake install_manifest.txt CMakeFiles otpasswd.info lcov Testing .git .gitignore tools examples/otpasswd-testcase po/
find . -iname ".*.sw?" -exec rm -f {} \;

echo Taring up
cd ..
tar -jcvf "$DIR".tar.bz2 $DIR

echo 'Remember to sign it!'

