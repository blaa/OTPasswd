#!/bin/bash

# Call from outside of project directory: ./otpasswd/tools/<SCRIPT> <VERSION>
# Assuming otpasswd is inside $DEVDIR directory.
# Call AFTER calling package.sh

DEVDIR=otpasswd
KEY=D59B22FE

if [ -z "$1" ]; then
    echo "Pass version as a first argument"
    exit 1 
fi

VERSION=$1
PACKAGE="otpasswd-$VERSION"
TARBALL="otpasswd_$VERSION".tar.xz
ORIG_TARBALL="otpasswd_$VERSION".orig.tar.xz

if [ ! -f "$TARBALL" ]; then
    echo "Call package.sh first and get back here"
    exit 1
fi


echo '* CLEANUP'
rm -rf debian_packaging

echo '* CREATE STRUCTURE'
mkdir debian_packaging
cp $TARBALL "debian_packaging/"$ORIG_TARBALL


echo '* UNPACK'
pushd debian_packaging
  tar -Jxf $ORIG_TARBALL
popd

echo
echo '* MOVE DEBIAN FILES'
cp otpasswd/tools/debian_pkg_template debian_packaging/$PACKAGE/debian -Rv

echo
echo '* BUILD PACKAGE'
pushd debian_packaging/$PACKAGE

if [ "$NO_SIGN" == "1" ]; then
    dpkg-buildpackage -uc -us
else
    dpkg-buildpackage -k$KEY
fi
popd

