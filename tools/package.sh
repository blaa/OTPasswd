#!/bin/bash

# Call from outside of project directory: ./otpasswd/tools/<SCRIPT> <VERSION>
# Assuming otpasswd is inside otpasswd directory

DEVDIR=otpasswd

if [ -z "$1" ]; then
    echo "Pass version as a first argument"
    exit 1 
fi

VERSION=$1
PACKAGE="otpasswd_$VERSION"

# FUNCTIONS
test_build () {
    echo
    echo '* IDIOT-TEST CURRENT SOURCE BEFORE PACKAGING'

    ./tools/clean.sh

    echo
    echo '* CMAKE'
    cmake -DDEBUG=1 -DDPROFILE=0 -DNLS=1 . || exit 1

    echo 
    echo '* MAKE'
    make || exit 1

    pushd tools
    make || exit 1
    popd

    echo
    echo '* BUILD SUCCESSFUL'

    if [ "$SKIPTESTS" != "1" ]; then
        echo
        echo '* TESTING'
        ctest . || (echo "BASIC TESTS FAILED"; exit 1)
    fi

    ./tools/clean.sh
}

check_versions () {
    echo
    echo '* CHECK VERSIONS'
    echo "Cmakelists versions:"
    grep OR_VERSION CMakeLists.txt
    grep PROG_VERSION $(find . -type f -regex '.*\.[ch]') | grep -i define

    echo
    echo "If they are ok - hit enter to continue"
    read
}

create_tree () {
    echo
    echo '* CREATE SOURCE TREE'

    rm -rf $PACKAGE
    cp $DEVDIR $PACKAGE -R

    echo
    echo '* CLEANING TREE'
    pushd $PACKAGE
    rm -rf .git .gitignore tools/.gitignore
    rm -rf .emacs*

    echo "CHECK THIS:"
    find . -type f -iname '.*'
    find . -iname '*~*'
    find . -iname '*#*'

    popd
}

echo '* CREATING' $PACKAGE
sleep 1

pushd $DEVDIR

check_versions;
test_build;

popd 

create_tree;

TBZ2="$PACKAGE".tar.bz2
tar -jcf $TBZ2 $PACKAGE || exit 1

echo
ls -l $TBZ2
sha256sum $TBZ2

echo
echo "DONE"
