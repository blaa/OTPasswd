#!/bin/bash

# Call from outside of project directory: ./otpasswd/tools/<SCRIPT> <VERSION>
# Assuming otpasswd is inside otpasswd directory

DEVDIR=otpasswd

if [ -z "$1" ]; then
    echo "Pass version as a first argument"
    exit 1 
fi

VERSION=$1
PACKAGE="otpasswd-$VERSION"
TARBALL="otpasswd_$VERSION".tar.xz

# FUNCTIONS
test_build () {
    echo
    echo '* IDIOT-TEST CURRENT SOURCE BEFORE PACKAGING'

    ./tools/clean.sh || exit 1

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

    ./tools/clean.sh || exit 1
}

check_versions () {
    echo
    echo "* DATES:"
    egrep '20[01][0-9]|[0-9]{2}-[A-Za-z]{3}-[0-9]{2}' $(find . -type f -regex '.*\.[hc158]')
    echo
    echo '* CHECK VERSIONS'
    echo "Cmakelists versions:"
    grep OR_VERSION CMakeLists.txt
    grep PROG_VERSION $(find . -type f -regex '.*\.[ch]') | grep -i define
    egrep 'v[0-9]+\.[0-9]+' docs/*.1 docs/*.5 docs/*.8 examples/*conf | grep -v PPPv3.1

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
    rm -rf tools/debian_pkg_template

    echo "YOU MIGHT WANT TO MANUALLY REMOVE THOSE:"
    find . -type f -iname '.*'
    find . -iname '*~*'
    find . -iname '*#*'
    echo "END OF LIST"
    popd
}

echo '* CREATING' $PACKAGE
sleep 1

pushd $DEVDIR

check_versions;
if [ "$SKIPBUILD" != "1" ]; then
    test_build;
fi


popd 

create_tree;

tar -Jcf $TARBALL $PACKAGE || exit 1

echo
ls -l $TARBALL
sha256sum $TARBALL

echo
echo "Remember to TAG in git and sign the tarball."
echo "DONE"

