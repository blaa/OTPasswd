#!/bin/sh
# Used by make test (ctest)

export LC_ALL="en_EN" 
yes yes | ./otpasswd -v -r 
