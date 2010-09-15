#!/bin/bash
# Used by make test (ctest)
export LC_ALL="en_EN" 
yes no | ./otpasswd -v -k 
