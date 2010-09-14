#!/bin/bash
# Used by make test (ctest)
yes yes | ./otpasswd -v -c codelength=4 -c alphabet=1 -c show=on -c salt=on -c label="lab" -c contact="cont" -k 
