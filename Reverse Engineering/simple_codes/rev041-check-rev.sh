#!/bin/bash

echo "The following lines of code may be vulernable to overflows"
grep -n 'strcpy' $1

echo "The following lines could be vulnerable to format string errors"
grep -n -B1 'printf' $1 | egrep -A1 '__esp \= &'

