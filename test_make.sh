#!/bin/bash

if [ "$1" == "" ]; then
    echo "Usage: $0 <file>"
    exit 1
fi
FILE="$1"

if [ "x${1}" == "xdist" ] ; then
  ARC="${PWD##*/}" ; rm -f office_analyzer
  tar cpzf "../${ARC}.tar.gz" .
  exit
fi
if [ "x${1}" == "xclean" ] ; then rm -f office_analyzer ; exit ; fi
gcc -s -o office_analyzer test.c -lncursesw -lzip
./office_analyzer "$FILE"
