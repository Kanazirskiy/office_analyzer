#!/bin/bash

if [ "$1" == "" ]; then
    echo "Usage: $0 <file>"
    exit 1
fi
FILE="$1"

if [ "x${1}" == "xdist" ] ; then
  ARC="${PWD##*/}" ; rm -f inspector
  tar cpzf "../${ARC}.tar.gz" .
  exit
fi
if [ "x${1}" == "xclean" ] ; then rm -f inspector ; exit ; fi
gcc -s main.c ui.c ooxml.c rtf.c hex_viewer.c -lncursesw -lzip -o inspector

./inspector "$FILE"
