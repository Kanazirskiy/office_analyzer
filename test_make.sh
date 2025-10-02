#!/bin/bash
if [ "x${1}" == "xdist" ] ; then
  ARC="${PWD##*/}" ; rm -f office_analyzer
  tar cpzf "../${ARC}.tar.gz" .
  exit
fi
if [ "x${1}" == "xclean" ] ; then rm -f office_analyzer ; exit ; fi
gcc -s -o office_analyzer test.c -lncursesw -lzip
./office_analyzer test.docx
