#!/bin/bash
#Cygwin
#Stack trace of a stack dump file.
#Thanks google, people on internet.
awk '/^[0-9]/{print $2}' $1.exe.stackdump | addr2line -f -e $1.exe
