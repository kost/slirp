#!/bin/bash
#Cygwin
#Stack trace of a slirp stack dump file.
#Thanks google, people on internet.
awk '/^[0-9]/{print $2}' slirp.exe.stackdump | addr2line -f -e slirp.exe
