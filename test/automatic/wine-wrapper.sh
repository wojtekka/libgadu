#!/bin/bash

# it strips quotes, but for this purpose it's not a problem

newcmd=""
for param in "$@" ; do
	newcmd="${newcmd}${param} "
	if [ "$param" == "--" ]; then
		newcmd="${newcmd}wine "
	fi
done
$newcmd
