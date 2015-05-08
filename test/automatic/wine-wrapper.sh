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

# bug: _mktemp_s run on wine creates 0444 chmoded file,
#      so it can't remove temp files by itself
rm -rf hashdata.*
