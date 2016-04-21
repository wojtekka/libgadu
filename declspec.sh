#!/bin/sh

# this script if for converting libgadu.h file to be used with MSVC

cat $1 \
	| sed -e "s/^[a-z][a-z0-9_ *]\+gg_[a-z0-9_]\+(.*/__declspec(dllimport) \0/g"\
	| sed -e "s/^extern [a-z][a-z0-9_ *]\+gg_[a-z0-9_]\+;.*/__declspec(dllimport) \0/g"\
	| sed -e "s/^extern [a-z][a-z0-9_ *]\+(\*gg_[a-z0-9_]\+)(.*/__declspec(dllimport) \0/g"
