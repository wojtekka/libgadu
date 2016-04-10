#!/bin/sh

find . -name '*.c' > vera.list
find . -name '*.h' >> vera.list

grep -v 'protobuf-c.' vera.list > vera.list.new
mv -f vera.list.new vera.list

vera++ --root /vera-config/ --profile libgadu --error --inputs vera.list \
	-P max-line-length=120 -P max-file-length=5000 -P strict-trailing-space=1
