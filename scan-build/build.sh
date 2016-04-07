#!/bin/sh

./autogen.sh NOCONFIGURE=indeed
scan-build ./configure --without-protobuf
scan-build -o /artifacts/clangScanBuildReports make
