#!/bin/sh

NOCONFIGURE=indeed ./autogen.sh
scan-build ./configure --without-protobuf
scan-build -o /artifacts/clangScanBuildReports make
