#!/usr/bin/make -f

BUILD_SCRIPT := $(shell pwd)/../build.sh
DOCKER_IMAGE := libgadu/builder-opensuse:42.1

.PHONY: all clean

all: builder-artifacts

clean: builder-clean
	rm -rf artifacts

include ../../common.mk
