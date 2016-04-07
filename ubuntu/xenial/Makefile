#!/usr/bin/make -f

BUILD_SCRIPT := $(shell pwd)/../build.sh
DOCKER_IMAGE := libgadu/builder-ubuntu:xenial

.PHONY: all clean

all: builder-artifacts

clean: builder-clean
	rm -rf artifacts

include ../../common.mk
