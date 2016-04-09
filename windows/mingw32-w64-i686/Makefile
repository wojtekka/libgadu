#!/usr/bin/make -f

ROOT_DIR := $(shell pwd)/../..
BUILD_SCRIPT := $(shell pwd)/../build.sh
DOCKER_IMAGE := libgadu/builder-windows:mingw32-w64-i686

.PHONY: all clean

all: builder-artifacts

clean: builder-clean
	rm -rf artifacts

include $(ROOT_DIR)/common.mk
