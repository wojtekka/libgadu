#!/usr/bin/make -f

ROOT_DIR := $(shell pwd)/../..
BUILD_SCRIPT := $(shell pwd)/../build.sh
DOCKER_IMAGE := libgadu/builder-windows:mingw32-w64-i686

EXTRA_ENVIRONMENT := -e TARGET=i686-w64-mingw32

.PHONY: all clean

all: builder-artifacts

clean: builder-clean

.deps/install-winbind.sh: $(shell pwd)/../install-winbind.sh
	mkdir .deps
	cp -f $< $@

docker-image: .deps/install-winbind.sh

include $(ROOT_DIR)/common.mk
