#!/usr/bin/make -f

ROOT_DIR := $(shell pwd)/..
BUILD_SCRIPT := $(shell pwd)/build.sh
DOCKER_IMAGE := libgadu/builder-check-style:latest

EXTRA_ENVIRONMENT := -v $(shell pwd)/vera-config:/vera-config

.PHONY: all clean

all: builder-artifacts

clean: builder-clean

include $(ROOT_DIR)/common.mk
