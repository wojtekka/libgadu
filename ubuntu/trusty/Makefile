#!/usr/bin/make -f

ROOT_DIR := $(shell pwd)/../..
BUILD_SCRIPT := $(shell pwd)/../build.sh
DOCKER_IMAGE := libgadu/builder-ubuntu:trusty

.PHONY: all clean

all: builder-artifacts

clean: builder-clean

include $(ROOT_DIR)/common.mk
