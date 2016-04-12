#!/usr/bin/make -f

ROOT_DIR := $(shell pwd)/..
BUILD_SCRIPT := $(shell pwd)/build.sh
DOCKER_IMAGE := libgadu/builder-coverity:latest

EXTRA_ENVIRONMENT := -e COVERITY_TOKEN=$(COVERITY_TOKEN) -e COVERITY_EMAIL=$(COVERITY_EMAIL)

.PHONY: all clean

all: builder-artifacts

clean: builder-clean

.deps/cov-analysis.tar.gz:
	mkdir -p .deps
	read -s -p "Token: " COV_TOKEN && \
	wget https://scan.coverity.com/download/linux-64 --post-data "token=$${COV_TOKEN}&project=wojtekka%2Flibgadu" -O $@.tmp
	mv -f $@.tmp $@

docker-image: .deps/cov-analysis.tar.gz

include $(ROOT_DIR)/common.mk
