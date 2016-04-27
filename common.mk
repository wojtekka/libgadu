#!/usr/bin/make -f

BRANCH ?= master
REVISION ?= HEAD
REPO ?= https://github.com/wojtekka/libgadu.git
SHIP_TARBALL ?= no
STAY_INTERACTIVE ?= no

.PHONY: all clean builder-artifacts docker-image docker-push

BUILDER_IMAGE_STAMP := .builder-image.stamp

BUILDER_ARTIFACT_STAMP := .builder-artifacts.stamp
BUILDER_ARTIFACT_DIR := artifacts

UID := $(shell id -u)
GID := $(shell id -g)

WORK_DIR := $(shell pwd)

REPO_VOLUME := $(shell test -z ${LOCAL_REPO} || printf -- "-v %s:/repo" ${LOCAL_REPO})
ifeq "$(REPO_VOLUME)" ""
	REAL_REPO = "$(REPO)"
else
	REAL_REPO = "file:///repo"
endif

ifneq "${SET_CC}" ""
	CC_OVERRIDE := -e CC=${SET_CC}
endif

ifneq "${CONFIGURE_FLAGS}" ""
	CONFIGURE_FLAGS := -e CONFIGURE_FLAGS="${CONFIGURE_FLAGS}"
endif

ifneq "$(SHIP_TARBALL)" "no"
	SHIP_TARBALL_SWITCH := -e SHIP_TARBALL=yes
endif

ifeq "$(STAY_INTERACTIVE)" "no"
	DOCKER_RUN_FLAGS := --rm
else
	DOCKER_RUN_FLAGS := -t -i -e STAY_INTERACTIVE=yes
endif

builder: $(BUILDER_ARTIFACT_STAMP)

builder-clean:
	rm -f $(BUILDER_ARTIFACT_STAMP)
	rm -rf artifacts
	rm -rf .deps

$(BUILDER_ARTIFACT_STAMP): $(BUILD_SCRIPT) $(ROOT_DIR)/build-common.sh
	rm -rf $(BUILDER_ARTIFACT_DIR)
	mkdir -p $(BUILDER_ARTIFACT_DIR)
	docker pull $(DOCKER_IMAGE) || true
	docker run $(DOCKER_RUN_FLAGS) \
		-v $(WORK_DIR)/$(BUILDER_ARTIFACT_DIR):/artifacts/ \
		-v $(BUILD_SCRIPT):/build.sh \
		-v $(ROOT_DIR)/build-common.sh:/build-common.sh \
		$(REPO_VOLUME) \
		-e BRANCH=$(BRANCH) \
		-e REVISION=$(REVISION) \
		-e REPO=$(REAL_REPO) \
		-e UID=$(UID) \
		-e GID=$(GID) \
		$(CC_OVERRIDE) \
		$(CONFIGURE_FLAGS) \
		$(SHIP_TARBALL_SWITCH) \
		$(EXTRA_ENVIRONMENT) \
		$(DOCKER_IMAGE) \
		/build-common.sh
	touch $(BUILDER_ARTIFACT_STAMP)

builder-artifacts: $(BUILDER_ARTIFACT_STAMP)

docker-image: Dockerfile
	docker build --rm -t $(DOCKER_IMAGE) .

docker-push: Dockerfile
	docker push $(DOCKER_IMAGE)

docker-clean:
	docker rmi $(DOCKER_IMAGE)
