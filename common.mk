#!/usr/bin/make -f

BRANCH ?= master
REPO ?= https://github.com/wojtekka/libgadu.git

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

builder: $(BUILDER_ARTIFACT_STAMP)

builder-clean:
	rm -f $(BUILDER_ARTIFACT_STAMP)

$(BUILDER_ARTIFACT_STAMP): $(BUILD_SCRIPT)
	rm -rf $(BUILDER_ARTIFACT_DIR)
	mkdir -p $(BUILDER_ARTIFACT_DIR)
	docker pull $(DOCKER_IMAGE) || true
	docker run --rm \
		-v $(WORK_DIR)/$(BUILDER_ARTIFACT_DIR):/artifacts/ \
		-v $(BUILD_SCRIPT):/build.sh \
		$(REPO_VOLUME) \
		-e BRANCH=$(BRANCH) \
		-e REPO=$(REAL_REPO) \
		-e UID=$(UID) \
		-e GID=$(GID) \
		$(EXTRA_ENVIRONMENT) \
		$(DOCKER_IMAGE) \
		/build.sh
	touch $(BUILDER_ARTIFACT_STAMP)

builder-artifacts: $(BUILDER_ARTIFACT_STAMP)

docker-image: Dockerfile
	docker build --rm -t $(DOCKER_IMAGE) .

docker-push: Dockerfile
	docker push $(DOCKER_IMAGE)

docker-clean:
	docker rmi $(DOCKER_IMAGE)
