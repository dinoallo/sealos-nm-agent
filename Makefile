ENV_FILE ?= make.env
include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE))
# The following variable can be configured via `make.env`
PROJECT_NAME ?= sealos-nm-agent
PROJECT_TEST_NAME ?= sealos-nm-agent-test
REV ?= $(shell git rev-parse --short HEAD)
PUBLIC_REPO ?= docker.io/user
IMG ?= $(PUBLIC_REPO)/$(PROJECT_NAME)
TEST_IMG ?= $(PUBLIC_REPO)/$(PROJECT_TEST_NAME)
TAG ?= $(IMG):$(REV)
LATEST_TAG ?= $(IMG):latest
TEST_TAG ?= $(TEST_IMG):$(REV)
DOCKER ?= docker
# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
OBJCOPY ?= llvm-objcopy
CFLAGS := -O2 -g -Wall -Werror -fno-stack-protector $(CFLAGS)

.DEFAULT_TARGET = all

.PHONY: all
all: generate fmt

.PHONY: fmt
fmt:
	go fmt ./...
	find . -type f -name "*.c" | xargs clang-format -i

.PHONY: generate ## $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLANGS := $(CFLAGS)
generate:
	go generate ./...

.PHONY: predeploy
predeploy:
	cd deploy/kustomize/staging && kustomize edit set image agent-daemon=${TAG}
	kustomize build deploy/kustomize/default > deploy/kustomize/example-deploy.yaml

.PHONY: image-build
image-build: generate
	${DOCKER} build -t ${TAG} -f ./build/docker/main/Dockerfile .

.PHONY: image-push
image-push:
	${DOCKER} push ${TAG}

.PHONY: image-publish
image-publish: image-build
	${DOCKER} tag ${TAG} ${LATEST_TAG}
	${DOCKER} push ${TAG}
	${DOCKER} push ${LATEST_TAG}

.PHONY: image-build-test
image-build-test: generate
	${DOCKER} build -t ${TEST_TAG} -f ./build/docker/test/Dockerfile .

.PHONY: image-push-test
image-push-test: image-build-test
	${DOCKER} push ${TEST_TAG}
