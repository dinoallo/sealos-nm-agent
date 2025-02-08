ENV_FILE ?= make.env
include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE))
# The following variable can be configured via `make.env`
PROJECT_NAME ?= sealos-nm-agent
PROJECT_TEST_NAME ?= sealos-nm-agent-test
REV ?= $(shell git rev-parse --short HEAD)
PUBLIC_REPO ?= docker.io/user
DEBUG_REPO ?= docker.io/user
IMG ?= $(PUBLIC_REPO)/$(PROJECT_NAME)
DEBUG_IMG ?= $(DEBUG_REPO)/$(PROJECT_NAME)
TEST_IMG ?= $(PUBLIC_REPO)/$(PROJECT_TEST_NAME)
TAG ?= $(IMG):$(REV)
DEBUG_TAG ?= $(DEBUG_IMG):$(REV)
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

.PHONY: predeploy-debug
predeploy: 
	cd deploy/kustomize/staging && kustomize edit set image agent-daemon=${DEBUG_TAG}
	kustomize build deploy/kustomize/default > deploy/kustomize/example-deploy.yaml

.PHONY: image-build-debug
image-build-debug: generate
	${DOCKER} build -t ${DEBUG_TAG} -f ./build/docker/main/Dockerfile.debug --output type=oci .
	
.PHONY: image-push-debug
image-push-debug: image-build-debug
	${DOCKER} push --insecure-registry ${DEBUG_TAG}

.PHONY: image-publish-debug
image-publish-debug: image-build-debug
	${DOCKER} tag ${DEBUG_TAG} ${TAG}
	${DOCKER} push ${TAG}

.PHONY: image-build-test
image-build-test: generate
	${DOCKER} build -t ${TEST_TAG} -f ./build/docker/test/Dockerfile --output type=oci .
	${DOCKER} push ${TEST_TAG}
