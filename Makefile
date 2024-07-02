# Image URL to use all building/pushing image targets
PROJECT_NAME ?= sealos-nm-agent
PROJECT_TEST_NAME ?= sealos-nm-agent-test
REV ?= $(shell git rev-parse --short HEAD)
PUBLIC_REPO ?= docker.io/dinoallo
DEBUG_REPO ?= 192.168.3.2:5000/dinoallo
IMG ?= $(PUBLIC_REPO)/$(PROJECT_NAME)
DEBUG_IMG ?= $(DEBUG_REPO)/$(PROJECT_NAME)
TEST_IMG ?= $(PUBLIC_REPO)/$(PROJECT_TEST_NAME)
TAG ?= $(IMG):$(REV)
DEBUG_TAG ?= $(DEBUG_IMG):$(REV)
TEST_TAG ?= $(TEST_IMG):$(REV)
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
# Obtain an absolute path to the directory of the Makefile.
# Assume the Makefile is in the root of the repository.
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UIDGID := $(shell stat -c '%u:%g' ${REPODIR})

.DEFAULT_TARGET = all

.PHONY: all 
all: generate fmt

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

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

.PHONY: oci-build-debug
oci-build-debug: generate
	nerdctl build -t ${DEBUG_TAG} -f ./build/docker/main/Dockerfile.debug --output=type=image,oci-mediatypes=true .
	
.PHONY: oci-push-debug
oci-push-debug: oci-build-debug ## Push docker image with the agent.
	nerdctl push ${DEBUG_TAG}

.PHONY: oci-publish-debug
oci-publish-debug: oci-build-debug
	nerdctl tag ${DEBUG_TAG} ${TAG}
	nerdctl push ${TAG}

.PHONY: oci-build-test
oci-build-test: generate
	nerdctl build -t ${TEST_TAG} -f ./build/docker/test/Dockerfile --output=type=image,oci-mediatypes=true .
	nerdctl push ${TEST_TAG}

# TODO: merge this into `make generate`
protoc:
	@echo "Generating Go files"
	cd api/proto && protoc --go_out=. --go-grpc_out=. \
		--go-grpc_opt=paths=source_relative --go_opt=paths=source_relative *.proto
