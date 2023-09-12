# Image URL to use all building/pushing image targets
IMG ?= dinoallo/sealos-networkmanager-agent:latest
DEBUG_IMG ?= dinoallo/sealos-networkmanager-agent:dev
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

.PHONY: docker-build
docker-build: ## Build docker image with the agent.
	docker build -t ${IMG} .

.PHONY: docker-build-debug
docker-build-debug:
	docker build -t ${DEBUG_IMG} -f ./Dockerfile.debug .

.PHONY: docker-push
docker-push: ## Push docker image with the agent.
	docker push ${IMG}
	
.PHONY: docker-push-debug
docker-push-debug: ## Push docker image with the agent.
	docker push ${DEBUG_IMG}