# Copyright 2025 The Butler Authors.
# SPDX-License-Identifier: Apache-2.0

BINARY_NAME := butler-server
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

IMG_REGISTRY ?= ghcr.io/butlerdotdev
IMG_NAME ?= butler-server
IMG_TAG ?= $(VERSION)
IMG ?= $(IMG_REGISTRY)/$(IMG_NAME):$(IMG_TAG)

.PHONY: all
all: build

##@ Development

.PHONY: build
build: ## Build the binary
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/server

.PHONY: run
run: ## Run the server locally
	go run ./cmd/server -dev -kubeconfig ~/.kube/config

.PHONY: test
test: ## Run tests
	go test -v -race ./...

.PHONY: lint
lint: ## Run linter
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format code
	go fmt ./...
	goimports -w .

.PHONY: tidy
tidy: ## Tidy dependencies
	go mod tidy

.PHONY: generate
generate: ## Generate code
	go generate ./...

##@ Console Integration

.PHONY: build-console
build-console: ## Build the console frontend
	cd ../butler-console && npm run build
	rm -rf internal/static/files/*
	cp -r ../butler-console/dist/* internal/static/files/

.PHONY: build-all
build-all: build-console build ## Build console and server

##@ Container

.PHONY: docker-build
docker-build: ## Build Docker image (requires butler-api adjacent)
	docker build --build-context butler-api=../butler-api -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push Docker image
	docker push $(IMG)

.PHONY: docker-build-push
docker-build-push: docker-build docker-push ## Build and push Docker image

##@ Deployment

.PHONY: deploy
deploy: ## Deploy to Kubernetes
	kubectl apply -f config/deploy/

.PHONY: undeploy
undeploy: ## Remove from Kubernetes
	kubectl delete -f config/deploy/

##@ Helpers

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
