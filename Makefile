#!make
SHELL := /bin/bash
.SHELLFLAGS := -ec
IMAGE := pete911/vault-auth-kubernetes
VERSION ?= dev

VERSION ?= dev

helm-test:
	$(info *** [helm test] ***)
	helm lint charts/vault-auth-kubernetes
	helm template charts/vault-auth-kubernetes | kubectl apply --dry-run=client -f -
.PHONY:helm-test

test: helm-test
	$(info *** [go test] ***)
	go clean -testcache && go test -cover ./...
.PHONY:test

build: test
	$(info *** [go build] ***)
	go build
.PHONY:build

integration-test:
	$(info *** [integration tests] ***)
	./integration/vault
	./integration/k8s
.PHONY:integration-test

e2e-test:
	$(info *** [end to end tests] ***)
	./e2e/e2e
.PHONY:e2e-test

image:
	docker build -t ${IMAGE}:${VERSION} .
	docker tag ${IMAGE}:${VERSION} ${IMAGE}:latest
.PHONY:image

push-image:
	docker push ${IMAGE}:${VERSION}
	docker push ${IMAGE}:latest
.PHONY:push-image
