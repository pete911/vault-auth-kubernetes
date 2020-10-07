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

test: helm-test
	$(info *** [go test] ***)
	go clean -testcache && go test -cover ./...

build: test
	$(info *** [go build] ***)
	go build -mod vendor

integration-test:
	$(info *** [integration tests] ***)
	./integration/vault
	./integration/k8s

e2e-test:
	$(info *** [end to end tests] ***)
	./e2e/e2e

image:
	docker build -t ${IMAGE}:${VERSION} .
	docker tag ${IMAGE}:${VERSION} ${IMAGE}:latest

push-image:
	docker push ${IMAGE}:${VERSION}
	docker push ${IMAGE}:latest
