#!make
SHELL := /bin/bash
.SHELLFLAGS := -ec

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

# build image in travis and push to dockerhub
