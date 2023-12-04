IMAGE_TAG                   := $(or ${GITHUB_TAG_NAME}, latest)
REGISTRY                    := ghcr.io/metal-stack
IMAGE_PREFIX                := $(REGISTRY)
REPO_ROOT                   := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
HACK_DIR                    := $(REPO_ROOT)/hack
HOSTNAME                    := $(shell hostname)
LD_FLAGS                    := "-w -X github.com/metal-stack/gardener-extension-audit/pkg/version.Version=$(IMAGE_TAG)"
VERIFY                      := true
LEADER_ELECTION             := false
IGNORE_OPERATION_ANNOTATION := false
WEBHOOK_CONFIG_URL          := localhost

GOLANGCI_LINT_VERSION := v1.54.2
GO_VERSION := 1.21

ifeq ($(CI),true)
  DOCKER_TTY_ARG=""
else
  DOCKER_TTY_ARG=t
endif

export GO111MODULE := on

TOOLS_DIR := hack/tools
-include vendor/github.com/gardener/gardener/hack/tools.mk

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: build
build:
	go build -ldflags $(LD_FLAGS) -tags netgo -o bin/gardener-extension-audit ./cmd/gardener-extension-audit

.PHONY: install
install: revendor $(HELM)
	@LD_FLAGS="-w -X github.com/gardener/$(EXTENSION_PREFIX)-$(NAME)/pkg/version.Version=$(VERSION)" \
	$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/install.sh ./...

.PHONY: docker-image
docker-image:
	@docker build --no-cache \
		--build-arg VERIFY=$(VERIFY) \
		--tag $(IMAGE_PREFIX)/gardener-extension-audit:$(IMAGE_TAG) \
		--file Dockerfile --memory 6g .

.PHONY: docker-push
docker-push:
	@docker push $(IMAGE_PREFIX)/gardener-extension-audit:$(IMAGE_TAG)

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor
	@GO111MODULE=on go mod tidy
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/*
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/.ci/*
	@$(REPO_ROOT)/hack/update-github-templates.sh

.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/clean.sh ./cmd/... ./pkg/...

.PHONY: check-generate
check-generate:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-generate.sh $(REPO_ROOT)

.PHONY: generate
generate: $(HELM)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/generate.sh ./charts/... ./cmd/... ./pkg/...

.PHONY: generate-in-docker
generate-in-docker: revendor $(HELM) $(YQ)
	# comment back in after first release:
	# echo $(shell git describe --abbrev=0 --tags) > VERSION
	docker run --rm -i$(DOCKER_TTY_ARG) -v $(PWD):/go/src/github.com/metal-stack/gardener-extension-audit golang:$(GO_VERSION) \
		sh -c "cd /go/src/github.com/metal-stack/gardener-extension-audit \
				&& make generate \
				# && make install generate \
				&& chown -R $(shell id -u):$(shell id -g) ."

.PHONY: test
test:
	go test -v ./...

.PHONY: push-to-gardener-local
push-to-gardener-local:
	CGO_ENABLED=1 go build \
		-ldflags "-extldflags '-static -s -w'" \
		-tags 'osusergo netgo static_build' \
		-o bin/gardener-extension-audit \
		./cmd/gardener-extension-audit
	docker build -f Dockerfile.dev -t ghcr.io/metal-stack/gardener-extension-audit:latest .
	kind --name gardener-local load docker-image ghcr.io/metal-stack/gardener-extension-audit:latest
