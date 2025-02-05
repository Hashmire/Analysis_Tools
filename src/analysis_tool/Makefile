SHELL:=/usr/bin/env bash
CURDIR:=$(shell pwd)
VENVDIR:=$(CURDIR)/venv
VERSION:=0.1.0
GIT_REPO:=$(shell git config --get remote.origin.url)
GIT_COMMIT:=$(shell git rev-parse HEAD)
VERSION_CONFIG_FILE:=version_file.yml
BUILD_INFO_SCRIPT:=build_info.py
OCI_IMAGE:=jackmckew/pyinstaller-windows@sha256:f3fef8b0307bcff8712f021fba697c0faec9fd9b90bb4c58db24cb85bd0e8f9a

.PHONY: help
# Run "make" or "make help" to get a list of user targets
# Adapted from https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
# To include a target in the help text, follow the following format:
#   <target(s)>: [dependencies] ## Comment
help: ## Show this help message
	@grep --no-filename -E '^[a-zA-Z_-]+:.*?##.*$$' $(MAKEFILE_LIST) | awk 'BEGIN { \
	 FS = ":.*?## "; \
	 printf "\033[1m%-30s\033[0m %s\n", "TARGET", "DESCRIPTION" \
	} \
	{ printf "\033[32m%-30s\033[0m %s\n", $$1, $$2 }'

.PHONY: generate-build-info
generate-build-info:
	@sed -i.bak "s|{{GIT_REPO_PLACEHOLDER}}|$(GIT_REPO)|g" $(BUILD_INFO_SCRIPT)
	@sed -i "s|{{GIT_COMMIT_PLACEHOLDER}}|$(GIT_COMMIT)|g" $(BUILD_INFO_SCRIPT)
	@sed -i "s|{{VERSION_PLACEHOLDER}}|$(VERSION)|g" $(BUILD_INFO_SCRIPT)

version_file.txt:
	@sed -i.bak "s|{{GIT_REPO_PLACEHOLDER}}|$(GIT_REPO)|g" $(VERSION_CONFIG_FILE)
	@sed -i "s|{{GIT_COMMIT_PLACEHOLDER}}|$(GIT_COMMIT)|g" $(VERSION_CONFIG_FILE)
	@sed -i "s|{{VERSION_PLACEHOLDER}}|$(VERSION)|g" $(VERSION_CONFIG_FILE)
	@create-version-file $(VERSION_CONFIG_FILE)

$(VENVDIR)/bin/python:
	@python3 -m venv $(VENVDIR)

.PHONY: generate-version
generate-version: version_file.txt generate-build-info ## Generate version info for Windows build

.PHONY: revert-version
revert-version: ## Revert the auto-generated version
	@git checkout HEAD -- $(VERSION_CONFIG_FILE)
	@git checkout HEAD -- $(BUILD_INFO_SCRIPT)

.PHONY: setup-local
setup-local: $(VENVDIR)/bin/python ## Set up local virtualenv, deps, tools automated versioning
	@$(VENVDIR)/bin/pip3 install -r requirements_dev.txt

.PHONY: setup
setup: ## Set up deps and tools automated versioning
	@pip3 install --user -r requirements_dev.txt

.PHONY: build-local
build-local: ## Build a local version of a Windows binary with docker
	docker run -it -v "$(CURDIR)":/src $(OCI_IMAGE)

clean: revert-version ## Remove build output
	@rm -rf $(VERSION_CONFIG_FILE).bak $(BUILD_INFO_SCRIPT).bak version_file.txt
	@docker run -it -v "$(CURDIR)":/src --entrypoint /bin/rm $(OCI_IMAGE) -rf build dist
	@rm -rf $(VENVDIR)
