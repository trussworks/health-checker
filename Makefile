# goreleaser removes the `v` prefix when building and this does too
VERSION = 0.0.1

ifdef CIRCLECI
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LDFLAGS=-linkmode external -extldflags -static
	endif
endif

.PHONY: help
help:  ## Print the help documentation
	@grep -E '^[/a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

bin/health-checker: ## Build health-checker
	go build -ldflags "$(LDFLAGS) -X main.version=${VERSION}" -o bin/health-checker .

.PHONY: clean
clean: ## Clean all generated files
	rm -rf ./bin
	rm -rf ./dist

default: help
