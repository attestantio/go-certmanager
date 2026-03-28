CUSTOM_GCL := ./custom-gcl

# Always rebuild custom golangci-lint to avoid stale binary issues
# (e.g. Go toolchain upgrades that invalidate the cached binary).
.PHONY: $(CUSTOM_GCL)
$(CUSTOM_GCL): .custom-gcl.yml
	golangci-lint custom

.PHONY: lint
lint: $(CUSTOM_GCL)
	$(CUSTOM_GCL) run

.PHONY: lint-fix
lint-fix: $(CUSTOM_GCL)
	$(CUSTOM_GCL) run --fix

.PHONY: lint-clean
lint-clean:
	rm -f $(CUSTOM_GCL)

.PHONY: test
test:
	go test -count 1 ./...

.PHONY: build
build:
	go build ./...

.PHONY: check
check: build test lint
