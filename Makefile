CUSTOM_GCL := ./custom-gcl

# Build custom golangci-lint if needed
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
