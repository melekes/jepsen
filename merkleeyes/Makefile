#!/usr/bin/make -f

VERSION := $(shell awk -F\" '/Version =/ { print $$2; exit }' < app.go)
LD_FLAGS = -X github.com/melekes/jepsen/merkleeyes/version=$(VERSION)
BUILD_FLAGS = -mod=readonly -ldflags "$(LD_FLAGS)"

release:
	@echo "==> building merkleeyes v$(VERSION)"
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o build/merkleeyes cmd/merkleeyes/main.go
	tar -zcvf "build/merkleeyes_$(VERSION).tar.gz" build/merkleeyes
	@rm build/merkleeyes

build:
	go build $(BUILD_FLAGS) -o build/merkleeyes cmd/merkleeyes/main.go
.PHONY: build


.PHONY: release
