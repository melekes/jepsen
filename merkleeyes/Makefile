#!/usr/bin/make -f

VERSION := $(shell git describe --always)
LD_FLAGS = -X github.com/melekes/jepsen/merkleeyes/version=$(VERSION)
BUILD_FLAGS = -mod=readonly -ldflags "$(LD_FLAGS)"

build:
	go build $(BUILD_FLAGS) -o build/merkleeyes cmd/merkleeyes/main.go
.PHONY: build
