#!/usr/bin/make -f

VERSION := $(awk -F\" 'Version =/ { print $2; exit }' < version/version.go)
LD_FLAGS = -X github.com/melekes/jepsen/merkleeyes/version=$(VERSION)
BUILD_FLAGS = -mod=readonly -ldflags "$(LD_FLAGS)"
REPO = "https://github.com/melekes/jepsen"

release:
	@echo "==> building merkleeyes $(VERSION)"
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o build/merkleeyes cmd/merkleeyes/main.go
	tar -zcvf "build/merkleeyes_$(VERSION).tar.gz" build/merkleeyes
	@echo "==> updating merkleeyes-url in ../tendermint/src/jepsen/tendermint/cli.clj"
	PREV_MERKLEEYES_URL = $(awk -F\" '/merkleeyes-url/ { print $4; exit }' ../tendermint/src/jepsen/tendermint/cli.clj)
	sed -i "s+$(PREV_MERKLEEYES_URL)+$(REPO)/releases/download/v$(VERSION)/merkleeyes.tar.gz+g" ../tendermint/src/jepsen/tendermint/cli.clj)

.PHONY: release
