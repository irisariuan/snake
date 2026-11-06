VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/irisariuan/snake/internal/engine.Version=$(VERSION)
BUILD   := CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all arm64 armv7 test integration ui-dev clean

all: arm64

# RT-AX86U/AX88U/GT-AX6000/GT-BE98 and other 64-bit HND models
arm64:
	GOARCH=arm64 $(BUILD) -o dist/snake-arm64 ./cmd/snake

# 32-bit ARM userspace (RT-AC68U, RT-AX58U, ...)
armv7:
	GOARCH=arm GOARM=7 $(BUILD) -o dist/snake-armv7 ./cmd/snake

test:
	go vet ./...
	go test ./...

# Applies real rules in a throwaway network namespace (root, needs ipset + iproute2).
integration:
	SNAKE_INTEGRATION=1 unshare -n go test -count=1 -tags integration ./internal/engine -run Integration -v

# Serves the UI with a fake engine on http://127.0.0.1:18444 (token: testtoken).
ui-dev:
	go test -tags uiharness -run UIHarness -timeout 0 -v ./internal/api

clean:
	rm -rf dist
