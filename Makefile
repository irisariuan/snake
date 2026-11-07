VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/irisariuan/snake/internal/engine.Version=$(VERSION)
BUILD   := CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all arm64 armv7 web web-deps test integration ui-dev clean

all: arm64

# The web UI (web/: Astro + Tailwind) is built to a static page in
# internal/webui/build/site, which the binary embeds. Needs Node.js 22.
# A plain `go build` without it still works, with a placeholder page.
WEB_OUT  := internal/webui/build/site/index.html
WEB_SRC  := $(shell find web/src -type f 2>/dev/null) web/astro.config.mjs web/package.json
WEB_DEPS := web/node_modules/.package-lock.json

web: $(WEB_OUT)

$(WEB_OUT): $(WEB_SRC) $(WEB_DEPS)
	cd web && ASTRO_TELEMETRY_DISABLED=1 npm run build

# npm ci only when the lockfile changed.
$(WEB_DEPS): web/package-lock.json
	cd web && npm ci --no-audit --no-fund

web-deps: $(WEB_DEPS)

# RT-AX86U/AX88U/GT-AX6000/GT-BE98 and other 64-bit HND models
arm64: web
	GOARCH=arm64 $(BUILD) -o dist/snake-arm64 ./cmd/snake

# 32-bit ARM userspace (RT-AC68U, RT-AX58U, ...)
armv7: web
	GOARCH=arm GOARM=7 $(BUILD) -o dist/snake-armv7 ./cmd/snake

test: web
	cd web && npm test
	go vet ./...
	SNAKE_REQUIRE_UI=1 go test ./...

# Applies real rules and runs a real OpenVPN client in a throwaway network
# namespace (root, needs ipset + iproute2; openvpn + openssl for the client).
integration:
	SNAKE_INTEGRATION=1 unshare -n go test -count=1 -tags integration ./internal/engine -run Integration -v
	SNAKE_INTEGRATION=1 unshare -n go test -count=1 -tags integration ./internal/openvpn -run Integration -v  # needs openvpn, openssl

# Serves the UI with a fake engine on http://127.0.0.1:18444 (token: testtoken).
ui-dev: web
	go test -tags uiharness -run UIHarness -timeout 0 -v ./internal/api

clean:
	rm -rf dist internal/webui/build/site
