.PHONY: setup build run clean

BINARY  = freewire-server
CONFIG  = freewire-server.json

# Fetch dependencies and tidy go.mod / go.sum.
setup:
	go get go.uber.org/zap@latest
	go get golang.org/x/crypto@latest
	go get golang.zx2c4.com/wireguard@latest
	go mod tidy

# Build a local macOS binary (arm64 or amd64 based on host).
build: setup
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/freewire-server

# Run the server.
# Requires root for utun interface creation and route configuration.
# Enable IP forwarding first so tunnel clients can reach the internet:
#   sudo sysctl -w net.inet.ip.forwarding=1
run: build
	sudo ./$(BINARY) $(CONFIG)

clean:
	rm -f $(BINARY) $(CONFIG)
