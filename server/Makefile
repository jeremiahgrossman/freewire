.PHONY: build test vet docker-up docker-down docker-logs docker-rebuild clean

BINARY = freewire-server

# The server runs in Docker (see ../docker-compose.yml). These targets cover
# local build and test; use the docker-* targets to run it.

build:
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/freewire-server

vet:
	go vet ./...

test:
	go test -race -count=1 ./...

# ---- Docker (the supported way to run the server) ----

# Build and start. Config and keys persist in ./data, which is gitignored.
docker-up:
	cd .. && docker compose up --build -d

docker-down:
	cd .. && docker compose down

docker-logs:
	docker logs -f freewire-server

# Pick up source changes.
docker-rebuild:
	cd .. && docker compose up --build -d --force-recreate

clean:
	rm -f $(BINARY)
