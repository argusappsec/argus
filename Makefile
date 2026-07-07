.PHONY: build test lint tidy clean run-help image-gate

BIN := argus
IMAGE := argus:ci

build:
	go build -o $(BIN) .

test:
	go test -race ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN) coverage.txt

run-help: build
	./$(BIN) --help

# Build the batteries-included image and run the image-contract gate against
# it — the same check CI runs on every PR. Drop a scanner from the Dockerfile
# and this fails locally instead of on GitHub. See ADR 0013.
image-gate:
	docker build -t $(IMAGE) .
	docker run --rm $(IMAGE) doctor --binaries
