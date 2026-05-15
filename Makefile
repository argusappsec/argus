.PHONY: build test lint tidy clean run-help

BIN := argus

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
