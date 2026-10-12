.PHONY: build test lint tidy clean run-help image-gate docs docs-check

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

# Regenerate the user guide's scanner catalog (docs/guide/scanners/) from the
# Tool Catalog. Run it after changing or adding a catalog Entry and commit the
# result: `make test` fails while the committed pages drift. See ADR 0027.
docs:
	go run ./internal/catalogdocs/gen

# Fail if regenerating the scanner catalog changes anything in the tree — the
# same drift check `make test` runs, as CI's explicit gate.
docs-check: docs
	@git diff --exit-code -- docs/guide/scanners
	@test -z "$$(git status --porcelain -- docs/guide/scanners)" || \
		{ echo "docs/guide/scanners has untracked or uncommitted pages; commit the output of make docs"; exit 1; }

# Build the batteries-included image and run the image-contract gate against
# it — the same check CI runs on every PR. Drop a Manifest scanner from the
# Dockerfile and this fails locally instead of on GitHub. See ADR 0013 and
# ADR 0027.
image-gate:
	docker build -t $(IMAGE) .
	docker run --rm $(IMAGE) doctor --binaries
