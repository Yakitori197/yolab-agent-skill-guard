# Convenience targets. Windows users without make: use scripts/verify.ps1.

BIN := skillguard
PKG := ./cmd/skillguard

.PHONY: build test race cover fmt vet verify demo action-test clean

build:
	go build -trimpath -o $(BIN) $(PKG)

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -coverprofile=cover.out -coverpkg=./internal/... ./...
	go run ./tools/covercheck -profile cover.out -min 90

fmt:
	gofmt -l cmd internal tools

vet:
	go vet ./...

verify:
	sh scripts/verify.sh

action-test:
	sh scripts/test-action.sh

# Regenerate the committed demo reports from the risky example.
demo: build
	./$(BIN) scan examples/risky-skill --format html --output docs/examples/risky-report.html --fail-on none --quiet
	./$(BIN) scan examples/risky-skill --format sarif --output docs/examples/risky-report.sarif --fail-on none --quiet
	./$(BIN) scan examples/risky-skill --format json --output docs/examples/risky-report.json --fail-on none --quiet

clean:
	rm -f $(BIN) $(BIN).exe cover.out
