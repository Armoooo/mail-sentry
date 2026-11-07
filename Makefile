.PHONY: build test check demo

build:
	go build -o bin/mailsentry ./cmd/mailsentry

test:
	go test ./...

check:
	go vet ./...
	go test -race ./...

demo:
	go run ./cmd/mailsentry scan samples/suspicious.eml samples/legitimate.eml
