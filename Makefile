.PHONY: proto build build-fips test clean

## proto: regenerate Go bindings from proto/gateon/v1/*.proto using buf
proto:
	buf generate

## build: build the gateon binary
build:
	go build -v -o dist/gateon ./cmd/gateon

## build-fips: build the gateon binary with FIPS 140-2 compliance (BoringCrypto)
build-fips:
	GOEXPERIMENT=boringcrypto go build -v -o dist/gateon-fips ./cmd/gateon

## test: run all tests
test:
	go test -v ./...

## clean: clean build artifacts
clean:
	go clean
	rm -rf dist/
