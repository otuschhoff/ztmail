.PHONY: build test

build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/ztmail-linux-amd64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o dist/ztmail-windows-amd64.exe .

test:
	go test -race ./...
	go vet ./...
