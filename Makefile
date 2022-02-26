BINARY_NAME=gRPCnmap

build:
	GOARCH=amd64 GOOS=darwin go build -o ${BINARY_NAME}-darwin
	GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME}-linux
	GOARCH=amd64 GOOS=windows go build -o ${BINARY_NAME}-windows
	go build $(BINARY_NAME)

run:
	./${BINARY_NAME}

test:
	go test -v

lint_install:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.44.2
	golangci-lint --version
lint:
	golangci-lint run


build_and_run: build run

clean:
	go clean
	rm ${BINARY_NAME}-darwin
	rm ${BINARY_NAME}-linux
	rm ${BINARY_NAME}-windows
	rm $(BINARY_NAME)
