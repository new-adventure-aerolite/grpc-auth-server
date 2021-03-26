.PHONY: build run docker test clean
build:
	go build -o auth-server main.go

run:
	@go run main.go

docker:
	docker build -t auth-server:latest .

test:
	go test -v ./...

clean:
	@rm -rf ./auth-server
