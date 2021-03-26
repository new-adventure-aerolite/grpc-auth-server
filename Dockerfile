FROM golang:1.16.2 AS builder
WORKDIR /go/src
COPY . .
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go mod tidy && go mod vendor
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-server

FROM alpine:latest
COPY --from=builder /go/src/auth-server /usr/bin/auth-server
ENTRYPOINT ["/usr/bin/auth-server"]
