# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w" -o /jwt-proxy .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /jwt-proxy /jwt-proxy
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/jwt-proxy"]
