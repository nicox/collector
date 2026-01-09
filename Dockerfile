# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.19-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o snmpcollector ./cmd/snmpcollector

# Runtime stage
FROM alpine:3.20

RUN adduser -D -g '' snmpcollector

WORKDIR /app
COPY --from=builder /app/snmpcollector /usr/local/bin/snmpcollector
COPY config/snmp-collector.example.yaml /app/config/snmp-collector.yaml

USER snmpcollector

ENTRYPOINT ["snmpcollector"]
CMD ["-config", "/app/config/snmp-collector.yaml"]
