FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o freewire-server ./cmd/freewire-server

FROM alpine:3.20

# iptables provides the masquerade rule below; without it forwarded packets
# keep their 10.0.0.0/24 source address and nothing can route replies back.
RUN apk add --no-cache iproute2 iptables

WORKDIR /app
COPY --from=builder /build/freewire-server .

EXPOSE 51820/udp
EXPOSE 8080/tcp
EXPOSE 443/tcp
EXPOSE 4500/udp

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
