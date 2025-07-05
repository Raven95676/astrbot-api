FROM golang:1.24-bookworm AS builder

WORKDIR /app

COPY . .

RUN go mod download

RUN GOOS=linux go build -a -o main .

FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 10010

CMD ["./main"]
