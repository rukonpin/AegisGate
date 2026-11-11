# Стадия 1: Сборка
FROM rust:slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
COPY src ./src
RUN cargo build --release

# Стадия 2: Финал
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/local/bin
COPY --from=builder /app/target/release/aegisgate .
EXPOSE 8080
CMD ["./aegisgate"]