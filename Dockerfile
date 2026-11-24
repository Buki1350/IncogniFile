FROM rust:1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY frontend ./frontend
COPY database ./database
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN mkdir /app/data && chown 10001:10001 /app/data && chmod 700 /app/data
COPY --from=builder /app/target/release/incognifile /usr/local/bin/incognifile
USER 10001:10001
ENV PORT=8080
ENV DATABASE_URL=sqlite:/app/data/incognifile.db
EXPOSE 8080
CMD ["incognifile"]
