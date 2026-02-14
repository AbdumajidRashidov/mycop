FROM rust:1.85-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/mycop /usr/local/bin/mycop
ENTRYPOINT ["mycop"]
CMD ["scan", "."]
