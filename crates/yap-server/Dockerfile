# Build from the repo root:  docker build -f crates/yap-server/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p yap-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home yap
COPY --from=build /src/target/release/yap-server /usr/local/bin/yap-server
USER yap
EXPOSE 8080
ENTRYPOINT ["yap-server"]
