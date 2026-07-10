FROM rust:1.90-trixie AS builder
WORKDIR /app

# Install dependencies for build-time
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy over the files needed to generate witness computation (changes less often than the server code).
COPY zkey zkey
COPY makefile .
COPY scripts/install_w2c2.sh scripts/run_w2c2.sh scripts/
COPY templates/w2c2_circuit_specific.c templates/
RUN mkdir circuit && \
    make \
        zkey/lib/libbls12-381_tiny.a \
        zkey/lib/libbls12-381_tiny_nocrypto.a \
        zkey/lib/libbls12-381_small.a \
        zkey/lib/libbls12-381_small_nocrypto.a \
        zkey/lib/libbn254_small.a \
        zkey/lib/libbn254_small_nocrypto.a

# Build the server
COPY Cargo.toml Cargo.lock build.rs makefile .
COPY crates crates
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    mkdir out && \
    cp target/release/main out/eudi2web3


# Copy everything into a small container
FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nodejs \
        npm \
    && npm install -g snarkjs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/out/* /usr/local/bin/
COPY static /static

ENV BIND="0.0.0.0:8080"
EXPOSE 8080
CMD ["eudi2web3"]

