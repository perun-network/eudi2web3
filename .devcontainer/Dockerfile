FROM rust:1.90-trixie AS builder
WORKDIR /app

RUN useradd -m -s /bin/bash dev

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake npm \
    && rm -rf /var/lib/apt/lists/*

# Install npm dependencies
RUN npm install -g @aiken-lang/aikup snarkjs && \
    HOME=/home/dev aikup install && \
    chown -R dev:dev /home/dev/.aiken

# Install circom binary
RUN curl -L -o circom https://github.com/iden3/circom/releases/download/v2.2.3/circom-linux-amd64 && \
    chmod +x circom && \
    mv circom /usr/local/bin/

COPY rust-toolchain.toml rust-toolchain.toml
RUN rustup show active-toolchain && \
    rustup component add rustfmt clippy

USER dev
ENV PATH=/home/dev/.aiken/bin:$PATH

CMD ["sleep", "infinity"]

