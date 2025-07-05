FROM rust:1.88.0 AS builder
WORKDIR app
COPY . ./
RUN cargo build --release --bin teeleaves-enclave


# Copy the binary from the build stage
FROM rust:1.84.1
COPY --from=builder /app/target/release/teeleaves-enclave /usr/local/bin/teeleaves-enclave

CMD ["/usr/local/bin/teeleaves-enclave"]
