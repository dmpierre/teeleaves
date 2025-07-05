FROM amazonlinux:latest

WORKDIR /app

COPY target/release/teeleaves-enclave .

CMD ["/app/teeleaves-enclave"]
