<p align="center">
  <img alt="image" src="https://github.com/user-attachments/assets/cf2072b0-9e35-4591-94e7-a239ec060cd4" width="40%" />
</p>

# TEELeaves

TEELeaves lets you run a prediction market orderbook within a Trusted Execution Environment (TEE). It runs with:

1. An open source repo
2. Verifiable execution - Schnorr signatures over ed25519 + nitro enclave attestation verification
3. Encrypted orders - using ECIES (ed25519 + aes256).

## Usage

Upload/clone repo on a beefy aws machine with nitro enclaves enabled. We recommend an ec2 instance with 32Gb RAM and 16 cores, e.g. `c5.4xlarge`. This code has been tested with an aws nitro enclave equipped with 8Gb of RAM and 4 cores. 

Before using, ensure that the host has been setup correctly with `scripts/install-host.sh`. Then:

1. Start the server with `cargo run --bin teeleaves-server`
2. Run the client `cargo run --bin teeleaves-client`, this will call the server which will route order execution to the enclave.

## Acknowledgements

- [rust-clob](https://github.com/dmpierre/rust-clob): a rust based, binary limit orderbook (blob) implementation. We used the orderbook implementation, some of the `client` code for benchmarks and `server` code for routing user's orders.
- [sp1-tee](https://github.com/succinctlabs/sp1-tee/tree/main): `common`, `host` and `enclave` code. We adapted `sp1-tee` code to work with `rust-clob`. We got rid of most of the prover, networking and auth logic. We re-use most of the scripts and docker setup.
