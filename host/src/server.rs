use std::{path::Path, sync::Arc};

pub mod stream;

use clap::Parser;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

pub struct Server {
    pub execution_mutex: tokio::sync::Mutex<()>,
    pub cid: u32,
}

impl Server {
    /// Create a new server.
    ///
    /// This function will block and start the enclave and spawn a task to save attestations to S3.
    pub fn new(args: &ServerArgs) -> Arc<Self> {
        start_enclave(args);

        Arc::new(Self {
            execution_mutex: tokio::sync::Mutex::new(()),
            cid: args.enclave_cid,
        })
    }
}

#[derive(Parser)]
pub struct ServerArgs {
    /// The port to listen on.
    #[clap(short, long, default_value = "8080")]
    pub port: u16,

    /// The address to listen on.
    #[clap(short, long, default_value = "localhost")]
    pub address: String,

    /// The CID and port of the enclave to connect to.
    #[clap(long, default_value_t = teeleaves_common::ENCLAVE_CID)]
    pub enclave_cid: u32,

    /// The number of cores to use for the enclave.
    #[clap(long, default_value = "4")]
    pub enclave_cores: u32,

    /// The memory to use for the enclave.
    #[clap(short, long, default_value = "8000")]
    pub enclave_memory: u32,

    /// Run the enclave in debug mode.
    #[clap(short, long)]
    pub debug: bool,
}

/// Terminate the enclave.
///
/// This function will block until the enclave is terminated or force the program to exit with an error code.
///
/// This function utilizes the `enclave.sh` script to terminate the enclave.
pub fn terminate_enclaves() {
    // Run the enclave.sh script.
    let mut command = std::process::Command::new("sh");
    command.current_dir(Path::new(MANIFEST_DIR).parent().unwrap());

    // Pipe the output to the parent process.
    command.stderr(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());

    command.arg("scripts/enclave.sh");
    command.arg("terminate");

    let output = command.output().expect("Failed to run enclave.sh");
    if !output.status.success() {
        tracing::error!("Failed to terminate enclaves");
        std::process::exit(1);
    }
}

/// Start the enclave.
///
/// This function will block until the enclave is started or force the program to exit with an error code.
///
/// This function utilizes the `enclave.sh` script to start the enclave.
pub fn start_enclave(args: &ServerArgs) {
    // Run the enclave.sh script.
    let mut command = std::process::Command::new("sh");
    command.current_dir(Path::new(MANIFEST_DIR).parent().unwrap());
    command.arg("scripts/enclave.sh");
    command.arg("run");
    if args.debug {
        command.arg("--debug");
    }

    // Set the environment variables.
    command.env("ENCLAVE_CID", args.enclave_cid.to_string());
    command.env("ENCLAVE_CPU_COUNT", args.enclave_cores.to_string());
    command.env("ENCLAVE_MEMORY", args.enclave_memory.to_string());

    // Pipe the output to the parent process.
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    let output = command.output().expect("Failed to run enclave.sh");
    if !output.status.success() {
        tracing::error!("Failed to start enclave");
        std::process::exit(1);
    }

    tracing::info!(
        "Enclave started on CID: {} with {} cores and {}MB of memory",
        args.enclave_cid,
        args.enclave_cores,
        args.enclave_memory
    );
}
