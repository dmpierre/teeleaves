use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use clap::Parser;
use clients::blob::EVMBlobOrder;
use std::sync::Arc;
use teeleaves_common::{EnclaveRequest, EnclaveResponse};
use teeleaves_host::server::{self, Server};
use teeleaves_host::{server::ServerArgs, HostStream};
use tokio::net::TcpListener;

/// A simple Virtio socket server that uses Hyper to response to requests.
#[tokio::main]
async fn main() {
    let args = ServerArgs::parse();

    server::terminate_enclaves();

    let server = Server::new(&args);
    let app = Router::new()
        .route("/execute", post(execute).layer(DefaultBodyLimit::disable()))
        .with_state(server);

    let listener = TcpListener::bind((args.address.clone(), args.port))
        .await
        .expect("Failed to bind to address");

    tracing::info!("Listening on {}:{}", args.address, args.port);

    // Run the server indefinitely or wait for a Ctrl-C.
    tokio::select! {
        e = axum::serve(listener, app.into_make_service()) => {
            if let Err(e) = e {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received, terminating enclaves");

            server::terminate_enclaves();
            std::process::exit(0);
        }
    }
}

/// Execute a program on the enclave.
///
/// In order to avoid OOM in the enclave, we run only one program at a time.
async fn execute(
    State(server): State<Arc<Server>>,
    payload: Result<Json<EVMBlobOrder>, JsonRejection>,
) -> Result<StatusCode, ServerError> {
    let evm_order = match payload {
        Ok(evm_order) => evm_order,
        Err(_) => return Ok(StatusCode::UNPROCESSABLE_ENTITY),
    };

    let ret = execute_inner(server.clone(), evm_order.0)
        .await
        .map(|res| match res {
            EnclaveResponse::PublicKey(encoded_point) => todo!(),
            EnclaveResponse::EncryptedSigningKey(items) => todo!(),
            EnclaveResponse::SigningKeyAttestation(items) => todo!(),
            EnclaveResponse::SignedPublicValues {
                // TODO: log that?
                order_state,
                taker_fill_amount,
            } => return StatusCode::OK,
            EnclaveResponse::Error(_) => todo!(),
            EnclaveResponse::Ack => todo!(),
        });

    ret
}

async fn execute_inner(
    server: Arc<Server>,
    request: EVMBlobOrder,
) -> Result<EnclaveResponse, ServerError> {
    tracing::info!("Got execution request");

    let _guard = server.execution_mutex.lock().await;

    tracing::info!("Acquired execution gurad");

    // Open a connection to the enclave.
    let mut stream = HostStream::new(server.cid, teeleaves_common::ENCLAVE_PORT)
        .await
        .map_err(|e| {
            tracing::error!(alert = true, "Failed to connect to enclave: {}", e);

            ServerError::FailedToConnectToEnclave
        })?;

    tracing::debug!("Successfully connected to enclave");

    // Setup the request.
    let request = EnclaveRequest::Execute {
        order: serde_json::to_string(&request).unwrap(),
    };

    // Send the request to the enclave.
    let execution_start = std::time::Instant::now();
    stream.send(request).await.map_err(|e| {
        tracing::error!(alert = true, "Failed to send request to enclave: {}", e);

        ServerError::FailedToSendRequestToEnclave
    })?;

    tracing::debug!("Successfully sent request to enclave");

    // TODO: Parse response from enclave
    // Receive the response from the enclave.
    let response = stream.recv().await.map_err(|e| {
        tracing::error!(
            alert = true,
            "Failed to receive response from enclave: {:?}",
            e
        );

        ServerError::FailedToReceiveResponseFromEnclave
    })?;

    let execution_duration = execution_start.elapsed();
    tracing::info!(
        "Execution duration: {:?} seconds",
        execution_duration.as_secs()
    );

    tracing::debug!("Successfully received response from enclave");

    Ok(response)
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum ServerError {
    #[error("Failed to connect to enclave")]
    FailedToConnectToEnclave,

    #[error("Failed to send request to enclave")]
    FailedToSendRequestToEnclave,

    #[error("Failed to receive response from enclave")]
    FailedToReceiveResponseFromEnclave,

    #[error("Unexpected response from enclave")]
    UnexpectedResponseFromEnclave,

    #[error("Failed to convert public key to address")]
    FailedToConvertPublicKeyToAddress,

    #[error("Enclave error: {0}")]
    EnclaveError(String),

    #[error("Stdin is too large, found {0} bytes")]
    StdinTooLarge(usize),

    #[error("Program is too large, found {0} bytes")]
    ProgramTooLarge(usize),

    #[error("Failed to deserialize request, {0}")]
    FailedToDeserializeRequest(bincode::Error),

    #[error("Failed to deserialize enclave measurement: {0}")]
    FailedToParseEnclaveMeasurement(#[from] serde_json::Error),

    #[error("Io Error when fetching enclave measurement: {0}")]
    IoError(#[from] std::io::Error),

    //#[error("Failed to get attestations: {0}")]
    //FailedToGetAttestations(#[from] crate::attestations::GetAttestationError),
    #[cfg(feature = "production")]
    #[error("Failed to authenticate request")]
    FailedToAuthenticateRequest,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let err = match self {
            ServerError::FailedToConnectToEnclave => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to connect to enclave".to_string(),
            ),
            ServerError::FailedToSendRequestToEnclave => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to send request to enclave".to_string(),
            ),
            ServerError::FailedToReceiveResponseFromEnclave => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to receive response from enclave".to_string(),
            ),
            ServerError::UnexpectedResponseFromEnclave => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected response from enclave".to_string(),
            ),
            ServerError::FailedToConvertPublicKeyToAddress => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to convert public key to address, this is a bug.".to_string(),
            ),
            ServerError::EnclaveError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            ServerError::StdinTooLarge(size) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Stdin is too large, found {} bytes", size),
            ),
            ServerError::ProgramTooLarge(size) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Program is too large, found {} bytes", size),
            ),
            ServerError::FailedToDeserializeRequest(e) => (
                StatusCode::BAD_REQUEST,
                format!("Failed to deserialize request, {}", e),
            ),
            ServerError::FailedToParseEnclaveMeasurement(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse enclave measurement, {}", e),
            ),
            ServerError::IoError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Io error when fetching enclave measurement, {}", e),
            ),
            //ServerError::FailedToGetAttestations(e) => (
            //    StatusCode::INTERNAL_SERVER_ERROR,
            //    format!("Failed to get attestations, {}", e),
            //),
            #[cfg(feature = "production")]
            ServerError::FailedToAuthenticateRequest => (
                StatusCode::UNAUTHORIZED,
                "Failed to authenticate request".to_string(),
            ),
        };

        err.into_response()
    }
}
