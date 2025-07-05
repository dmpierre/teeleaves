use clients::blob::EVMBlobOrder;
use clobs::OrderState;
use serde::{Deserialize, Serialize};

mod communication;
pub use communication::{CommunicationError, VsockStream};

/// A VSOCK address is defined as the tuple of (CID, port).
///
/// So its OK to hardcode the port here.
pub const ENCLAVE_PORT: u16 = 5005;

/// The CID of the enclave.
pub const ENCLAVE_CID: u32 = 42;

#[derive(Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub sender_pk: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveRequest {
    /// Print from the enclave to the debug console.
    Print(String),
    /// Request the enclave's public key.
    GetPublicKey,
    Decrypt(Ciphertext),
    /// An execution request, sent from the host to the enclave.
    Execute {
        order: String,
    },
    /// Close the session, the enclave will drop the connection after this request.
    CloseSession,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnclaveResponse {
    PublicKey(Vec<u8>),
    Result {
        order_state: OrderState,
        taker_fill_amount: u128,
    },
    /// The receiver of this variant should print this message to stdout.
    Error(String),
    /// Indicate to the host that the enclave has received the message.
    Ack,
}

impl EnclaveRequest {
    pub fn type_of(&self) -> &'static str {
        match self {
            EnclaveRequest::CloseSession => "CloseSession",
            EnclaveRequest::GetPublicKey => "GetPublicKey",
            EnclaveRequest::Print(_) => "Print",
            EnclaveRequest::Decrypt(..) => "decrypt",
            EnclaveRequest::Execute { .. } => "Execute",
        }
    }
}

impl EnclaveResponse {
    pub fn type_of(&self) -> &'static str {
        match self {
            EnclaveResponse::PublicKey(_) => "PublicKey",
            EnclaveResponse::Result { .. } => "Result",
            EnclaveResponse::Error(_) => "Error",
            EnclaveResponse::Ack => "Ack",
        }
    }
}
