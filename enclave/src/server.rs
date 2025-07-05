use crate::EnclaveArgs;
use alloy_primitives::Signature;
use clients::blob::EVMBlobOrder;
use clobs::{book::Book, order::Order, OrderState, OrderType, Side, SignatureType};
use parking_lot::Mutex;
use std::{sync::Arc, time::Instant};
use teeleaves_common::{EnclaveRequest, EnclaveResponse, VsockStream};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream as VsockStreamRaw, VMADDR_CID_ANY};
/// Macro for printing debug messages.
///
/// Only prints if the `debug-mode` feature is enabled.
macro_rules! debug_print {
    ($($tt:tt)*) => {
        #[cfg(feature = "debug-mode")]
        println!($($tt)*);
    };
}

enum ConnectionState {
    Continue,
    Close,
}

pub struct Server {
    /// The arguments passed to the enclave at startup.
    args: EnclaveArgs,
    /// The signing key for the enclave.
    ///
    /// TODO: should this be changed?
    /// TODO: add the encryption key?
    /// Wrapped in a [`parking_lot::Mutex`] as the host may change it.
    // signing_key: Mutex<SigningKey>,
    /// Note: Only one execution can be running at a time, as it allocates a significant amount of memory.
    ///
    /// In the enclave, memory MUST be specified up front, so extra consideration is required to ensure we dont OOM.
    ///
    /// This is a [`parking_lot::Mutex`] to avoid priority inversion.
    execution_guard: Mutex<()>,
    /// The order book
    book: Arc<Mutex<Book>>,
}

impl Server {
    pub fn new(args: EnclaveArgs) -> Self {
        // let signing_key = SigningKey::random(&mut OsRng);

        //debug_print!(
        //    "Server started with public key: {:?}",
        //    signing_key.verifying_key()
        //);

        // initialize order book
        //
        Self {
            // signing_key: Mutex::new(signing_key),
            args,
            execution_guard: Mutex::new(()),
            book: Arc::new(Mutex::new(Book::new())),
        }
    }

    pub async fn run(self) {
        let this = Arc::new(self);

        let addr = VsockAddr::new(
            this.args.cid.unwrap_or(VMADDR_CID_ANY),
            teeleaves_common::ENCLAVE_PORT as u32,
        );

        let listener = VsockListener::bind(addr).expect("Failed to bind to vsock");

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");

            // Spawn a new (blocking) thread to handle the request.
            tokio::task::spawn({
                let this = this.clone();

                debug_print!("Spawning new connection");

                async move {
                    this.handle_connection(stream).await;
                }
            });
        }
    }

    /// Handles a connection from the host.
    ///
    /// NOTE: unwraps are used here on recv as this is only ran in a spawned thread.
    async fn handle_connection(self: Arc<Self>, stream: VsockStreamRaw) {
        let mut stream = VsockStream::<EnclaveRequest, EnclaveResponse>::new(stream);

        loop {
            let message = stream.recv().await.unwrap();

            debug_print!("Received message: {:?}", message.type_of());

            match self.clone().handle_message(message, &mut stream).await {
                ConnectionState::Continue => {}
                ConnectionState::Close => {
                    debug_print!("Connection closed.");
                    break;
                }
            }
        }
    }

    /// Handles a message from the host.
    ///
    /// Returns false if the connection should be closed.
    ///
    /// NOTE: unwraps are used here on sends as this is only ran in a spawned thread.
    async fn handle_message(
        self: Arc<Self>,
        message: EnclaveRequest,
        stream: &mut VsockStream<EnclaveRequest, EnclaveResponse>,
    ) -> ConnectionState {
        match message {
            #[cfg(feature = "debug-mode")]
            EnclaveRequest::Print(message) => {
                debug_print!("{}", message);

                let _ = stream.send(EnclaveResponse::Ack);
            }
            #[cfg(not(feature = "debug-mode"))]
            EnclaveRequest::Print(_) => {
                // Outside of debug mode the console cannot be accessed.

                stream.send(EnclaveResponse::Ack).await.unwrap();
            }
            // TODO: implement enclave public key
            EnclaveRequest::GetPublicKey => {
                todo!()
                //let public_key = self.get_public_key();

                //stream
                //    .send(EnclaveResponse::PublicKey(public_key))
                //    .await
                //    .unwrap();
            }
            EnclaveRequest::AttestSigningKey => {
                todo!();
                //match tokio::task::spawn_blocking(move || self.attest_signing_key()).await {
                //    Ok(response) => {
                //        stream.send(response).await.unwrap();
                //    }
                //    Err(e) => {
                //        stream
                //            .send(EnclaveResponse::Error(format!(
                //                "Join error when attesting signing key: {:?}",
                //                e
                //            )))
                //            .await
                //            .unwrap();
                //    }
                //}
            }
            EnclaveRequest::Execute { order } => {
                match tokio::task::spawn_blocking(move || self.execute(order)).await {
                    Ok(response) => {
                        stream.send(response).await.unwrap();
                    }
                    Err(e) => {
                        stream
                            .send(EnclaveResponse::Error(format!(
                                "Join error when executing program: {}",
                                e
                            )))
                            .await
                            .unwrap();
                    }
                }
            }
            EnclaveRequest::GetEncryptedSigningKey => {
                stream
                    .send(EnclaveResponse::Error("Not implemented".to_string()))
                    .await
                    .unwrap();
            }
            EnclaveRequest::SetSigningKey(_) => {
                stream
                    .send(EnclaveResponse::Error("Not implemented".to_string()))
                    .await
                    .unwrap();
            }
            EnclaveRequest::CloseSession => {
                return ConnectionState::Close;
            }
        }

        ConnectionState::Continue
    }

    /// Decrypts the signing key (using KMS) and sets it on the server.
    #[allow(unused)]
    fn set_signing_key(&self, ciphertext: Vec<u8>) {
        todo!()
    }

    /// Encrypts the servers signing key (using KMS) and sends it to the host.
    #[allow(unused)]
    fn get_signing_key(&self) -> Vec<u8> {
        todo!()
    }

    // TODO: implement this
    //fn get_public_key(&self) -> k256::EncodedPoint {
    //    self.signing_key
    //        .lock()
    //        .verifying_key()
    //        .to_encoded_point(false)
    //}

    /// Executes a program with the given stdin and program.
    ///
    /// Sends a signature over the public values (and the vkey) to the host.
    fn execute(&self, order: EVMBlobOrder) -> EnclaveResponse {
        // Take the guard to ensure only one execution can be running at a time.
        let _guard = self.execution_guard.lock();

        debug_print!("Matching start");
        // TODO: remove this unwrap
        let mut order = process_order(order);
        let (order_state, taker_fill_amount, _) =
            self.book.lock().add_limit_order(&mut order).unwrap();
        // let (_, vk) = self.prover.setup(&program);
        debug_print!("Matching complete");

        // TODO: sign this
        EnclaveResponse::SignedPublicValues {
            order_state,
            taker_fill_amount,
        }
    }
}

pub struct ProcessedEVMBlobOrder {
    evm_blob_order: EVMBlobOrder,
    timestamp: Instant,
}

impl Into<Order> for ProcessedEVMBlobOrder {
    fn into(self) -> Order {
        let evm_blob_order = self.evm_blob_order;
        let timestamp = self.timestamp;

        Order {
            order_type: OrderType::LimitOrder,
            salt: evm_blob_order.salt,
            maker: evm_blob_order.maker,
            signer: evm_blob_order.signer,
            taker: evm_blob_order.taker,
            token_id: evm_blob_order.tokenId,
            maker_amount: evm_blob_order.makerAmount,
            maker_remaining: evm_blob_order.makerAmount,
            taker_amount: evm_blob_order.takerAmount,
            taker_remaining: evm_blob_order.takerAmount,
            onchain_maker_remaining: evm_blob_order.makerAmount,
            onchain_taker_remaining: evm_blob_order.takerAmount,
            price: evm_blob_order.price,
            expiration: evm_blob_order.expiration,
            nonce: evm_blob_order.nonce,
            fee_rate_bps: evm_blob_order.feeRateBps,
            side: Side::try_from(evm_blob_order.side).unwrap(), // TODO: remove unwraps
            signature_type: SignatureType::try_from(evm_blob_order.signatureType).unwrap(),
            signature: Signature::try_from(evm_blob_order.signature.as_ref()).unwrap(),
            state: OrderState::New,
            timestamp,
        }
    }
}
pub fn process_order(order: EVMBlobOrder) -> Order {
    let processed_evm_blob_order = ProcessedEVMBlobOrder {
        evm_blob_order: order,
        timestamp: Instant::now(),
    };
    processed_evm_blob_order.into()
}
