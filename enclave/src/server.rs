use crate::EnclaveArgs;
use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit, Nonce};
use alloy_primitives::Signature;
use ark_curve25519::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use clients::blob::EVMBlobOrder;
use clobs::{book::Book, order::Order, OrderState, OrderType, Side, SignatureType};
use parking_lot::Mutex;
use sha3::{Digest, Sha3_256};
use std::{sync::Arc, time::Instant};
use teeleaves_common::{Ciphertext, EnclaveRequest, EnclaveResponse, VsockStream};
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
    sk: Fr,
}

impl Server {
    pub fn new(args: EnclaveArgs) -> Self {
        let rng = &mut thread_rng();
        let sk = Fr::rand(rng);
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
            sk,
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
                let pk = EdwardsProjective::generator() * self.sk;
                let mut v = vec![];
                pk.serialize_compressed(&mut v).unwrap();

                stream.send(EnclaveResponse::PublicKey(v)).await.unwrap();
            }
            EnclaveRequest::Decrypt(ciphertext) => {
                match tokio::task::spawn_blocking(move || {
                    let Ciphertext {
                        ciphertext,
                        nonce,
                        sender_pk,
                    } = ciphertext;
                    // Take the guard to ensure only one execution can be running at a time.
                    let _guard = self.execution_guard.lock();

                    let sender_pk =
                        EdwardsProjective::deserialize_compressed(&sender_pk[..]).unwrap();
                    let dh = sender_pk * self.sk;
                    let mut v = vec![];
                    dh.serialize_compressed(&mut v).unwrap();

                    let key = Sha3_256::digest(&v);

                    let cipher = Aes256GcmSiv::new_from_slice(&key).unwrap();
                    let nonce = Nonce::from_slice(&nonce);
                    let message = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
                    let order =
                        serde_json::from_str::<EVMBlobOrder>(&String::from_utf8(message).unwrap())
                            .unwrap();

                    debug_print!("Matching start");
                    // TODO: remove this unwrap
                    let mut order = process_order(order);
                    let (order_state, taker_fill_amount, _) =
                        self.book.lock().add_limit_order(&mut order).unwrap();
                    // let (_, vk) = self.prover.setup(&program);
                    debug_print!("Matching complete");

                    // TODO: sign this
                    EnclaveResponse::Result {
                        order_state,
                        taker_fill_amount,
                    }
                })
                .await
                {
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
            EnclaveRequest::Execute { order } => {}
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
