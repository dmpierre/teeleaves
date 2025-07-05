use std::time::Instant;

use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit, Nonce};
use alloy_primitives::{Address, Bytes};
use ark_curve25519::{EdwardsProjective, Fr};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{thread_rng, Rng};
use clients::blob::EVMBlobOrder;
use clobs::Side;
use reqwest::Client;
use sha3::{Digest, Sha3_256};

pub fn get_order_amounts(side: Side, size: u128, price: u8) -> (u128, u128) {
    match side {
        Side::Bid => return (size * price as u128, size),
        Side::Ask => return (size, size * price as u128),
    };
}

pub fn generate_blob_order(mid_price: u8, token_id: u128) -> EVMBlobOrder {
    let rng = &mut thread_rng();
    let side = if rng.gen_bool(0.5) {
        Side::Ask
    } else {
        Side::Bid
    };
    let price_variation = rng.gen_range(0..10);
    let price = if side == Side::Bid {
        mid_price - price_variation
    } else {
        mid_price + price_variation
    };
    let size = rng.gen_range(1..10000);
    let (maker_amount, taker_amount) = get_order_amounts(side, size, price);
    let salt = rng.gen_range(0..u128::MAX);
    let maker = Address::default();
    let taker = Address::default();
    let signer = Address::default();
    let signature = Bytes::from([0u8; 65]);

    EVMBlobOrder {
        price,
        salt,
        maker,
        signer,
        taker,
        tokenId: token_id,
        makerAmount: maker_amount,
        takerAmount: taker_amount,
        expiration: 0, // not important for now
        nonce: 0,
        feeRateBps: 0,
        side: side.into(),
        signatureType: 0, // 0 = EOA
        signature,
    }
}

/// A simple Virtio socket server that uses Hyper to response to requests.
#[tokio::main]
async fn main() {
    let client = Client::new();

    let rng = &mut thread_rng();

    let sk = Fr::rand(rng);
    let pk = EdwardsProjective::generator() * sk;

    let enclave_pk = client
        .get("http://localhost:8080/pk")
        .send()
        .await
        .expect("Failed to get public key")
        .bytes()
        .await
        .expect("Failed to read response bytes");

    let enclave_pk = EdwardsProjective::deserialize_compressed(&enclave_pk[..]).unwrap();

    let dh = enclave_pk * sk;
    let mut v = vec![];
    dh.serialize_compressed(&mut v).unwrap();

    let order = generate_blob_order(50, 1);
    let order = serde_json::to_string(&order).unwrap().into_bytes();

    let key = Sha3_256::digest(&v);

    let cipher = Aes256GcmSiv::new_from_slice(&key).unwrap();
    let nonce = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce, order.as_ref()).unwrap();

    let start = Instant::now();
    let res = client
        .post("http://localhost:8080/execute")
        .json(&teeleaves_common::Ciphertext {
            ciphertext: ciphertext.to_vec(),
            nonce: nonce.to_vec(),
            sender_pk: {
                let mut v = vec![];
                pk.serialize_compressed(&mut v).unwrap();
                v
            },
        })
        .send()
        .await;
    println!("{:?}", res);
}
