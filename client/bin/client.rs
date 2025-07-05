use std::time::Instant;

use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit, Nonce};
use alloy_primitives::{Address, Bytes};
use ark_crypto_primitives::signature::{
    schnorr::{PublicKey, Schnorr, Signature},
    SignatureScheme,
};
use ark_curve25519::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{thread_rng, Rng};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use clients::blob::EVMBlobOrder;
use clobs::Side;
use reqwest::Client;
use sha3::{Digest, Sha3_256};
use teeleaves_common::SignedResult;

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

    let dk = Fr::rand(rng);
    let ek = EdwardsProjective::generator() * dk;

    let enclave_ek = client
        .get("http://localhost:8080/ek")
        .send()
        .await
        .expect("Failed to get public key")
        .bytes()
        .await
        .expect("Failed to read response bytes");

    let enclave_ek = EdwardsProjective::deserialize_compressed(&enclave_ek[..]).unwrap();

    let enclave_vk = client
        .get("http://localhost:8080/vk")
        .send()
        .await
        .expect("Failed to get public key")
        .bytes()
        .await
        .expect("Failed to read response bytes");

    let enclave_vk = EdwardsProjective::deserialize_compressed(&enclave_vk[..]).unwrap();

    let dh = enclave_ek * dk;
    let mut v = vec![];
    dh.serialize_compressed(&mut v).unwrap();

    let n_orders = 500;
    let ciphertexts = (0..n_orders)
        .map(|_| {
            let order = generate_blob_order(50, 1);
            let order = serde_json::to_string(&order).unwrap().into_bytes();

            let key = Sha3_256::digest(&v);

            let cipher = Aes256GcmSiv::new_from_slice(&key).unwrap();
            let nonce = rng.gen::<[u8; 12]>();
            let nonce = Nonce::from_slice(&nonce);
            let ciphertext = cipher.encrypt(nonce, order.as_ref()).unwrap();
            teeleaves_common::Ciphertext {
                ciphertext: ciphertext.to_vec(),
                nonce: nonce.to_vec(),
                sender_ek: {
                    let mut v = vec![];
                    ek.serialize_compressed(&mut v).unwrap();
                    v
                },
            }
        })
        .collect::<Vec<_>>();

    let mut results = vec![];

    let start = Instant::now();
    for ciphertext in &ciphertexts {
        let res = client
            .post("http://localhost:8080/execute")
            .json(&ciphertext)
            .send()
            .await;
        results.push(res);
    }

    let duration = start.elapsed().as_secs_f64();
    println!(
        "[CLIENT] Server + enclave processed {n_orders} orders in {:.2} ({:.2} order/s)",
        duration,
        n_orders as f64 / duration
    );

    let mut pp = Schnorr::<EdwardsProjective, Sha3_256>::setup(rng).unwrap();
    pp.generator = EdwardsAffine::generator();
    pp.salt = [0u8; 32];

    for res in results {
        let SignedResult {
            order_state,
            taker_fill_amount,
            sig,
        } = res.unwrap().json().await.unwrap();
        assert!(Schnorr::verify(
            &pp,
            &enclave_vk.into_affine(),
            &[&[order_state as u8][..], &taker_fill_amount.to_le_bytes()].concat(),
            {
                let sig = <[Fr; 2]>::deserialize_compressed(&sig[..]).unwrap();
                &Signature {
                    prover_response: sig[0],
                    verifier_challenge: sig[1],
                }
            },
        )
        .unwrap());
    }
    let attestation = client
        .get("http://localhost:8080/attestation")
        .send()
        .await
        .expect("Failed to get attestation")
        .bytes()
        .await
        .expect("Failed to read response bytes");

    let res_attestation =
        attestation_doc_validation::validate_and_parse_attestation_doc(&attestation);
    println!(
        "[CLIENT] Enclave attestation verified as {}",
        res_attestation.is_ok()
    );
}
