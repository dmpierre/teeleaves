use std::time::Instant;

use alloy_primitives::{Address, Bytes};
use clients::blob::EVMBlobOrder;
use clobs::Side;
use rand::Rng;
use reqwest::Client;

pub fn get_order_amounts(side: Side, size: u128, price: u8) -> (u128, u128) {
    match side {
        Side::Bid => return (size * price as u128, size),
        Side::Ask => return (size, size * price as u128),
    };
}

pub fn generate_blob_order(mid_price: u8, token_id: u128) -> EVMBlobOrder {
    let mut rng = rand::rng();
    let side = if rng.random_bool(0.5) {
        Side::Ask
    } else {
        Side::Bid
    };
    let price_variation = rng.random_range(0..10);
    let price = if side == Side::Bid {
        mid_price - price_variation
    } else {
        mid_price + price_variation
    };
    let size = rng.random_range(1..10000);
    let (maker_amount, taker_amount) = get_order_amounts(side, size, price);
    let salt = rng.random_range(0..u128::MAX);
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
    let start = Instant::now();
    let order = generate_blob_order(50, 1);
    let res = client
        .post("http://localhost:8080/execute")
        .json(&order)
        .send()
        .await;
    println!("{:?}", res);
}
