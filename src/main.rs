mod oracle;
mod bleichenbacher;

use crate::bleichenbacher::bleichenbacher_attack_async;
use crate::oracle::{encrypt_pkcs1_v15, Oracle};
use rsa::BigUint;
use rand::thread_rng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::traits::PublicKeyParts;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Demo harness: generate a small RSA key, encrypt a message, and recover it via Bleichenbacher.
    let mut rng = thread_rng();

    // Keep key size moderate so the demo completes quickly.
    let bits = 128; // Very small key for a super fast demo.
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate RSA key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let n: BigUint = pub_key.n().clone();
    let e: BigUint = pub_key.e().clone();

    // Message to encrypt/decrypt via the attack
    let message = b"hi".to_vec();

    // Encrypt using PKCS#1 v1.5 formatting into an integer, then RSA encrypt.
    let c: BigUint = encrypt_pkcs1_v15(&n, &e, &message, &mut rng).expect("encryption failed");

    // Build the padding oracle using the private key
    let oracle = Arc::new(Oracle::new(priv_key));

    let recovered = bleichenbacher_attack_async(&n, &e, &c, oracle.clone())
        .await
        .expect("attack failed to recover plaintext");

    println!("Original:  {}", String::from_utf8_lossy(&message));
    println!("Recovered: {}", String::from_utf8_lossy(&recovered));
    println!("Oracle queries: {}", oracle.query_count());

    assert_eq!(message, recovered, "Recovered plaintext does not match");
    println!("Success: plaintext recovered via Bleichenbacher's CCA!");
}
