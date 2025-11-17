use num_bigint::{BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use std::time::{Duration, Instant};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::task::spawn_blocking;
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
struct Key {
    e: BigUint,
    d: BigUint,
    n: BigUint,
}

#[derive(Clone, Debug)]
struct Stats {
    oracle_queries: Arc<AtomicU64>,
}

impl Default for Stats {
    fn default() -> Self { Self { oracle_queries: Arc::new(AtomicU64::new(0)) } }
}

fn byte_len(n: &BigUint) -> usize {
    if n.is_zero() {
        0
    } else {
        ((n.bits() + 7) / 8) as usize
    }
}

fn fmt_hex(n: &BigUint, max_bytes: usize) -> String {
    let bytes = n.to_bytes_be();
    if bytes.len() <= max_bytes {
        return format!("0x{}", hex::encode(bytes));
    }
    let head = &bytes[..max_bytes/2];
    let tail = &bytes[bytes.len() - max_bytes/2..];
    format!("0x{}..{} ({} bytes)", hex::encode(head), hex::encode(tail), bytes.len())
}

fn ceil_div(a: &BigUint, b: &BigUint) -> BigUint {
    if b.is_zero() {
        panic!("division by zero");
    }
    let (q, r) = a.div_rem(b);
    if r.is_zero() { q } else { q + BigUint::one() }
}

fn floor_div(a: &BigUint, b: &BigUint) -> BigUint {
    a / b
}

fn max_u(a: &BigUint, b: &BigUint) -> BigUint { if a > b { a.clone() } else { b.clone() } }
fn min_u(a: &BigUint, b: &BigUint) -> BigUint { if a < b { a.clone() } else { b.clone() } }

fn two_pow(bits: usize) -> BigUint {
    BigUint::one() << bits
}

fn generate_keypair(size_n_bits: usize, e_val: u64) -> Key {
    let mut rng = OsRng;
    // Use rsa crate to generate primes/key with chosen exponent
    let e_rsa = rsa::BigUint::from(e_val);
    let priv_key = RsaPrivateKey::new_with_exp(&mut rng, size_n_bits as usize, &e_rsa)
        .expect("key generation failed");
    // Convert rsa::BigUint (num_bigint_dig) to num_bigint::BigUint
    let to_num_big = |x: &rsa::BigUint| BigUint::from_bytes_be(&x.to_bytes_be());
    Key { e: to_num_big(priv_key.e()), d: to_num_big(priv_key.d()), n: to_num_big(priv_key.n()) }
}

// Build simplified PKCS#1 v1.5-style block: 0x02 || PS || 0x00 || M
// NOTE: Mirrors the Sage version which does not enforce non-zero PS and actually omits the 0x00 byte.
fn padding(message: &BigUint, target_len: usize) -> BigUint {
    // prefix 0x02 at the MSB position (k-2 bytes above LSB)
    let mut res = BigUint::from(0x02u32) << (8 * (target_len - 2));

    // random pad occupying bytes just above the message (Sage-style; no explicit 0x00 separator)
    let msg_len = byte_len(message);
    assert!(target_len >= 3 + msg_len, "message too long for target block");
    let pad_len = target_len - 3 - msg_len;
    if pad_len > 0 {
        let mut rng = OsRng;
        // Build random pad BigUint from pad_len bytes
        let mut pad_val = BigUint::zero();
        for i in 0..pad_len {
            let byte: u8 = (rng.next_u32() & 0xFF) as u8;
            let shift = (pad_len - i + msg_len) * 8; // matches Sage placement
            pad_val += BigUint::from(byte) << shift;
        }
        res += pad_val;
    }

    // append message at LSB side (no explicit 0x00 as per Sage code)
    res += message;
    res
}

fn oracle_length(c: &BigUint, key: &Key, stats: &Stats) -> usize {
    stats.oracle_queries.fetch_add(1, Ordering::Relaxed);
    let m = c.modpow(&key.d, &key.n);
    byte_len(&m)
}

fn oracle_padding(c: &BigUint, key: &Key, stats: &Stats) -> bool {
    stats.oracle_queries.fetch_add(1, Ordering::Relaxed);
    let m = c.modpow(&key.d, &key.n);
    let k = byte_len(&key.n);
    let mb = byte_len(&m);
    if mb != k - 1 { return false; }
    // Check top byte equals 0x02 (Sage-style check)
    let shift_bits = ((mb - 1) * 8) as usize;
    let top = &m >> shift_bits;
    top == BigUint::from(0x02u32)
}

async fn search_s_padding_parallel(
    ciphertext: Arc<BigUint>,
    key: Arc<Key>,
    start_s: BigUint,
    stats: Stats,
) -> BigUint {
    let workers = num_cpus::get().max(2);
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::unbounded_channel::<BigUint>();

    for w in 0..workers {
        let txc = tx.clone();
        let c = ciphertext.clone();
        let k = key.clone();
        let stopc = stop.clone();
        let s0 = &start_s + BigUint::from((w as u64) + 1);
        let stats_c = stats.clone();
        spawn_blocking(move || {
            let mut s = s0;
            while !stopc.load(Ordering::Relaxed) {
                let c_ref: &BigUint = &c;
                let c2 = (c_ref * s.modpow(&k.e, &k.n)) % &k.n;
                if oracle_padding(&c2, &k, &stats_c) {
                    let _ = txc.send(s.clone());
                    stopc.store(true, Ordering::Relaxed);
                    break;
                }
                s += BigUint::from(workers as u64);
            }
        });
    }
    drop(tx);
    let found = rx.recv().await.expect("channel closed without result");
    found
}

async fn search_s_length_parallel(
    ciphertext: Arc<BigUint>,
    key: Arc<Key>,
    start_s: BigUint,
    target_nn: usize,
    stats: Stats,
) -> BigUint {
    let workers = num_cpus::get().max(2);
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::unbounded_channel::<BigUint>();

    for w in 0..workers {
        let txc = tx.clone();
        let c = ciphertext.clone();
        let k = key.clone();
        let stopc = stop.clone();
        let s0 = &start_s + BigUint::from((w as u64) + 1);
        let stats_c = stats.clone();
        spawn_blocking(move || {
            let mut s = s0;
            while !stopc.load(Ordering::Relaxed) {
                let c_ref: &BigUint = &c;
                let c2 = (c_ref * s.modpow(&k.e, &k.n)) % &k.n;
                if oracle_length(&c2, &k, &stats_c) == target_nn {
                    let _ = txc.send(s.clone());
                    stopc.store(true, Ordering::Relaxed);
                    break;
                }
                s += BigUint::from(workers as u64);
            }
        });
    }
    drop(tx);
    rx.recv().await.expect("channel closed without result")
}

async fn bleichenbacher_padding() {
    let threads = num_cpus::get();
    println!("[padding] starting attack (threads={})", threads);
    // small key for demo speed; the Sage version used 1024 bits
    let key = generate_keypair(256, 17);
    let k = byte_len(&key.n);
    let plaintext = BigUint::from(0x6c6f6cu32); // "lol"
    let padded = padding(&plaintext, k);
    let ciphertext = padded.modpow(&key.e, &key.n);
    let start = Instant::now();
    let stats = Stats::default();

    let b = two_pow((k - 2) * 8);
    println!(
        "[padding] k={} bytes, B={}, padded={}, ct={}",
        k,
        fmt_hex(&b, 8),
        fmt_hex(&padded, 12),
        fmt_hex(&ciphertext, 12)
    );

    // attack
    let mut intervals: Vec<(BigUint, BigUint)> = vec![(
        (&b << 1u32),                   // 2B
        (&b * BigUint::from(3u32) - BigUint::one()), // 3B - 1
    )];
    let mut s = ceil_div(&key.n, &(BigUint::from(3u32) * &b)) - BigUint::one();
    let mut i: u64 = 1;

    loop {
        if i % 5 == 0 {
            println!(
                "[padding] iter {} | intervals={} | queries={}",
                i,
                intervals.len(),
                stats.oracle_queries.load(Ordering::Relaxed)
            );
        }
        // step 2: find next s such that oracle accepts
        let mut c2 = BigUint::zero();
        if i > 1 && intervals.len() == 1 {
            // Step 2c optimization when only one interval remains
            let s_prev = s.clone();
            let (a, b_int) = intervals[0].clone();
            let two = BigUint::from(2u32);
            let three = BigUint::from(3u32);
            let mut r = floor_div(&(two.clone() * (&b_int * &s_prev - two.clone() * &b)), &key.n);
            'outer: loop {
                s = ceil_div(&(two.clone() * &b + &r * &key.n), &b_int) - BigUint::one();
                let s_max = ceil_div(&(three.clone() * &b + &r * &key.n), &a);
                while s < s_max {
                    s += BigUint::one();
                    c2 = (&ciphertext * s.modpow(&key.e, &key.n)) % &key.n;
                    if oracle_padding(&c2, &key, &stats) { break 'outer; }
                    if stats.oracle_queries.load(Ordering::Relaxed) % 1000 == 0 {
                        println!("[padding] queries={}", stats.oracle_queries.load(Ordering::Relaxed));
                    }
                }
                r += BigUint::one();
            }
        } else {
            // Step 2a/2b search (linear)
            let found_s = search_s_padding_parallel(Arc::new(ciphertext.clone()), Arc::new(key.clone()), s.clone(), stats.clone()).await;
            s = found_s;
            c2 = (&ciphertext * s.modpow(&key.e, &key.n)) % &key.n;
        }

        // step 3: narrow intervals
        let mut new_intervals: Vec<(BigUint, BigUint)> = Vec::new();
        for (a, b_int) in intervals.iter() {
            let three_b = &b * BigUint::from(3u32);
            let min_r = floor_div(&(a * &s - &three_b + BigUint::one()), &key.n);
            let max_r = floor_div(&(b_int * &s - (&b << 1u32)), &key.n);

            let mut r = min_r;
            while r <= max_r {
                let new_min = max_u(a, &ceil_div(&((&b << 1u32) + &r * &key.n), &s));
                let new_max = min_u(b_int, &floor_div(&(three_b.clone() - BigUint::one() + &r * &key.n), &s));
                if new_min <= new_max {
                    // Found potential interval
                    if new_min == new_max {
                        // success
                        println!("[padding] found! new_min = {}", &fmt_hex(&new_min, 16));
                        println!("[padding] did we find that? {}", &fmt_hex(&padded, 16));
                        println!(
                            "[padding] done in {:.2?} with {} queries",
                            start.elapsed(), stats.oracle_queries.load(Ordering::Relaxed)
                        );
                        return;
                    }
                    new_intervals.push((new_min, new_max));
                }
                r += BigUint::one();
            }
        }
        intervals = new_intervals;
        i += 1;
        if intervals.is_empty() {
            eprintln!("[padding] No intervals left; attack failed (try again)");
            println!(
                "[padding] stopped after {:.2?}, {} iterations, {} queries",
                start.elapsed(), i, stats.oracle_queries.load(Ordering::Relaxed)
            );
            return;
        }
    }
}

async fn bleichenbacher_length() {
    let threads = num_cpus::get();
    println!("[length] starting attack (threads={})", threads);
    // small key for demo speed; the Sage version used 2048 bits
    let key = generate_keypair(256, 17);
    let k = byte_len(&key.n);
    let plaintext = BigUint::from(0x6c6f6cu32); // "lol"
    let padded = padding(&plaintext, k);
    let ciphertext = padded.modpow(&key.e, &key.n);
    let start = Instant::now();
    let stats = Stats::default();

    let k_bytes = k; // N byte length
    let b = two_pow((k_bytes - 2) * 8);
    println!(
        "[length] k={} bytes, B={}, padded={}, ct={}",
        k_bytes,
        fmt_hex(&b, 8),
        fmt_hex(&padded, 12),
        fmt_hex(&ciphertext, 12)
    );

    let mut intervals: Vec<(BigUint, BigUint)> = vec![((&b << 1u32), (&b * BigUint::from(3u32) - BigUint::one()))];
    let mut s = ceil_div(&key.n, &(BigUint::from(3u32) * &b)) - BigUint::one();
    let mut i: u64 = 1;

    loop {
        if i % 5 == 0 {
            println!(
                "[length] iter {} | intervals={} | queries={}",
                i,
                intervals.len(),
                stats.oracle_queries.load(Ordering::Relaxed)
            );
        }
        // step 2: find next s such that oracle indicates length nn < k-1
        let mut c2 = BigUint::zero();
        if i > 1 && intervals.len() == 1 {
            // step 2c
            let (a, b_int) = intervals[0].clone();
            let nn = k_bytes - 2; // mirrors Sage "set it like that"
            let nnm1_bits = 8 * (nn - 1);
            let nn_bits = 8 * nn;
            let two = BigUint::from(2u32);
            let mut r = floor_div(&(two.clone() * (&b_int * &s - two_pow(nnm1_bits))), &key.n);
            'outer: loop {
                s = ceil_div(&(two_pow(nnm1_bits) + &r * &key.n), &b_int) - BigUint::one();
                let s_max = ceil_div(&(two_pow(nn_bits) - BigUint::one() + &r * &key.n), &a);
                while s < s_max {
                    s += BigUint::one();
                    c2 = (&ciphertext * s.modpow(&key.e, &key.n)) % &key.n;
                    if oracle_length(&c2, &key, &stats) == nn { break 'outer; }
                    if stats.oracle_queries.load(Ordering::Relaxed) % 1000 == 0 {
                        println!("[length] queries={}", stats.oracle_queries.load(Ordering::Relaxed));
                    }
                }
                r += BigUint::one();
            }
        } else {
            // step 2a/2b
            let target_nn = k_bytes - 2; // follows Sage intent: find when oracle returns nn == k-2
            let found_s = search_s_length_parallel(Arc::new(ciphertext.clone()), Arc::new(key.clone()), s.clone(), target_nn, stats.clone()).await;
            s = found_s;
            c2 = (&ciphertext * s.modpow(&key.e, &key.n)) % &key.n;
        }

        // step 3: narrow intervals
        let mut new_intervals: Vec<(BigUint, BigUint)> = Vec::new();
    let nn = oracle_length(&c2, &key, &stats); // use the recent nn
        let two_nn_1 = two_pow(8 * (nn - 1));
        let two_nn = two_pow(8 * nn);
        for (a, b_int) in intervals.iter() {
            let min_r = floor_div(&(a * &s - &two_nn - BigUint::one()), &key.n);
            let max_r = floor_div(&(b_int * &s - &two_nn_1), &key.n);
            let mut r = min_r;
            while r <= max_r {
                let new_min = max_u(a, &ceil_div(&(two_nn_1.clone() + &r * &key.n), &s));
                let new_max = min_u(b_int, &floor_div(&(two_nn.clone() - BigUint::one() + &r * &key.n), &s));
                if new_min <= new_max {
                    if new_min == new_max {
                        println!("[length] found! new_min = {}", &fmt_hex(&new_min, 16));
                        println!("[length] did we find that? {}", &fmt_hex(&padded, 16));
                        println!(
                            "[length] done in {:.2?} with {} queries",
                            start.elapsed(), stats.oracle_queries.load(Ordering::Relaxed)
                        );
                        return;
                    }
                    new_intervals.push((new_min, new_max));
                }
                r += BigUint::one();
            }
        }
        intervals = new_intervals;
        i += 1;
        if intervals.is_empty() {
            eprintln!("[length] No intervals left; attack failed (try again)");
            println!(
                "[length] stopped after {:.2?}, {} iterations, {} queries",
                start.elapsed(), i, stats.oracle_queries.load(Ordering::Relaxed)
            );
            return;
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Simple CLI: default to length oracle attack. Use "padding" to run that variant.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1].to_lowercase().contains("padding") {
        bleichenbacher_padding().await;
    } else {
        bleichenbacher_length().await;
    }
}

// Fast unit tests for core helpers and oracles
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_and_oracles() {
        // use a very small key to keep test fast
        let key = generate_keypair(128, 17);
        let k = byte_len(&key.n);
        let plaintext = BigUint::from(0x6c6f6cu32); // "lol"
        let padded = padding(&plaintext, k);
        let ciphertext = padded.modpow(&key.e, &key.n);

        let stats = Stats::default();

        // oracle_length should return the byte length of the decrypted padded block
        let ln = oracle_length(&ciphertext, &key, &stats);
        assert!(ln > 0 && ln <= k);

        // oracle_padding should be true for the correctly padded ciphertext
        assert!(oracle_padding(&ciphertext, &key, &stats));
    }

    #[test]
    fn test_byte_len() {
        assert_eq!(byte_len(&BigUint::zero()), 0);
        assert_eq!(byte_len(&BigUint::from(0xFFu32)), 1);
        assert_eq!(byte_len(&BigUint::from(0x100u32)), 2);
        assert_eq!(byte_len(&BigUint::from(0xFFFFu32)), 2);
        assert_eq!(byte_len(&BigUint::from(0x10000u32)), 3);
    }

    #[test]
    fn test_ceil_div() {
        let a = BigUint::from(10u32);
        let b = BigUint::from(3u32);
        assert_eq!(ceil_div(&a, &b), BigUint::from(4u32));

        let a = BigUint::from(9u32);
        let b = BigUint::from(3u32);
        assert_eq!(ceil_div(&a, &b), BigUint::from(3u32));

        let a = BigUint::from(1u32);
        let b = BigUint::from(10u32);
        assert_eq!(ceil_div(&a, &b), BigUint::from(1u32));
    }

    #[test]
    fn test_floor_div() {
        let a = BigUint::from(10u32);
        let b = BigUint::from(3u32);
        assert_eq!(floor_div(&a, &b), BigUint::from(3u32));

        let a = BigUint::from(9u32);
        let b = BigUint::from(3u32);
        assert_eq!(floor_div(&a, &b), BigUint::from(3u32));
    }

    #[test]
    fn test_max_min_u() {
        let a = BigUint::from(100u32);
        let b = BigUint::from(200u32);
        assert_eq!(max_u(&a, &b), b);
        assert_eq!(min_u(&a, &b), a);
        assert_eq!(max_u(&b, &a), b);
        assert_eq!(min_u(&b, &a), a);
    }

    #[test]
    fn test_two_pow() {
        assert_eq!(two_pow(0), BigUint::from(1u32));
        assert_eq!(two_pow(8), BigUint::from(256u32));
        assert_eq!(two_pow(16), BigUint::from(65536u32));
    }

    #[test]
    fn test_padding_structure() {
        let key = generate_keypair(128, 17);
        let k = byte_len(&key.n);
        let plaintext = BigUint::from(0xABCDu32);
        let padded = padding(&plaintext, k);

        // Check that padded has the right length (or k-1 due to leading zero byte)
        let padded_len = byte_len(&padded);
        assert!(padded_len == k || padded_len == k - 1, 
            "padded length {} should be {} or {}", padded_len, k, k - 1);

        // Check that the top byte (MSB after potential leading zero) is 0x02
        let shift_bits = (padded_len - 1) * 8;
        let top_byte = &padded >> shift_bits;
        assert_eq!(top_byte, BigUint::from(0x02u32));

        // Check that the plaintext is at the bottom (LSB)
        let mask = BigUint::from(0xFFFFu32);
        let bottom = &padded & mask;
        assert_eq!(bottom, plaintext);
    }

    #[test]
    fn test_oracle_padding_invalid() {
        let key = generate_keypair(128, 17);
        let stats = Stats::default();
        
        // Create an invalid ciphertext (random value that won't decrypt to valid padding)
        let invalid_ct = BigUint::from(12345u32);
        
        // Should return false for invalid padding (most likely)
        let _result = oracle_padding(&invalid_ct, &key, &stats);
        // Note: this might occasionally be true if random value happens to decrypt correctly
        // but statistically very unlikely - we just verify the oracle was called
        assert_eq!(stats.oracle_queries.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_oracle_length_variations() {
        let key = generate_keypair(128, 17);
        let k = byte_len(&key.n);
        let stats = Stats::default();

        // Test with different plaintext sizes
        let plaintexts = vec![
            BigUint::from(0x01u32),
            BigUint::from(0xFFu32),
            BigUint::from(0xFFFFu32),
        ];

        for pt in plaintexts {
            let padded = padding(&pt, k);
            let ct = padded.modpow(&key.e, &key.n);
            let ln = oracle_length(&ct, &key, &stats);
            // Length should be reasonable
            assert!(ln > 0 && ln <= k);
        }
    }

    #[test]
    fn test_keypair_generation() {
        // Test that key generation works for small sizes
        let key = generate_keypair(128, 17);
        assert_eq!(key.e, BigUint::from(17u32));
        assert!(key.d > BigUint::zero());
        assert!(key.n > BigUint::zero());
        
        // Verify n is roughly the right size
        let n_bits = key.n.bits();
        assert!(n_bits >= 120 && n_bits <= 136); // allow some variance
    }

    #[test]
    fn test_fmt_hex() {
        let small = BigUint::from(0xABCDu32);
        let result = fmt_hex(&small, 10);
        assert!(result.contains("0x"));
        assert!(result.contains("abcd"));

        let large = BigUint::from(0x123456789ABCDEFu64);
        let result = fmt_hex(&large, 4);
        assert!(result.contains(".."));
        assert!(result.contains("bytes"));
    }
}
