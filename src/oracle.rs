use rsa::BigUint;
use rand::Rng;
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Oracle {
    n: BigUint,
    d: BigUint,
    queries: AtomicU64,
}

impl Oracle {
    pub fn new(priv_key: RsaPrivateKey) -> Self {
        Self { n: priv_key.n().clone(), d: priv_key.d().clone(), queries: AtomicU64::new(0) }
    }

    pub fn modulus_bytes(&self) -> usize {
        // Byte length of modulus
        (self.n.bits() as usize + 7) / 8
    }

    pub fn n(&self) -> &BigUint { &self.n }

    pub fn d(&self) -> &BigUint { &self.d }

    pub fn query_count(&self) -> u64 { self.queries.load(Ordering::Relaxed) }

    // PKCS#1 v1.5 padding oracle: returns true if c^d mod n decodes to 0x00 0x02 || PS (>=8 nonzero) || 0x00 || M
    pub fn is_pkcs1_conforming(&self, c: &BigUint) -> bool {
        let q = self.queries.fetch_add(1, Ordering::Relaxed) + 1;
        if q % 1000 == 0 {
            eprintln!("oracle queries: {}", q);
        }
        let n = &self.n;
        if c >= n { return false; }
        let m = c.modpow(&self.d, n);
        let k = self.modulus_bytes();
        let m_bytes = to_k_bytes(&m, k);
        if m_bytes.len() != k { return false; }
        // Check leading bytes
        if m_bytes.get(0).copied() != Some(0x00) || m_bytes.get(1).copied() != Some(0x02) {
            return false;
        }
        // Next should be at least 8 non-zero bytes until a 0x00 separator
        // Find separator index
        // PS starts at index 2
        let mut idx = 2;
        // Consume non-zero padding bytes
        while idx < m_bytes.len() {
            if m_bytes[idx] == 0 { break; }
            idx += 1;
        }
        // There must be a zero separator and at least 8 padding bytes
        if idx >= m_bytes.len() { return false; } // no separator
        let ps_len = idx - 2;
        if ps_len < 8 { return false; }
        true
    }
}

pub fn encrypt_pkcs1_v15<R: Rng + ?Sized>(
    n: &BigUint,
    e: &BigUint,
    msg: &[u8],
    rng: &mut R,
) -> Option<BigUint> {
    let k = (n.bits() as usize + 7) / 8;
    if msg.len() > k.saturating_sub(11) { return None; }
    let ps_len = k - 3 - msg.len();

    let mut ps = vec![0u8; ps_len];
    // Fill PS with non-zero random bytes
    for b in &mut ps {
        let mut x = 0u8;
        while x == 0 { x = rng.gen(); }
        *b = x;
    }

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(msg);

    let m = BigUint::from_bytes_be(&em);
    let c = m.modpow(e, n);
    Some(c)
}

pub fn to_k_bytes(x: &BigUint, k: usize) -> Vec<u8> {
    let mut v = x.to_bytes_be();
    if v.len() < k {
        let mut p = vec![0u8; k - v.len()];
        p.extend_from_slice(&v);
        v = p;
    }
    v
}
