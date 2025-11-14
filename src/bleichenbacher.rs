use rsa::BigUint;
use std::sync::Arc;
use tokio::task;
use futures::future::join_all;

use crate::oracle::{to_k_bytes, Oracle};

// Implements Bleichenbacher's 1998 adaptive chosen-ciphertext attack on RSA PKCS#1 v1.5
// Reference: https://link.springer.com/chapter/10.1007/BFb0054868
//https://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5
pub async fn bleichenbacher_attack_async(
    n: &BigUint,
    e: &BigUint,
    c: &BigUint,
    oracle: Arc<Oracle>,
) -> Option<Vec<u8>> {
    let k = (n.bits() as usize + 7) / 8;
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);

    // B = 2^{8(k-2)}
    let B = BigUint::from(1u32) << (8 * (k - 2));
    let two_B = &two * &B;
    let three_B = &(BigUint::from(3u32)) * &B; // 3B

    // Step 1: Blinding - we skip blinding in this POC, c0 = c
    let c0 = c.clone();

    // Step 2: Initialize set of intervals M_0 = {[2B, 3B - 1]}
    let mut intervals: Vec<(BigUint, BigUint)> = vec![(two_B.clone(), &three_B - &one)];

    // Step 2.a: find the first s such that oracle returns valid
    let mut i: u64 = 1;
    let mut s_i: BigUint;

    // For i = 1, search s from ceil(n / 3B) upwards
    let mut s = div_ceil(n, &three_B);
    if s == BigUint::from(0u32) { s = one.clone(); }
    // Quick check for s = 1 (original ciphertext already conforming)
    if oracle.is_pkcs1_conforming(&c0) {
        s_i = BigUint::from(1u32);
        eprintln!("[Step 1] Found initial s=1");
    } else {
        // Parallelized batch search for first conforming s
        eprintln!("[Step 1] Searching for first conforming s from {}", s);
        s_i = find_next_s_linear_parallel_async(n, e, &c0, oracle.clone(), &s, 4096).await?;
        eprintln!("[Step 1] Found first conforming s={}", s_i);
    }

    // Step 3: iterate
    loop {
        // Instrumentation: interval stats
        if i % 5 == 0 { // log every 5 iterations
            let widths: Vec<BigUint> = intervals.iter().map(|(a,b)| b - a).collect();
            let max_width = widths.iter().max().cloned().unwrap_or_else(|| BigUint::from(0u32));
            eprintln!("[iter {}] intervals={} max_width_bits={} queries={} s_i_bits={}", i, intervals.len(), max_width.bits(), oracle.query_count(), s_i.bits());
        }
        // Step 3.b: Narrow the set of solutions
        let mut new_intervals: Vec<(BigUint, BigUint)> = Vec::new();
        for (a, b) in intervals.iter() {
            // r in [ceil((2B*s - 3B + 1)/n), floor((3B*s - 2B)/n)]
            let two_b_s = &two_B * &s_i;
            let three_b_minus_one = &three_B - &one;
            let r_min = if two_b_s > three_b_minus_one {
                div_ceil(&(two_b_s - three_b_minus_one), n)
            } else {
                BigUint::from(0u32)
            };
            let r_max = (&(&(&three_B * &s_i) - &two_B)) / n;
            let mut r = r_min;
            while r <= r_max {
                // a' = ceil((2B + r*n)/s)
                // b' = floor((3B - 1 + r*n)/s)
                let rn = &r * n;
                let a_candidate = div_ceil(&(&two_B + &rn), &s_i);
                let b_candidate = (&(&(&three_B - &one) + &rn)) / &s_i;

                let a_new = max_big(&a_candidate, a);
                let b_new = min_big(&b_candidate, b);

                if a_new <= b_new {
                    // Check for solution immediately
                    if a_new == b_new {
                        eprintln!("[Step {}] Solution found: m={}", i, a_new);
                        // m = a_new (no blinding) -> recover message from k-byte block
                        let em = to_k_bytes(&a_new, k);
                        if em.len() < 4 || em[0] != 0 || em[1] != 2 { return None; }
                        let mut idx = 2usize;
                        while idx < em.len() && em[idx] != 0 { idx += 1; }
                        if idx >= em.len() { return None; }
                        let msg = em[(idx + 1)..].to_vec();
                        return Some(msg);
                    }
                    new_intervals.push((a_new, b_new));
                }
                r = &r + &one;
            }
        }
        intervals = merge_intervals(new_intervals);

        // Step 3.c: Check if we have a unique solution (redundant check after merge)
        if intervals.len() == 1 {
            let (a, b) = &intervals[0];
            if a == b {
                // m = a (no blinding) -> recover message from k-byte block
                let em = to_k_bytes(a, k);
                // Strip PKCS#1 v1.5 formatting: 0x00 0x02 || PS || 0x00 || M
                if em.len() < 4 || em[0] != 0 || em[1] != 2 { return None; }
                // Find 0x00 separator after PS
                let mut idx = 2usize;
                while idx < em.len() && em[idx] != 0 { idx += 1; }
                if idx >= em.len() { return None; }
                let msg = em[(idx + 1)..].to_vec();
                return Some(msg);
            }
        }

        // Step 3.a: find next s
        i += 1;
        if intervals.len() >= 2 {
            // Multiple intervals: linear batch search
            let s_start = &s_i + &BigUint::from(1u32);
            s_i = find_next_s_linear_parallel_async(n, e, &c0, oracle.clone(), &s_start, 4096).await?;
        } else {
            // Single interval: optimized r-loop search (avoid scanning each s individually)
            let (a, b) = &intervals[0];
            s_i = find_next_s_single_interval_optimized_async(n, e, &c0, oracle.clone(), &s_i, a, b, &two_B, &three_B).await?;
        }
    }
}

async fn find_next_s_linear_parallel_async(
    n: &BigUint,
    e: &BigUint,
    c0: &BigUint,
    oracle: Arc<Oracle>,
    s_start: &BigUint,
    batch_size: usize,
) -> Option<BigUint> {
    let mut s = s_start.clone();
    let mut scanned: u64 = 0;
    loop {
        if let Some(found) = first_conforming_in_batch_async(n, e, c0, oracle.clone(), &s, batch_size).await {
            return Some(found);
        }
        s = s + BigUint::from(batch_size as u32);
        scanned += batch_size as u64;
        if scanned % 1_000_000 == 0 {
            eprintln!("scanned {} s candidates in initial search...", scanned);
        }
    }
}

// Optimized single-interval search: iterate r and test derived s range endpoints before full batch.
async fn find_next_s_single_interval_optimized_async(
    n: &BigUint,
    e: &BigUint,
    c0: &BigUint,
    oracle: Arc<Oracle>,
    s_prev: &BigUint,
    a: &BigUint,
    b: &BigUint,
    two_B: &BigUint,
    three_B: &BigUint,
) -> Option<BigUint> {
    let one = BigUint::from(1u32);
    // r start per spec: r = ceil(2*(b*s_prev - 2B)/n)
    let r_start_num = ((b.clone() * s_prev.clone()) * BigUint::from(2u32)) - (two_B.clone() * BigUint::from(2u32));
    let mut r = div_ceil(&r_start_num, n);
    // Safety clamp if negative-like (underflow simulated via sub_or_zero earlier logic)
    if r == BigUint::from(0u32) { r = BigUint::from(1u32); }
    loop {
        let rn = r.clone() * n;
        let s_min = div_ceil(&(two_B.clone() + rn.clone()), b);
        let s_max = ((three_B.clone() - &one) + rn.clone()) / a;
        if s_min > s_max { r = &r + &one; continue; }
        // Test endpoints first (heuristic often succeeds quickly)
        for candidate in [s_min.clone(), s_max.clone()] {
            let c_test = (c0.clone() * candidate.modpow(e, n)) % n;
            if oracle.is_pkcs1_conforming(&c_test) { return Some(candidate); }
        }
        // If range large, do parallel batch across it
        let span = &s_max - &s_min;
        let bits = span.bits();
        if bits > 14 { // threshold to justify parallel search
            if let Some(found) = first_conforming_in_range_async(n, e, c0, oracle.clone(), &s_min, &s_max, 4096).await {
                return Some(found);
            }
        } else {
            // Small range: sequential scan
            let mut s = s_min + BigUint::from(1u32);
            while s < s_max {
                let c_test = (c0.clone() * s.modpow(e, n)) % n;
                if oracle.is_pkcs1_conforming(&c_test) { return Some(s); }
                s = s + &one;
            }
        }
        r = &r + &one;
    }
}

fn div_ceil(a: &BigUint, b: &BigUint) -> BigUint {
    // ceil(a/b) = (a + b - 1) / b for positive integers
    (a + (b - BigUint::from(1u32))) / b
}

async fn first_conforming_in_batch_async(
    n: &BigUint,
    e: &BigUint,
    c0: &BigUint,
    oracle: Arc<Oracle>,
    s_start: &BigUint,
    batch_size: usize,
) -> Option<BigUint> {
    let workers = std::cmp::max(2, num_cpus::get());
    let chunk = (batch_size + workers - 1) / workers;
    let mut tasks = Vec::new();
    for w in 0..workers {
        let start_off = w * chunk;
        if start_off >= batch_size { break; }
        let len = chunk.min(batch_size - start_off);
        let n_c = n.clone();
        let e_c = e.clone();
        let c0_c = c0.clone();
        let s0 = s_start + BigUint::from(start_off as u32);
        let oracle_c = oracle.clone();
        tasks.push(task::spawn_blocking(move || {
            let mut s = s0;
            for j in 0..len {
                let c_test = (c0_c.clone() * s.modpow(&e_c, &n_c)) % &n_c;
                if oracle_c.is_pkcs1_conforming(&c_test) {
                    return Some((start_off + j, s));
                }
                s = s + BigUint::from(1u32);
            }
            None
        }));
    }
    let results = join_all(tasks).await;
    let mut best: Option<(usize, BigUint)> = None;
    for r in results {
        if let Ok(Some((idx, s))) = r {
            best = match best { Some((bi, bs)) if bi <= idx => Some((bi, bs)), _ => Some((idx, s)) };
        }
    }
    best.map(|(_, s)| s)
}

async fn first_conforming_in_range_async(
    n: &BigUint,
    e: &BigUint,
    c0: &BigUint,
    oracle: Arc<Oracle>,
    s_min: &BigUint,
    s_max: &BigUint,
    batch_size: usize,
) -> Option<BigUint> {
    let mut start = s_min.clone();
    while &start <= s_max {
        // Determine this batch's upper bound and total candidates without BigUint->usize conversion
        let mut end = start.clone();
        let mut total = 0usize;
        for _ in 0..batch_size {
            if end > *s_max { break; }
            end = end + BigUint::from(1u32);
            total += 1;
        }
        // Parallel check within [start, end)
        let workers = std::cmp::max(2, num_cpus::get());
        let mut tasks = Vec::new();
        let chunk = (total + workers - 1) / workers;
        for w in 0..workers {
            let start_off = w * chunk;
            if start_off >= total { break; }
            let len = chunk.min(total - start_off);
            let n_c = n.clone();
            let e_c = e.clone();
            let c0_c = c0.clone();
            let s0 = &start + BigUint::from(start_off as u32);
            let oracle_c = oracle.clone();
            tasks.push(task::spawn_blocking(move || {
                let mut s = s0;
                for j in 0..len {
                    let c_test = (c0_c.clone() * s.modpow(&e_c, &n_c)) % &n_c;
                    if oracle_c.is_pkcs1_conforming(&c_test) {
                        return Some((start_off + j, s));
                    }
                    s = s + BigUint::from(1u32);
                }
                None
            }));
        }
        let results = join_all(tasks).await;
        let mut best: Option<(usize, BigUint)> = None;
        for r in results {
            if let Ok(Some((idx, s))) = r {
                best = match best { Some((bi, bs)) if bi <= idx => Some((bi, bs)), _ => Some((idx, s)) };
            }
        }
        if let Some((_, found)) = best { return Some(found); }
        // Advance start to end
        start = end;
    }
    None
}

fn max_big<'a>(a: &'a BigUint, b: &'a BigUint) -> BigUint { if a > b { a.clone() } else { b.clone() } }
fn min_big<'a>(a: &'a BigUint, b: &'a BigUint) -> BigUint { if a < b { a.clone() } else { b.clone() } }

fn merge_intervals(mut ivs: Vec<(BigUint, BigUint)>) -> Vec<(BigUint, BigUint)> {
    if ivs.is_empty() { return ivs; }
    ivs.sort_by(|x, y| x.0.cmp(&y.0));
    let mut out: Vec<(BigUint, BigUint)> = Vec::new();
    let mut cur = ivs[0].clone();
    for i in 1..ivs.len() {
        let (ref a, ref b) = cur;
        let (ref c, ref d) = ivs[i];
        if c <= b { // overlap or touching
            let new_b = if d > b { d.clone() } else { b.clone() };
            cur = (a.clone(), new_b);
        } else {
            out.push(cur);
            cur = (c.clone(), d.clone());
        }
    }
    out.push(cur);
    out
}
