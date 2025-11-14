# Bleichenbacher's CCA POC (Rust)

This is a proof-of-concept implementation of Bleichenbacher's adaptive chosen-ciphertext attack against RSA PKCS#1 v1.5 encryption. It demonstrates how a padding oracle can be abused to recover a plaintext from a ciphertext without the private key.

It runs entirely locally: a simulated oracle uses the private key to check whether a decrypted block conforms to PKCS#1 v1.5. The attacker interacts only via this yes/no oracle.

## Implementation

- **Multi-threaded**: Uses Tokio runtime with parallel oracle queries across multiple CPU cores
- **Optimized search**: Single-interval phase uses r-based search (Step 2c from Bleichenbacher's paper)
- **Progress logging**: Prints oracle query count every 1000 queries and iteration stats every 5 iterations

## How it works

- Generates a small RSA key (128-bit by default for fast demo; configurable in `src/main.rs`).
- Encrypts a short message with PKCS#1 v1.5 format.
- Runs the classic Bleichenbacher attack to recover the plaintext using only the oracle.
- **Expected queries**: ~65k–2M depending on key size and random padding. The valid-padding probability is ~1/65k per trial.

## Quick start

```bash
# Build
cargo build --release

# Run the demo
cargo run --release
```

You should see the original and recovered plaintext match and a count of oracle queries.

## Notes

- The implementation follows the original 1998 algorithm with interval refinement and optimized single-interval search (Step 2c).
- **Performance**: For small keys (128–256 bit), expect 100k–2M oracle queries total. Larger keys will require more queries.
- **Random variation**: Each run generates a new random key and padding, so query counts vary significantly.
- This code is for educational purposes to understand why PKCS#1 v1.5 padding is fragile against adaptive chosen-ciphertext attacks.
- **Long runtime**: The attack is inherently slow. For a quick verification, let it run for a few minutes; you can interrupt with Ctrl+C.

## References

- Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks against Protocols Based on the RSA Encryption Standard PKCS #1".
