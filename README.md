# Bulletproofs Range Proofs over Ristretto255

> **Educational demo only.** This is a from-scratch TypeScript implementation of Bulletproofs intended for teaching the protocol in the browser. It has not been audited, makes no constant-time guarantees, and must not be used to protect real assets.

## 1. What It Is

Bulletproofs are short non-interactive zero-knowledge proofs that a committed value lies in a given range, with no trusted setup and proof size logarithmic in the range. They reduce to an inner-product argument over ristretto255. The security model is computational under the discrete log assumption; soundness is via Fiat-Shamir in the random oracle model.

## 2. When to Use It

- **Confidential transactions** where you need to prove amounts are non-negative without revealing them — size beats naive OR-proofs by orders of magnitude.
- **Any protocol needing range proofs without a trusted setup ceremony** — unlike Groth16, there is no toxic waste.
- **Aggregated multi-value proofs** where the log-size benefit compounds — dozens of values in a single sub-kilobyte proof.
- **Do NOT use** when you need constant-size proofs — Groth16 is 192 bytes regardless; Bulletproofs grow with `log(range × count)`.
- **Do NOT use** when verifier time matters more than prover time — verification is O(n), not sublinear.

## 3. Live Demo

**URL:** https://systemslibrarian.github.io/crypto-lab-bulletproofs/

Users can commit a 64-bit value, generate a live range proof over ristretto255, verify it, inspect the Fiat-Shamir challenges and per-component proof sizes, run a *batched* multi-value flow, compare its size against the theoretical aggregated Bulletproof, and watch the cheat mode get rejected when the committed value is outside the legal range.

### Scope notes

- The single-value range proof is the full Bünz et al. 2018 Protocol 2 with the `H' = y^{-i} H` basis change and a transcript-bound IPA.
- A **true aggregated Bulletproof** (Protocol 2 §4.3) is implemented for power-of-two batch sizes — one log-size proof for *m* values, e.g. 864 B for m=8 vs 5376 B batched.
- A **single-MSM batch verifier** is implemented alongside the reference verifier for both the single-value and the aggregated proof, and exposed in the UI as a second "Verify" button.
- Proofs can be **exported and re-verified** from hex bytes, demonstrating that Bulletproofs are non-interactive.
- A **deterministic seed mode** swaps in a SHA-512 counter PRNG so blinders and proofs are reproducible bit-for-bit (teaching/testing only).
- A **manual tampering panel** flips a bit in `t̂` and shows both verifiers reject.
- A **benchmark panel** measures prove and verify times for the single-value proof and aggregates at *m* = 1, 2, 4, 8.
- All proof sizes shown for the single-value flow are measured from the actual serialized proof bytes, not from a formula.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bulletproofs
cd crypto-lab-bulletproofs
npm install
npm run dev      # local dev server
npm test         # boundary + serialization + true-aggregate + batch-verifier tests
npm run build    # production build
```

CI runs on every push: see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## 5. Part of the Crypto-Lab Suite

> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*