# Bulletproofs Range Proofs over Ristretto255

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

Users can commit a 64-bit value, generate a live range proof over ristretto255, verify it, attempt aggregate proofs across multiple values, and see the cheat mode fail verification when the committed value is outside the legal range.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bulletproofs
cd crypto-lab-bulletproofs
npm install
npm run dev
```

## 5. Part of the Crypto-Lab Suite

> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*