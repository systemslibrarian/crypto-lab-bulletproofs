# crypto-lab-bulletproofs

## What It Is

Bulletproofs are short non-interactive zero-knowledge proofs that a committed value lies in a given range, with no trusted setup and proof size logarithmic in the range. They reduce to an inner-product argument over ristretto255. The security model is computational under the discrete log assumption; soundness is via Fiat-Shamir in the random oracle model.

## When to Use It

- **Confidential transactions** where you need to prove amounts are non-negative without revealing them — size beats naive OR-proofs by orders of magnitude.
- **Any protocol needing range proofs without a trusted setup ceremony** — unlike Groth16, there is no toxic waste.
- **Aggregated multi-value proofs** where the log-size benefit compounds — dozens of values in a single sub-kilobyte proof.
- **Do NOT use** when you need constant-size proofs — Groth16 is 192 bytes regardless; Bulletproofs grow with `log(range × count)`.
- **Do NOT use** when verifier time matters more than prover time — verification is O(n), not sublinear.
- **Do NOT use in production** — this is a from-scratch teaching implementation; it has not been audited, makes no constant-time guarantees, and must not be used to protect real assets.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-bulletproofs](https://systemslibrarian.github.io/crypto-lab-bulletproofs/)**

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

## What Can Go Wrong

- A range proof only proves the committed value lies in range; it says nothing about *which* value or its meaning. Application logic must still bind the commitment to the right amount/account, or a valid proof can authorize the wrong thing.
- Verification is linear (O(n)) and aggregation cost grows with `log(range × count)`; verifying many proofs one at a time is slow, so batch verification is usually required at scale.
- Fiat-Shamir soundness depends on hashing the full transcript. A challenge not bound to every public input (generators, commitment, prior messages) opens the proof to forgery.
- Implementations are not automatically constant-time; leaking the blinding factor or a scalar through timing can compromise the hiding of the committed value.
- Weak or reused randomness for the blinders breaks the hiding and zero-knowledge properties.

## Real-World Usage

- Monero uses Bulletproofs (and Bulletproofs+) for confidential-transaction range proofs, hiding transaction amounts while proving they are non-negative.
- Mimblewimble-style chains such as Grin and Beam use range proofs without a trusted setup to keep amounts confidential.
- Proof-of-reserves and confidential-asset systems use range proofs to show balances are within valid bounds without disclosing the actual figures.
- More generally, any setting that must prove a hidden value lies in a valid range (ages, balances, limits) without revealing it is a candidate for Bulletproof range proofs.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-bulletproofs
cd crypto-lab-bulletproofs
npm install
npm run dev
```

## Related Demos
- [crypto-lab-snark-arena](https://systemslibrarian.github.io/crypto-lab-snark-arena/) — Groth16/PLONK zk-SNARKs, the constant-size proofs Bulletproofs are contrasted against.
- [crypto-lab-stark-tower](https://systemslibrarian.github.io/crypto-lab-stark-tower/) — zk-STARKs, another transparent (no trusted setup) proof system.
- [crypto-lab-zk-arena](https://systemslibrarian.github.io/crypto-lab-zk-arena/) — side-by-side comparison of SNARK and STARK proof systems.
- [crypto-lab-zk-proof-lab](https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/) — Schnorr commitments and Fiat-Shamir, the building blocks behind these proofs.
- [crypto-lab-commit-gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/) — Pedersen commitments, the hiding commitment scheme a range proof is built over.

## Testing

```bash
npm test         # crypto suite + serialization + aggregate + batch-verifier + headless UI smoke test
npm run build    # production build (type-checks, then bundles)
```

CI runs on every push: see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
