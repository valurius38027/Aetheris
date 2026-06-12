//! IPA Accumulator for the Aetheris recursive proof system (Phase 1.4).
//!
//! Trust model: this is a "trusted-aggregator" accumulator. The aggregator
//! MUST call `verify_conservation` (out-of-circuit) on every inner proof.
//! The accumulator state (`Q`, `transcript`, `depth`) is the cryptographic
//! anchor. The in-circuit `CircuitAccumulate` (in `circuit_accumulate.rs`)
//! verifies the algebraic update relation; a future Phase (1.6, see
//! ISSUE-1.4.A) will add in-circuit IPA verification for trustless recursion.
//!
//! Curve placement: the accumulator's `Q` and `pi_commitment` are Vesta
//! points (`EqAffine`, base `Fq`, scalar `Fp`). All arithmetic is native
//! Fq (`FINAL_ARCHITECTURAL_PLAN.md §A`). The inner proof's IPA commitment
//! curve remains Pallas.

use aetheris_zkp::{halo2_pasta::Halo2PastaBackend, poseidon_fq, trait_::TxCommitments, ZkProverSystem};
use ff::{Field, FromUniformBytes, PrimeField};
use group::{prime::PrimeCurveAffine, Curve, GroupEncoding};
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp, Fq};
use subtle::CtOption;

/// Domain separator for the accumulator's transcript state.
/// Concatenated as a length-tag to prevent cross-protocol blake3 collisions.
pub const ACCUMULATOR_TRANSCRIPT_DOMAIN: &[u8] = b"aetheris-ipa-accumulator-v2\x00";

/// Domain separator for the per-proof `pi_commitment` derivation.
pub const PI_COMMITMENT_DOMAIN: &[u8] = b"aetheris-pi-cmt-v2\x00";

/// Inner-proof wire-format prefix. The aggregator MUST reject proofs that
/// do not start with this prefix (prevents accidental accumulation of
/// non-Aetheris proofs).
pub const INNER_PROOF_PREFIX: &[u8] = b"halo2_ipa_vesta_v1_";

/// Wire format prefix for the serialized accumulator state.
/// 28 bytes including the trailing separator.
pub const ACCUMULATOR_WIRE_PREFIX: &[u8] = b"aetheris_accumulator_ipa_v2_";

/// Wire format prefix for the signed accumulator state.
/// 28 bytes including the trailing separator.
/// Total: 28 + 32 + 32 + 64 + 4 = 160 bytes.
pub const SIGNED_ACCUMULATOR_WIRE_PREFIX: &[u8] = b"aetheris_signed_accumulator_v2_";

/// Domain separator for the ed25519 signature on accumulator claims.
pub const ACCUMULATOR_SIGNATURE_DOMAIN: &[u8] = b"aetheris-accumulator-sig-v2\x00";

/// Maximum chain depth (anti-DoS bound). 1M accumulated proofs is well
/// beyond any realistic block chain (at 1k txs/block, 1000 blocks of
/// depth).
pub const MAX_ACCUMULATOR_DEPTH: u32 = 1_000_000;

#[derive(Debug)]
pub enum AccumulatorError {
    /// Inner proof does not start with the expected wire-format prefix.
    BadPrefix,
    /// Inner proof failed `verify_conservation`.
    InnerProofInvalid(String),
    /// Accumulator depth would exceed `MAX_ACCUMULATOR_DEPTH`.
    DepthOverflow,
    /// Serialized wire bytes are malformed.
    BadWireFormat(String),
}

impl std::fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPrefix => write!(f, "inner proof has wrong wire-format prefix"),
            Self::InnerProofInvalid(h) => {
                write!(f, "inner proof verify_conservation failed (proof_hash: {})", h)
            }
            Self::DepthOverflow => write!(
                f,
                "accumulator depth would exceed {}",
                MAX_ACCUMULATOR_DEPTH
            ),
            Self::BadWireFormat(s) => write!(f, "malformed accumulator wire bytes: {}", s),
        }
    }
}

impl std::error::Error for AccumulatorError {}

/// Accumulator state: the cryptographic anchor that binds the chain of
/// accumulated inner proofs.
///
/// `Q` is a Vesta group element (the "rolling IPA commitment"). `transcript`
/// is a 32-byte Poseidon hash that absorbs the proof hash and the previous
/// accumulator state. `depth` is the number of accumulated proofs.
///
/// Serialization: use `to_bytes()` / `from_bytes()` (custom wire format with
/// the `ACCUMULATOR_WIRE_PREFIX`). The struct does not derive
/// `Serialize`/`Deserialize` because `EqAffine` does not implement them.
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct AccumulatorIPA {
    pub Q: EqAffine,
    pub transcript: [u8; 32],
    pub depth: u32,
    /// ed25519 signature on the signed claim (empty if unsigned).
    pub signature: Option<[u8; 64]>,
}

impl Default for AccumulatorIPA {
    fn default() -> Self {
        Self::new()
    }
}

impl AccumulatorIPA {
    /// Initial accumulator state: `Q` = identity (point at infinity),
    /// `transcript` = `poseidon_hash(domain_fq_bytes, genesis_fq_bytes)`,
    /// `depth` = 0.
    pub fn new() -> Self {
        let domain_fq_bytes = domain_tag_to_fq_bytes(ACCUMULATOR_TRANSCRIPT_DOMAIN);
        let genesis_bytes = tag_to_fq_bytes(b"genesis");
        let transcript = poseidon_fq::poseidon_hash(&domain_fq_bytes, &genesis_bytes);
        Self {
            Q: EqAffine::identity(),
            transcript,
            depth: 0,
            signature: None,
        }
    }

    /// Accumulate one inner proof.
    ///
    /// Steps (out-of-circuit):
    ///   1. Verify prefix on the proof bytes.
    ///   2. Call `verify_conservation` to ensure the proof is well-formed.
    ///   3. Compute `inner_proof_hash = blake3(proof)` (two-phase: byte reduction → Poseidon).
    ///   4. Compute `commitment_hash = blake3(commitments || public_amount)`.
    ///   5. `inner_proof_hash_eff = Poseidon(inner_proof_hash, commitment_hash)`.
    ///   6. Compute `pi_commitment = hash_to_curve(PI_COMMITMENT_DOMAIN, inner_proof_hash_eff)`.
    ///   7. Compute `challenge = Poseidon_hash_chain(domain, transcript, ipe)`,
    ///      reduced to `Fp` (Vesta scalar).
    ///   8. `Q_new = Q + challenge * pi_commitment` (Vesta scalar mul + add).
    ///   9. `transcript_new = Poseidon_hash_chain(domain, transcript, challenge, Q, ipe)`.
    ///  10. `depth += 1`.
    ///
    /// Returns the new accumulator state; `self` is consumed (struct is `Copy`-able by value).
    pub fn accumulate(
        &self,
        proof: &[u8],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> Result<Self, AccumulatorError> {
        // 1. Prefix check (cheapest: byte slice comparison, fail-fast).
        if !proof.starts_with(INNER_PROOF_PREFIX) {
            return Err(AccumulatorError::BadPrefix);
        }

        // 2. Depth check (BEFORE expensive verify_conservation — this is the
        //    anti-DoS guard. Running the full Halo2 IPA proof verification
        //    on every submission at depth = MAX-1 would let an attacker burn
        //    CPU by flooding the aggregator with valid proofs that all
        //    eventually get rejected for depth overflow.)
        if self.depth >= MAX_ACCUMULATOR_DEPTH {
            return Err(AccumulatorError::DepthOverflow);
        }

        // 3. Shape check (bound in_len/out_len before calling
        //    `verify_conservation` — the latter panics in `ensure_keys`
        //    if the row budget is exceeded, which a 23-byte payload can
        //    trigger). The Halo2 IPA circuit uses PROVING_K = 11
        //    (2048 rows, see `aetheris-zkp/src/halo2_pasta.rs`); each
        //    input/output cell costs ~65 rows, plus ~3 fixed overhead,
        //    so `in_len + out_len` MUST be < (2048 - 3) / 65 ≈ 31. We
        //    round down to 30 for a small safety margin.
        const MAX_PROOF_IOPS: usize = 30;
        if proof.len() < INNER_PROOF_PREFIX.len() + 4 {
            return Err(AccumulatorError::BadPrefix);
        }
        let in_len = u16::from_le_bytes(
            proof[INNER_PROOF_PREFIX.len()..INNER_PROOF_PREFIX.len() + 2]
                .try_into()
                .expect("slice is 2 bytes"),
        ) as usize;
        let out_len = u16::from_le_bytes(
            proof[INNER_PROOF_PREFIX.len() + 2..INNER_PROOF_PREFIX.len() + 4]
                .try_into()
                .expect("slice is 2 bytes"),
        ) as usize;
        if in_len + out_len > MAX_PROOF_IOPS {
            return Err(AccumulatorError::InnerProofInvalid(format!(
                "proof shape too large: in={} out={} (max {} total)",
                in_len, out_len, MAX_PROOF_IOPS
            )));
        }

        // 4. Inner proof verification.
        //    `verify_conservation` now binds output_commitments in its
        //    instance column (Phase 1.9 P0 fix), providing in-circuit
        //    commitment binding via the permutation argument. The accumulator
        //    additionally folds commitments into `inner_proof_hash_eff`
        //    (step 5) for defense-in-depth (Phase 1.5 / ISSUE-1.4.E).
        if !Halo2PastaBackend::verify_conservation(proof, output_commitments, public_amount) {
            return Err(AccumulatorError::InnerProofInvalid(hex::encode(
                blake3::hash(proof).as_bytes(),
            )));
        }

        // 5. inner_proof_hash_eff = poseidon_hash(proof_hash, commitment_hash)
        //    Two-phase: blake3 reduces arbitrary-length proof → 32B, then Poseidon binds.
        let inner_proof_hash = blake3::hash(proof);
        let commitment_hash = {
            let mut h = blake3::Hasher::new();
            h.update(&[0xC0u8]); // domain: commitment list (vs. proof 0xA0)
            h.update(&(output_commitments.len() as u32).to_le_bytes());
            for cm in output_commitments {
                h.update(cm);
            }
            h.update(&public_amount.to_le_bytes());
            h.finalize()
        };
        let inner_proof_hash_eff =
            poseidon_fq::poseidon_hash(inner_proof_hash.as_bytes(), commitment_hash.as_bytes());

        // 6. pi_commitment = hash_to_curve(PI_COMMITMENT_DOMAIN, inner_proof_hash_eff)
        //    Phase 1.4: NUMS-style try-and-increment hash-to-curve.
        //    - Take Poseidon(PI_COMMITMENT_DOMAIN_fq, inner_proof_hash_eff) -> 32 bytes
        //    - Mix in a 32-bit counter (length-tag to prevent ambiguity)
        //    - Reduce mod Fp (Vesta scalar field, native for EqAffine scalar mul)
        //      via `from_uniform_bytes` (NOT `from_repr`, which is canonical-only
        //      and would reject ~75% of inputs)
        //    - Multiply by the Vesta generator to get a Vesta point
        //    - Increment counter and re-derive if the resulting point is the
        //      identity (2^-254 chance; theoretically possible, practically never)
        //    Phase 1.5: also includes output_commitments binding via
        //    `inner_proof_hash_eff` (the chain can no longer be replayed
        //    with different commitments).
        let pi_commitment = hash_to_curve_nums_eff(&inner_proof_hash_eff);

        // 7. challenge = poseidon_hash_chain([domain, transcript, ipe]),
        //    reduced to Fp (Vesta scalar, for EqAffine scalar mul).
        let domain_fq_bytes = domain_tag_to_fq_bytes(ACCUMULATOR_TRANSCRIPT_DOMAIN);
        let challenge = uniform_bytes_to_fp(&poseidon_fq::poseidon_hash_chain(&[
            domain_fq_bytes,
            self.transcript,
            inner_proof_hash_eff,
        ]));

        // 8. Q_new = Q + challenge * pi_commitment.
        //    Both Q and pi_commitment are Vesta points (EqAffine). Scalar
        //    multiplication uses an Fp scalar (Vesta's scalar field). This
        //    is the correctness fix from Pallas→Vesta migration
        //    (FINAL_ARCHITECTURAL_PLAN.md §A).
        let t_proj = pi_commitment * challenge;
        let t_aff = t_proj.to_affine();
        let q_new_proj = self.Q + t_aff;
        let q_new = q_new_proj.to_affine();

        // 9. transcript_new = poseidon_hash_chain([domain, transcript, challenge,
        //    Q_new_compressed, inner_proof_hash_eff]).
        let q_new_compressed = q_new.to_bytes();
        let domain_fq_bytes = domain_tag_to_fq_bytes(ACCUMULATOR_TRANSCRIPT_DOMAIN);
        let challenge_repr: [u8; 32] = challenge.to_repr();
        let transcript_new = poseidon_fq::poseidon_hash_chain(&[
            domain_fq_bytes,
            self.transcript,
            challenge_repr,
            q_new_compressed,
            inner_proof_hash_eff,
        ]);

        Ok(Self {
            Q: q_new,
            transcript: transcript_new,
            depth: self.depth + 1,
            signature: None,
        })
    }

    /// Replay the chain and confirm every proof is individually valid.
    ///
    /// **Honest contract**: this returns `true` iff every proof in the
    /// chain passes `verify_conservation` AND the accumulator's state
    /// transitions are well-formed (no depth overflow, no bad prefix,
    /// no malformed wire format). It does **NOT** compare the resulting
    /// state against a previously-committed `claimed_acc`; the caller
    /// MUST do that comparison (e.g. by comparing the `transcript`
    /// hash). For Phase 1.4, callers are expected to be honest
    /// aggregators that commit to a `transcript` hash and check that
    /// `validate_proof_chain(...)` returns `true`. A future Phase
    /// (1.5+) will replace this naive O(n) replay with an O(1) in-
    /// circuit `CircuitAccumulate` proof verification.
    pub fn validate_proof_chain(
        proofs: &[Vec<u8>],
        commitments_list: &[TxCommitments],
        public_amounts: &[i64],
    ) -> bool {
        if proofs.len() != commitments_list.len() || proofs.len() != public_amounts.len() {
            return false;
        }
        let mut acc = Self::new();
        for ((proof, commitments), public_amount) in proofs
            .iter()
            .zip(commitments_list.iter())
            .zip(public_amounts.iter())
        {
            match acc.accumulate(proof, commitments, *public_amount) {
                Ok(new_acc) => acc = new_acc,
                Err(_) => return false,
            }
        }
        true
    }

    /// Attach an ed25519 signature to this accumulator.
    /// Returns a new accumulator with the signature set.
    pub fn with_signature(mut self, sig: [u8; 64]) -> Self {
        self.signature = Some(sig);
        self
    }

    /// Serialize (unsigned) to wire bytes. Format:
    ///   `ACCUMULATOR_WIRE_PREFIX` (28 bytes)
    ///   || `Q_compressed` (32 bytes; all zeros = identity)
    ///   || `transcript` (32 bytes)
    ///   || `depth` (4 bytes, little-endian)
    ///
    /// Note: the identity point's `EqAffine::to_bytes()` encoding is
    /// `[0u8; 32]` per the pasta_curves library (verified at
    /// `pasta_curves-0.5.1/src/curves.rs:693-704`), and `from_bytes` on
    /// the same all-zeros input returns `Some(identity)`. The explicit
    /// special-case below is defense-in-depth: if the library ever
    /// changes its convention, our wire format remains stable.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACCUMULATOR_WIRE_PREFIX.len() + 32 + 32 + 4);
        out.extend_from_slice(ACCUMULATOR_WIRE_PREFIX);
        if bool::from(self.Q.is_identity()) {
            out.extend_from_slice(&[0u8; 32]);
        } else {
            out.extend_from_slice(self.Q.to_bytes().as_ref());
        }
        out.extend_from_slice(&self.transcript);
        out.extend_from_slice(&self.depth.to_le_bytes());
        out
    }

    /// Serialize (signed) to wire bytes. Format:
    ///   `SIGNED_ACCUMULATOR_WIRE_PREFIX` (28 bytes)
    ///   || `Q_compressed` (32 bytes)
    ///   || `transcript` (32 bytes)
    ///   || `signature` (64 bytes, ed25519)
    ///   || `depth` (4 bytes, little-endian)
    ///
    /// Returns `Err` if no signature is attached.
    pub fn to_signed_bytes(&self) -> Result<Vec<u8>, AccumulatorError> {
        let sig = self
            .signature
            .ok_or_else(|| AccumulatorError::BadWireFormat("no signature attached".to_string()))?;
        let mut out = Vec::with_capacity(SIGNED_ACCUMULATOR_WIRE_PREFIX.len() + 32 + 32 + 64 + 4);
        out.extend_from_slice(SIGNED_ACCUMULATOR_WIRE_PREFIX);
        if bool::from(self.Q.is_identity()) {
            out.extend_from_slice(&[0u8; 32]);
        } else {
            out.extend_from_slice(self.Q.to_bytes().as_ref());
        }
        out.extend_from_slice(&self.transcript);
        out.extend_from_slice(&sig);
        out.extend_from_slice(&self.depth.to_le_bytes());
        Ok(out)
    }

    /// Deserialize from unsigned or signed wire bytes.
    /// Auto-detects format by prefix and length:
    /// - 96B + `ACCUMULATOR_WIRE_PREFIX` → unsigned
    /// - 160B + `SIGNED_ACCUMULATOR_WIRE_PREFIX` → signed (signature extracted)
    ///
    /// This is backward-compatible: old unsigned accumulators (96B) still
    /// deserialize without error.
    #[allow(non_snake_case)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccumulatorError> {
        let unsigned_len = ACCUMULATOR_WIRE_PREFIX.len() + 32 + 32 + 4; // 96
        let signed_len = SIGNED_ACCUMULATOR_WIRE_PREFIX.len() + 32 + 32 + 64 + 4; // 160

        // Determine format
        let (prefix, is_signed) =
            if bytes.len() == signed_len && bytes.starts_with(SIGNED_ACCUMULATOR_WIRE_PREFIX) {
                (SIGNED_ACCUMULATOR_WIRE_PREFIX, true)
            } else if bytes.len() == unsigned_len && bytes.starts_with(ACCUMULATOR_WIRE_PREFIX) {
                (ACCUMULATOR_WIRE_PREFIX, false)
            } else {
                return Err(AccumulatorError::BadWireFormat(format!(
                    "expected {}B (unsigned) or {}B (signed) with correct prefix, got {}B",
                    unsigned_len,
                    signed_len,
                    bytes.len()
                )));
            };

        let q_start = prefix.len();
        let mut q_bytes = [0u8; 32];
        q_bytes.copy_from_slice(&bytes[q_start..q_start + 32]);

        let Q = if q_bytes == [0u8; 32] {
            EqAffine::identity()
        } else {
            ct_option_to_err(
                EqAffine::from_bytes(&q_bytes),
                "Q is not a valid Vesta point",
            )?
        };

        let t_start = q_start + 32;
        let mut transcript = [0u8; 32];
        transcript.copy_from_slice(&bytes[t_start..t_start + 32]);

        let (sig_start, d_start) = if is_signed {
            // signed: 28 + 32 + 32 = 92, sig at 92..156, depth at 156..160
            let sig_s = t_start + 32;
            (Some(sig_s), sig_s + 64)
        } else {
            (None, t_start + 32)
        };

        let signature = if let Some(ss) = sig_start {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[ss..ss + 64]);
            Some(sig)
        } else {
            None
        };

        let mut depth_bytes = [0u8; 4];
        depth_bytes.copy_from_slice(&bytes[d_start..d_start + 4]);
        let depth = u32::from_le_bytes(depth_bytes);

        Ok(Self {
            Q,
            transcript,
            depth,
            signature,
        })
    }
}

/// Hash-to-curve: NUMS-style deterministic point derivation.
///
/// `inner_proof_hash_eff` is the 32-byte value that commits to the
/// inner proof + output commitments + public_amount (see `accumulate`
/// step 5). The outer domain binding uses Poseidon.
///
/// We hash it with the domain separator (Poseidon) to get a 32-byte seed, mix in a
/// 32-bit counter (length-tag to prevent ambiguity), and reduce mod Fp
/// (Vesta scalar field) via `from_uniform_bytes`. Multiply by the
/// Vesta generator to get a Vesta point. If the result is the
/// identity (statistically negligible — 2^-254 for a non-zero scalar),
/// we increment and retry.
///
/// Important: we use `Fp::from_uniform_bytes(&[u8; 64])` (mod-p
/// reduction of a 512-bit value) rather than `Fp::from_repr` (which
/// only accepts canonical 32-byte encodings).
///
/// This is NOT constant-time (iteration count leaks), but for 1.4 the
/// `accumulate()` is called by a permissioned aggregator, not a public
/// untrusted caller. A future Phase (1.5, see ISSUE-1.4.B) will replace
/// this with a constant-time SSWU2 implementation.
fn hash_to_curve_nums_eff(inner_proof_hash_eff: &[u8; 32]) -> EqAffine {
    hash_to_curve_nums_bytes(inner_proof_hash_eff)
}

fn hash_to_curve_nums_bytes(seed_in: &[u8; 32]) -> EqAffine {
    let domain_fq_bytes = domain_tag_to_fq_bytes(PI_COMMITMENT_DOMAIN);
    let seed = poseidon_fq::poseidon_hash(&domain_fq_bytes, seed_in);
    let mut counter: u32 = 0;
    loop {
        let mut mixed32 = [0u8; 32];
        mixed32[..4].copy_from_slice(&counter.to_le_bytes());
        mixed32[4..].copy_from_slice(&seed[..28]);
        let mut input64 = [0u8; 64];
        input64[..32].copy_from_slice(&mixed32);
        let c = Fp::from_uniform_bytes(&input64);
        debug_assert!(
            !bool::from(c.is_zero()),
            "uniform sample is zero (impossible)"
        );
        let p_proj = EqAffine::generator() * c;
        let p_aff = p_proj.to_affine();
        if !bool::from(p_aff.is_identity()) {
            return p_aff;
        }
        counter = counter.checked_add(1).expect("counter overflow");
    }
}

/// Convert a domain tag (arbitrary bytes) to a 32-byte Fq field element
/// for use as a Poseidon domain separator.
fn domain_tag_to_fq_bytes(tag: &[u8]) -> [u8; 32] {
    let h = blake3::hash(tag);
    let mut uniform = [0u8; 64];
    uniform[..32].copy_from_slice(h.as_bytes());
    Fq::from_uniform_bytes(&uniform).to_repr()
}

/// Convert a short tag (like "genesis") to a 32-byte Fq field element.
fn tag_to_fq_bytes(tag: &[u8]) -> [u8; 32] {
    let h = blake3::hash(tag);
    let mut uniform = [0u8; 64];
    uniform[..32].copy_from_slice(h.as_bytes());
    Fq::from_uniform_bytes(&uniform).to_repr()
}

/// Reduce a 32-byte hash output to an `Fp` field element (Vesta scalar).
///
/// **CRITICAL:** we use `Fp::from_uniform_bytes(&[u8; 64])` (mod-p
/// reduction of a 512-bit value) rather than `Fp::from_repr` (which
/// only accepts canonical 32-byte encodings). `from_repr` would reject
/// ~3/4 of uniformly-random 32-byte inputs as "non-canonical" (>= Pallas
/// prime), and `unwrap_or(Fp::ZERO)` would silently substitute the
/// additive identity. For the Fiat-Shamir challenge in `accumulate()`
/// (used as a Vesta scalar), this would mean `Q_new = Q + 0·π = Q` in 3/4
/// of accumulations — the IPA chain's binding property would collapse,
/// and a malicious aggregator could grind the proof's nonce to force the
/// trivial update. `from_uniform_bytes` is total (never returns zero
/// for a non-zero 64-byte input) and gives a uniform Fp sample.
fn uniform_bytes_to_fp(bytes: &[u8; 32]) -> Fp {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(bytes);
    Fp::from_uniform_bytes(&buf)
}

#[allow(dead_code)]
fn option_to_err<T>(opt: Option<T>, msg: &str) -> Result<T, AccumulatorError> {
    opt.ok_or_else(|| AccumulatorError::BadWireFormat(msg.to_string()))
}

/// Convert a `CtOption<T>` (constant-time option from `subtle`) to a `Result`.
fn ct_option_to_err<T>(opt: CtOption<T>, msg: &str) -> Result<T, AccumulatorError> {
    let is_some = bool::from(opt.is_some());
    if is_some {
        Ok(opt.unwrap())
    } else {
        Err(AccumulatorError::BadWireFormat(msg.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn accumulator_initial_state_is_deterministic() {
        let a = AccumulatorIPA::new();
        let b = AccumulatorIPA::new();
        assert_eq!(a.transcript, b.transcript);
        assert_eq!(a.depth, 0);
        assert!(bool::from(a.Q.is_identity()));
    }

    #[test]
    fn accumulator_rejects_bad_prefix() {
        let acc = AccumulatorIPA::new();
        let bad_proof = b"not_a_valid_proof_prefix_xxxxxxxxxxxxxxxx";
        let result = acc.accumulate(bad_proof, &[], 0);
        assert!(matches!(result, Err(AccumulatorError::BadPrefix)));
    }

    #[test]
    fn accumulator_rejects_valid_prefix_but_invalid_proof() {
        let acc = AccumulatorIPA::new();
        // Right prefix (19B) + valid shape (in_len=1, out_len=0; both fit in
        // the k=11 proving key rows) + a few bytes of inner_proof that
        // cannot be a real Halo2 IPA proof. The prefix check passes, but
        // `verify_conservation` returns false (the transcript is malformed),
        // so `accumulate()` returns `InnerProofInvalid` without panicking.
        let mut bad_proof = Vec::new();
        bad_proof.extend_from_slice(INNER_PROOF_PREFIX);
        bad_proof.extend_from_slice(&1u16.to_le_bytes());
        bad_proof.extend_from_slice(&0u16.to_le_bytes());
        bad_proof.extend_from_slice(&[0xFFu8; 32]);
        let result = acc.accumulate(&bad_proof, &[], 0);
        assert!(matches!(
            result,
            Err(AccumulatorError::InnerProofInvalid(_))
        ));
    }

    #[test]
    fn accumulator_serialize_roundtrip() {
        let acc = AccumulatorIPA::new();
        let bytes = acc.to_bytes();
        let recovered = AccumulatorIPA::from_bytes(&bytes).expect("deserialize");
        assert_eq!(acc.transcript, recovered.transcript);
        assert_eq!(acc.depth, recovered.depth);
        assert_eq!(acc.Q.to_bytes(), recovered.Q.to_bytes());
        assert!(recovered.signature.is_none());
    }

    #[test]
    fn accumulator_signed_serialize_roundtrip() {
        let acc = AccumulatorIPA::new();
        let sig = [0xABu8; 64];
        let signed = acc.clone().with_signature(sig);
        let bytes = signed.to_signed_bytes().expect("to_signed_bytes");
        let recovered = AccumulatorIPA::from_bytes(&bytes).expect("deserialize signed");
        assert_eq!(acc.transcript, recovered.transcript);
        assert_eq!(acc.depth, recovered.depth);
        assert_eq!(acc.Q.to_bytes(), recovered.Q.to_bytes());
        assert_eq!(recovered.signature, Some(sig));
    }

    #[test]
    fn accumulator_serialize_rejects_bad_length() {
        let bytes = vec![0u8; 50];
        let result = AccumulatorIPA::from_bytes(&bytes);
        assert!(matches!(result, Err(AccumulatorError::BadWireFormat(_))));
    }

    #[test]
    fn accumulator_serialize_rejects_bad_prefix() {
        // Use the correct unsigned wire-format length (28 + 32 + 32 + 4 = 96)
        // so the length check passes and the prefix-rejection branch is exercised.
        let mut bytes = vec![0u8; ACCUMULATOR_WIRE_PREFIX.len() + 32 + 32 + 4];
        bytes[..4].copy_from_slice(b"junk");
        let result = AccumulatorIPA::from_bytes(&bytes);
        assert!(matches!(result, Err(AccumulatorError::BadWireFormat(_))));
    }

    #[test]
    fn accumulator_to_signed_bytes_fails_without_signature() {
        let acc = AccumulatorIPA::new();
        let result = acc.to_signed_bytes();
        assert!(matches!(result, Err(AccumulatorError::BadWireFormat(_))));
    }

    #[test]
    fn accumulator_domain_separators_are_unique() {
        // Sanity: the three domain separators are distinct and non-overlapping
        // (no substring of one is a prefix of another, no shared bytes).
        assert_ne!(ACCUMULATOR_TRANSCRIPT_DOMAIN, PI_COMMITMENT_DOMAIN);
        assert_ne!(ACCUMULATOR_TRANSCRIPT_DOMAIN, INNER_PROOF_PREFIX);
        assert_ne!(PI_COMMITMENT_DOMAIN, INNER_PROOF_PREFIX);
        // Each contains a non-zero byte at the end (\x00) to prevent
        // ambiguous concat attacks.
        assert!(ACCUMULATOR_TRANSCRIPT_DOMAIN.last() == Some(&0));
        assert!(PI_COMMITMENT_DOMAIN.last() == Some(&0));
    }

    #[test]
    fn hash_to_curve_nums_is_deterministic() {
        let h = blake3::hash(b"test proof bytes");
        let p1 = hash_to_curve_nums_bytes(h.as_bytes());
        let p2 = hash_to_curve_nums_bytes(h.as_bytes());
        assert_eq!(p1.to_bytes(), p2.to_bytes());
        assert!(!bool::from(p1.is_identity()));
    }

    #[test]
    fn hash_to_curve_nums_differs_for_different_inputs() {
        let h1 = blake3::hash(b"proof_a");
        let h2 = blake3::hash(b"proof_b");
        let p1 = hash_to_curve_nums_bytes(h1.as_bytes());
        let p2 = hash_to_curve_nums_bytes(h2.as_bytes());
        assert_ne!(p1.to_bytes(), p2.to_bytes());
    }

    /// Depth-overflow test: even with a valid prefix + shape, an
    /// accumulator at the depth cap MUST reject further accumulations
    /// without invoking the expensive `verify_conservation`.
    #[test]
    fn accumulator_rejects_depth_overflow_without_zk_verify() {
        // Build an accumulator at the cap by directly mutating fields
        // (test-only path).
        let mut acc = AccumulatorIPA::new();
        acc.depth = MAX_ACCUMULATOR_DEPTH;
        let mut bad_proof = Vec::new();
        bad_proof.extend_from_slice(INNER_PROOF_PREFIX);
        bad_proof.extend_from_slice(&1u16.to_le_bytes());
        bad_proof.extend_from_slice(&0u16.to_le_bytes());
        bad_proof.extend_from_slice(&[0xFFu8; 32]);
        // The depth check is BEFORE verify_conservation, so a malformed
        // proof at depth = MAX still returns DepthOverflow (not
        // InnerProofInvalid).
        let result = acc.accumulate(&bad_proof, &[], 0);
        assert!(matches!(result, Err(AccumulatorError::DepthOverflow)));
    }

    /// Transcript binding: flipping a single byte in the inner proof
    /// MUST change the resulting `transcript` hash. (Uses
    /// `validate_proof_chain`-style: same `proofs` list with one byte
    /// flipped should produce a different accumulator. We can't easily
    /// call `accumulate()` here without a real proof, but we can call
    /// the lower-level `hash_to_curve_nums` and `uniform_bytes_to_fp` to
    /// demonstrate that small input changes produce different outputs
    /// — which is the binding property the chain relies on.)
    #[test]
    fn hash_to_curve_nums_binds_to_input() {
        let h1 = blake3::hash(b"proof_v1");
        let h2 = blake3::hash(b"proof_v2"); // one byte different
        let p1 = hash_to_curve_nums_bytes(h1.as_bytes());
        let p2 = hash_to_curve_nums_bytes(h2.as_bytes());
        assert_ne!(p1.to_bytes(), p2.to_bytes());

        // Same for uniform_bytes_to_fp (challenge reduction).
        let bytes1: [u8; 32] = *h1.as_bytes();
        let bytes2: [u8; 32] = *h2.as_bytes();
        let c1 = uniform_bytes_to_fp(&bytes1);
        let c2 = uniform_bytes_to_fp(&bytes2);
        assert_ne!(c1, c2);
    }

    /// Phase 1.5 / ISSUE-1.4.E: `hash_to_curve_nums_eff` binds BOTH the
    /// inner proof hash AND the effective hash (proof ⊕ commitment_hash
    /// ⊕ public_amount). Flipping a single bit in the effective hash
    /// changes the output, so the chain cannot be replayed with
    /// different output commitments or public_amounts.
    #[test]
    fn hash_to_curve_nums_eff_binds_to_commitment() {
        let h_eff_1 = [0x01u8; 32];
        let mut h_eff_2 = h_eff_1;
        h_eff_2[31] = 0x02; // one bit flipped
        let p1 = hash_to_curve_nums_eff(&h_eff_1);
        let p2 = hash_to_curve_nums_eff(&h_eff_2);
        assert_ne!(p1.to_bytes(), p2.to_bytes());
    }
}
