/// Per-tx commitment set (flat list of output commitments)
pub type TxCommitments = Vec<[u8; 32]>;

/// Abstract ZK proving system interface.
/// V1 uses Halo2Backend (Halo2 + Pasta curves).
/// V2+ can swap via this trait (e.g., post-quantum lattice ZK).
pub trait ZkProverSystem: Sized {
    type Params;
    type ProvingKey;
    type VerifyingKey;

    fn ensure_params() -> &'static Self::Params;
    fn ensure_keys(
        amounts_in_len: usize,
        amounts_out_len: usize,
    ) -> (Self::VerifyingKey, Self::ProvingKey);

    fn prove_conservation(
        amounts_in: &[u64],
        amounts_out: &[u64],
        in_blindings: &[[u8; 32]],
        out_blindings: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> Vec<u8>;

    fn verify_conservation(
        proof: &[u8],
        output_commitments: &[[u8; 32]],
        public_amount: i64,
    ) -> bool;

    /// Compute a Wesolowski VDF proof over the class group Cl(D), |D|=2048.
    ///
    /// **Wire format**: returns `(result, proof)` — both are serialized class
    /// group forms (`Form::to_bytes`, ~256 bytes each for |D|=2048).
    ///
    /// **Security model**:
    /// - Difficulty-binding: a proof generated at `difficulty=D1` is rejected
    ///   by `verify_vdf` called with `difficulty=D2` because the verifier
    ///   recomputes `r = 2^D2 mod l` from the caller's difficulty.
    /// - No trusted setup: the class group discriminant is deterministic
    ///   (`b"Aetheris Class Group VDF v1"`), no parameters to subvert.
    /// - Sequential cost: `prove_vdf` is O(D) sequential squarings, so
    ///   `D=1_600_000` takes ~80s on modern CPU. Production callers should
    ///   use `AETHERIS_VDF_DIFFICULTY=10` (~1s) in tests, or set a difficulty
    ///   tuned to their block time target.
    ///
    /// See `aetheris_crypto::VDF` for the underlying implementation.
    fn prove_vdf(public_seed: &[u8], difficulty: u64) -> (Vec<u8>, Vec<u8>) {
        let vdf = aetheris_crypto::VDF::new(difficulty);
        let (result, proof, _) = vdf.solve(public_seed);
        (result, proof)
    }

    /// Verify a Wesolowski VDF proof: `π^l ∘ x^r == y` where `l` is derived
    /// from `hash(public_seed, result)`, `r = 2^difficulty mod l`.
    ///
    /// **Argument order** is `(result, proof, public_seed, difficulty)` —
    /// result first to match the natural block-header field order
    /// (`vdf_result`, `vdf_proof`).
    ///
    /// Returns `false` for: empty inputs, deserialization failures
    /// (`Form::from_bytes` returns None), and equation mismatches.
    fn verify_vdf(result: &[u8], proof: &[u8], public_seed: &[u8], difficulty: u64) -> bool {
        aetheris_crypto::VDF::new(difficulty).verify(public_seed, result, proof)
    }
}
