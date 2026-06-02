/// Per-tx commitment set (one entry per output)
pub type TxCommitments = Vec<Vec<[u8; 32]>>;

/// Abstract ZK proving system interface.
/// V1 uses Halo2Backend (Halo2 + Pasta curves).
/// V2+ can swap via this trait (e.g., post-quantum lattice ZK).
pub trait ZkProverSystem: Sized {
    type Params;
    type ProvingKey;
    type VerifyingKey;

    fn ensure_params() -> &'static Self::Params;
    fn ensure_keys() -> (&'static Self::VerifyingKey, &'static Self::ProvingKey);

    fn prove_conservation(
        amounts_in: &[u64],
        amounts_out: &[u64],
        in_blindings: &[&[u8; 32]],
        out_blindings: &[&[u8; 32]],
        output_commitments: &[Vec<[u8; 32]>],
        public_amount: i64,
    ) -> Vec<u8>;

    fn verify_conservation(
        proof: &[u8],
        output_commitments: &[Vec<[u8; 32]>],
        public_amount: i64,
    ) -> bool;

    fn aggregate_proofs(
        last_agg: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[TxCommitments],
        tx_public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> Result<Vec<u8>, String>;

    fn verify_aggregate(
        agg_proof: &[u8],
        prev_agg: &[u8],
        tx_proofs: &[Vec<u8>],
        tx_commitments: &[TxCommitments],
        tx_public_amounts: &[i64],
        height: u64,
        state_root: &[u8; 32],
    ) -> bool;

    fn prove_vdf(public_seed: &[u8], difficulty: u64) -> Vec<u8>;

    fn verify_vdf(proof: &[u8], public_seed: &[u8], difficulty: u64) -> bool;
}
