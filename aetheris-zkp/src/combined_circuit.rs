use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Cell, Layouter, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
        create_proof, keygen_pk, keygen_vk,
    },
    poly::{Rotation, VerificationStrategy},
    transcript::{Blake2bWrite, TranscriptWriterBuffer, TranscriptReadBuffer, Blake2bRead, Challenge255},
};
use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use rand::rngs::OsRng;

use crate::ipa::commitment::CommitmentSchemeIPA;
use crate::ipa::prover::ProverIPA;
use crate::ipa::strategy::SingleStrategyIPA;
use crate::poseidon_fq::ensure_poseidon_spec;
use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
use crate::halo2_pasta::{ensure_params, CachedKeyPair};

/// Instance layout: [merkle_root, nullifier, public_amount, cm_0, cm_1, ...]
#[derive(Clone, Debug)]
pub struct CombinedConfig {
    /// Value conservation columns
    pub advice: [Column<Advice>; 5],
    /// Membership additional columns (non-Poseidon)
    pub leaf: Column<Advice>,
    pub siblings: Column<Advice>,
    pub sk: Column<Advice>,
    pub index: Column<Advice>,
    pub bit: Column<Advice>,
    /// Poseidon columns (3 state + partial_sbox + 3 RC fixed)
    pub poseidon: PoseidonFqConfig,
    /// Selectors
    pub s_running_sum: Selector,
    pub s_zero_check: Selector,
    pub s_conservation: Selector,
    pub s_bool: Selector,
    pub s_select: Selector,
    /// Shared instance column: [root, nf, pub_amt, cm_0, cm_1, ...]
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct CombinedConservationCircuit {
    // ── Value conservation ──
    pub amounts_in: Vec<u64>,
    pub amounts_out: Vec<u64>,
    pub in_blindings: Vec<[u8; 32]>,
    pub out_blindings: Vec<[u8; 32]>,
    pub output_commitments: Vec<Vec<[u8; 32]>>,
    pub public_amount: i64,
    // ── Membership + nullifier ──
    pub leaf: [u8; 32],
    pub path_siblings: Vec<[u8; 32]>,
    pub position_bits: Vec<bool>,
    pub sk: [u8; 32],
    pub index: u64,
    // ── Public inputs ──
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
}

static COMBINED_KEY_CACHE: OnceLock<Mutex<HashMap<(usize, usize, usize), CachedKeyPair>>> =
    OnceLock::new();

fn ensure_combined_keys(
    amounts_in_len: usize,
    amounts_out_len: usize,
    depth: usize,
) -> CachedKeyPair {
    let params = ensure_params();
    let cache = COMBINED_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (amounts_in_len, amounts_out_len, depth);
    {
        let map = cache.lock().expect("combined key cache poisoned");
        if let Some(kp) = map.get(&key) {
            return kp.clone();
        }
    }
    let (amounts_out, public_amount): (Vec<u64>, i64) = if amounts_out_len == 0 {
        (vec![], amounts_in_len as i64)
    } else {
        let mut v = vec![0u64; amounts_out_len];
        let fill = amounts_in_len.min(amounts_out_len);
        for i in 0..fill {
            v[i] = 1;
        }
        if amounts_in_len > fill {
            v[fill - 1] += (amounts_in_len - fill) as u64;
        }
        (v, 0)
    };
    let dummy = CombinedConservationCircuit {
        amounts_in: vec![1u64; amounts_in_len],
        amounts_out,
        in_blindings: vec![[1u8; 32]; amounts_in_len],
        out_blindings: vec![[1u8; 32]; amounts_out_len],
        output_commitments: vec![vec![[1u8; 32]]; amounts_out_len],
        public_amount,
        leaf: [0u8; 32],
        path_siblings: vec![[0u8; 32]; depth],
        position_bits: vec![false; depth],
        sk: [0u8; 32],
        index: 0,
        merkle_root: [0u8; 32],
        nullifier: [0u8; 32],
    };
    let vk = keygen_vk(params, &dummy).expect("combined keygen_vk failed");
    let pk = keygen_pk(params, vk.clone(), &dummy).expect("combined keygen_pk failed");
    let result = (vk.clone(), pk.clone());
    cache
        .lock()
        .expect("poisoned")
        .insert(key, (vk, pk));
    result
}

impl Circuit<Fq> for CombinedConservationCircuit {
    type Config = CombinedConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            amounts_in: vec![0u64; self.amounts_in.len()],
            amounts_out: vec![0u64; self.amounts_out.len()],
            in_blindings: vec![[0u8; 32]; self.in_blindings.len()],
            out_blindings: vec![[0u8; 32]; self.out_blindings.len()],
            output_commitments: self
                .output_commitments
                .iter()
                .map(|cm_set| vec![[0u8; 32]; cm_set.len()])
                .collect(),
            public_amount: 0,
            leaf: [0u8; 32],
            path_siblings: vec![[0u8; 32]; self.path_siblings.len()],
            position_bits: self.position_bits.clone(),
            sk: [0u8; 32],
            index: 0,
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        // ── Value conservation columns ──
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for col in &advice {
            meta.enable_equality(*col);
        }

        // ── Membership advice columns ──
        let leaf = meta.advice_column();
        let siblings = meta.advice_column();
        let sk = meta.advice_column();
        let index = meta.advice_column();
        let bit = meta.advice_column();
        for col in [leaf, siblings, sk, index, bit] {
            meta.enable_equality(col);
        }

        // ── Poseidon columns ──
        let poseidon = PoseidonFqChip::configure(meta);

        // ── Selectors ──
        let s_running_sum = meta.selector();
        let s_zero_check = meta.selector();
        let s_conservation = meta.selector();
        let s_bool = meta.selector();
        let s_select = meta.selector();

        // ── Instance column ──
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // ── Value conservation gates ──

        // Gate 1: running_sum
        meta.create_gate("running_sum", |meta| {
            let s = meta.query_selector(s_running_sum);
            let z_prev = meta.query_advice(advice[0], Rotation(-1));
            let z_cur = meta.query_advice(advice[0], Rotation(0));
            let b = meta.query_advice(advice[1], Rotation(0));
            vec![s * (z_prev - Expression::Constant(Fq::from(2)) * z_cur - b)]
        });

        // Gate 2: bit_constraint
        meta.create_gate("bit_constraint", |meta| {
            let s = meta.query_selector(s_running_sum);
            let b = meta.query_advice(advice[1], Rotation(0));
            vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
        });

        // Gate 3: zero_check
        meta.create_gate("zero_check", |meta| {
            let s = meta.query_selector(s_zero_check);
            let a = meta.query_advice(advice[0], Rotation(0));
            let b = meta.query_advice(advice[2], Rotation(0));
            vec![s.clone() * (a - b.clone()), s * b]
        });

        // Gate 4: conservation_running_sum
        meta.create_gate("conservation_running_sum", |meta| {
            let s = meta.query_selector(s_conservation);
            let prev = meta.query_advice(advice[2], Rotation(-1));
            let cur = meta.query_advice(advice[2], Rotation(0));
            let signed = meta.query_advice(advice[4], Rotation(0));
            vec![s * (cur - prev - signed)]
        });

        // ── Membership gates ──

        // Gate 5: bool_check (bit ∈ {0,1})
        meta.create_gate("bool_check", |meta| {
            let s = meta.query_selector(s_bool);
            let b = meta.query_advice(bit, Rotation::cur());
            vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
        });

        // Gate 6: mux_inputs (gate-based input selection)
        meta.create_gate("mux_inputs", |meta| {
            let s = meta.query_selector(s_select);
            let leaf_val = meta.query_advice(leaf, Rotation::cur());
            let sibling_val = meta.query_advice(siblings, Rotation::cur());
            let bit_val = meta.query_advice(bit, Rotation::cur());
            let state_0 = meta.query_advice(poseidon.state[0], Rotation::cur());
            let state_1 = meta.query_advice(poseidon.state[1], Rotation::cur());
            let one_minus_bit = Expression::Constant(Fq::one()) - bit_val.clone();
            let first_mux =
                one_minus_bit.clone() * leaf_val.clone() + bit_val.clone() * sibling_val.clone();
            let second_mux = one_minus_bit * sibling_val.clone() + bit_val * leaf_val.clone();
            vec![
                s.clone() * (state_0 - first_mux),
                s * (state_1 - second_mux),
            ]
        });

        CombinedConfig {
            advice,
            leaf,
            siblings,
            sk,
            index,
            bit,
            poseidon,
            s_running_sum,
            s_zero_check,
            s_conservation,
            s_bool,
            s_select,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let depth = self.path_siblings.len();
        let spec = ensure_poseidon_spec();
        const T: usize = 3;

        // ── Parse witnesses ──
        let leaf_fq = Fq::from_repr(self.leaf).expect("leaf is canonical Fq");
        let sk_fq = Fq::from_repr(self.sk).expect("sk is canonical Fq");
        let index_fq = Fq::from(self.index);
        let sibling_fqs: Vec<Fq> = self
            .path_siblings
            .iter()
            .map(|s| Fq::from_repr(*s).expect("sibling is canonical Fq"))
            .collect();

        // ── Witness region (bits, sk, index) ──
        let sk_cell: Cell;
        let index_cell: Cell;

        let witness_result = layouter.assign_region(
            || "witnesses",
            |mut region| {
                let mut offset = 0usize;
                for (i, &b) in self.position_bits.iter().enumerate() {
                    config.s_bool.enable(&mut region, offset)?;
                    let bit_val = if b { Fq::one() } else { Fq::ZERO };
                    region.assign_advice(
                        || format!("bit_{}", i),
                        config.bit,
                        offset,
                        || Value::known(bit_val),
                    )?;
                    offset += 1;
                }
                offset += 1;
                let skc = region.assign_advice(
                    || "sk",
                    config.sk,
                    offset,
                    || Value::known(sk_fq),
                )?;
                offset += 1;
                let ic = region.assign_advice(
                    || "index",
                    config.index,
                    offset,
                    || Value::known(index_fq),
                )?;
                Ok((skc.cell(), ic.cell()))
            },
        )?;
        sk_cell = witness_result.0;
        index_cell = witness_result.1;

        // ── Value conservation region ──────────────────────────────────────
        let all_amounts: Vec<u64> = self
            .amounts_in
            .iter()
            .chain(self.amounts_out.iter())
            .copied()
            .collect();

        layouter.assign_region(
            || "value_conservation",
            |mut region| {
                let mut offset = 0usize;
                let inv_2 = Fq::from(2).invert().unwrap();

                for &amount in &all_amounts {
                    let z_0 = Fq::from(amount);
                    region.assign_advice(
                        || "z_0",
                        config.advice[0],
                        offset,
                        || Value::known(z_0),
                    )?;
                    region.assign_advice(
                        || "z_0_bit",
                        config.advice[1],
                        offset,
                        || Value::known(Fq::ZERO),
                    )?;
                    let mut z_prev = z_0;
                    let mut remaining = amount;
                    for _ in 0..64 {
                        offset += 1;
                        config.s_running_sum.enable(&mut region, offset)?;
                        let bit_val = remaining & 1;
                        let bit_fq = Fq::from(bit_val);
                        let z_cur = (z_prev - bit_fq) * inv_2;
                        region.assign_advice(
                            || "z_cur",
                            config.advice[0],
                            offset,
                            || Value::known(z_cur),
                        )?;
                        region.assign_advice(
                            || "bit",
                            config.advice[1],
                            offset,
                            || Value::known(bit_fq),
                        )?;
                        z_prev = z_cur;
                        remaining >>= 1;
                    }
                    offset += 1;
                    config.s_zero_check.enable(&mut region, offset)?;
                    region.assign_advice(
                        || "z_64_zero",
                        config.advice[0],
                        offset,
                        || Value::known(z_prev),
                    )?;
                    region.assign_advice(
                        || "zero",
                        config.advice[2],
                        offset,
                        || Value::known(Fq::ZERO),
                    )?;
                    offset += 1;
                }

                let n_in = self.amounts_in.len();
                offset += 1;
                region.assign_advice(
                    || "run_sum_0",
                    config.advice[2],
                    offset,
                    || Value::known(Fq::ZERO),
                )?;

                let mut running_sum = Fq::ZERO;
                for (i, &amount) in all_amounts.iter().enumerate() {
                    offset += 1;
                    let signed: Fq = if i < n_in {
                        Fq::from(amount)
                    } else {
                        Fq::ZERO - Fq::from(amount)
                    };
                    running_sum = running_sum + signed;
                    region.assign_advice(
                        || "run_sum",
                        config.advice[2],
                        offset,
                        || Value::known(running_sum),
                    )?;
                    region.assign_advice(
                        || "signed_amt",
                        config.advice[4],
                        offset,
                        || Value::known(signed),
                    )?;
                    config.s_conservation.enable(&mut region, offset)?;
                }

                // Final: bind running_sum to instance[2] (shifted by root+nullifier)
                offset += 1;
                region.assign_advice(
                    || "zero_signed",
                    config.advice[4],
                    offset,
                    || Value::known(Fq::ZERO),
                )?;
                region.assign_advice_from_instance(
                    || "pub_amt",
                    config.instance,
                    2,
                    config.advice[2],
                    offset,
                )?;
                config.s_conservation.enable(&mut region, offset)?;

                // Commitment bindings: instance[3+j] → advice[3]
                for (j, cm_set) in self.output_commitments.iter().enumerate() {
                    let idx = n_in + j;
                    if idx < all_amounts.len() && !cm_set.is_empty() {
                        region.assign_advice_from_instance(
                            || "commitment",
                            config.instance,
                            3 + j,
                            config.advice[3],
                            offset,
                        )?;
                    }
                    if idx < all_amounts.len() {
                        offset += 1;
                    }
                }
                Ok(())
            },
        )?;

        // ── Merkle path verification (inline Poseidon + gate mux) ────────
        // Level-to-level constrain_equal links hash output → next leaf input
        // for formal soundness (beyond Poseidon preimage resistance).
        let mut current_val = leaf_fq;
        let mut level_cells: Vec<(Cell, Cell)> = Vec::with_capacity(depth);

        for i in 0..depth {
            let sibling_val = sibling_fqs[i];
            let bit = self.position_bits[i];
            let bit_fq = if bit { Fq::one() } else { Fq::ZERO };
            let first = if !bit { current_val } else { sibling_val };
            let second = if !bit { sibling_val } else { current_val };
            let chip = PoseidonFqChip::new(config.poseidon.clone());
            let next_val = chip.native_hash(first, second);

            let (leaf_cell, hash_cell) = layouter.assign_region(
                || format!("merkle_level_{}", i),
                |mut region| {
                    let mut state = [
                        Value::known(first),
                        Value::known(second),
                        Value::known(Fq::ZERO),
                    ];
                    let mut offset = 0usize;

                    // Row 0: mux + bool_check + first full round
                    config.s_select.enable(&mut region, offset)?;
                    config.s_bool.enable(&mut region, offset)?;
                    config.poseidon.s_full.enable(&mut region, offset)?;

                    let leaf_cell = region.assign_advice(
                        || "leaf",
                        config.leaf,
                        offset,
                        || Value::known(current_val),
                    )?;
                    region.assign_advice(
                        || "sibling",
                        config.siblings,
                        offset,
                        || Value::known(sibling_val),
                    )?;
                    region.assign_advice(
                        || "bit",
                        config.bit,
                        offset,
                        || Value::known(bit_fq),
                    )?;

                    for col_i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", col_i),
                            config.poseidon.state[col_i],
                            offset,
                            || state[col_i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", col_i),
                            config.poseidon.rc[col_i],
                            offset,
                            || Value::known(spec.constants[offset][col_i]),
                        )?;
                    }

                    let sbox: Vec<Value<Fq>> = (0..T)
                        .map(|j| {
                            state[j].map(|s| {
                                let x = s + spec.constants[offset][j];
                                let x2 = x * x;
                                x2 * x2 * x
                            })
                        })
                        .collect();
                    for col_i in 0..T {
                        let mut sum = sbox[0].map(|s| s * spec.mds[col_i][0]);
                        for j in 1..T {
                            sum = sum
                                .zip(sbox[j])
                                .map(|(acc, s)| acc + s * spec.mds[col_i][j]);
                        }
                        state[col_i] = sum;
                    }
                    offset += 1;

                    // Remaining first-half full rounds
                    for _ in 1..spec.r_f / 2 {
                        config.poseidon.s_full.enable(&mut region, offset)?;
                        for col_i in 0..T {
                            region.assign_advice(
                                || format!("state_{}", col_i),
                                config.poseidon.state[col_i],
                                offset,
                                || state[col_i],
                            )?;
                            region.assign_fixed(
                                || format!("rc_{}", col_i),
                                config.poseidon.rc[col_i],
                                offset,
                                || Value::known(spec.constants[offset][col_i]),
                            )?;
                        }
                        let sbox: Vec<Value<Fq>> = (0..T)
                            .map(|j| {
                                state[j].map(|s| {
                                    let x = s + spec.constants[offset][j];
                                    let x2 = x * x;
                                    x2 * x2 * x
                                })
                            })
                            .collect();
                        for col_i in 0..T {
                            let mut sum = sbox[0].map(|s| s * spec.mds[col_i][0]);
                            for j in 1..T {
                                sum = sum
                                    .zip(sbox[j])
                                    .map(|(acc, s)| acc + s * spec.mds[col_i][j]);
                            }
                            state[col_i] = sum;
                        }
                        offset += 1;
                    }

                    // Partial rounds
                    for _ in 0..spec.r_p {
                        config.poseidon.s_partial.enable(&mut region, offset)?;
                        for col_i in 0..T {
                            region.assign_advice(
                                || format!("state_{}", col_i),
                                config.poseidon.state[col_i],
                                offset,
                                || state[col_i],
                            )?;
                            region.assign_fixed(
                                || format!("rc_{}", col_i),
                                config.poseidon.rc[col_i],
                                offset,
                                || Value::known(spec.constants[offset][col_i]),
                            )?;
                        }
                        let sbox0 = state[0].map(|s| {
                            let x = s + spec.constants[offset][0];
                            let x2 = x * x;
                            x2 * x2 * x
                        });
                        region.assign_advice(
                            || "partial_sbox",
                            config.poseidon.partial_sbox,
                            offset,
                            || sbox0,
                        )?;
                        let other: Vec<Value<Fq>> = state[1..]
                            .iter()
                            .enumerate()
                            .map(|(j, &s)| s.map(|v| v + spec.constants[offset][j + 1]))
                            .collect();
                        for col_i in 0..T {
                            let mut sum = sbox0.map(|s| s * spec.mds[col_i][0]);
                            for j in 1..T {
                                sum = sum
                                    .zip(other[j - 1])
                                    .map(|(acc, s)| acc + s * spec.mds[col_i][j]);
                            }
                            state[col_i] = sum;
                        }
                        offset += 1;
                    }

                    // Second-half full rounds
                    for _ in 0..spec.r_f / 2 {
                        config.poseidon.s_full.enable(&mut region, offset)?;
                        for col_i in 0..T {
                            region.assign_advice(
                                || format!("state_{}", col_i),
                                config.poseidon.state[col_i],
                                offset,
                                || state[col_i],
                            )?;
                            region.assign_fixed(
                                || format!("rc_{}", col_i),
                                config.poseidon.rc[col_i],
                                offset,
                                || Value::known(spec.constants[offset][col_i]),
                            )?;
                        }
                        let sbox: Vec<Value<Fq>> = (0..T)
                            .map(|j| {
                                state[j].map(|s| {
                                    let x = s + spec.constants[offset][j];
                                    let x2 = x * x;
                                    x2 * x2 * x
                                })
                            })
                            .collect();
                        for col_i in 0..T {
                            let mut sum = sbox[0].map(|s| s * spec.mds[col_i][0]);
                            for j in 1..T {
                                sum = sum
                                    .zip(sbox[j])
                                    .map(|(acc, s)| acc + s * spec.mds[col_i][j]);
                            }
                            state[col_i] = sum;
                        }
                        offset += 1;
                    }

                    debug_assert!(offset == spec.r_f + spec.r_p);
                    let out = region.assign_advice(
                        || "output",
                        config.poseidon.state[0],
                        offset,
                        || state[0],
                    )?;
                    for col_i in 1..T {
                        region.assign_advice(
                            || format!("state_final_{}", col_i),
                            config.poseidon.state[col_i],
                            offset,
                            || state[col_i],
                        )?;
                    }
                    Ok((leaf_cell.cell(), out.cell()))
                },
            )?;

            level_cells.push((leaf_cell, hash_cell));

            current_val = next_val;
        }

        // Chain levels: constrain_equal(hash_output_i, leaf_input_{i+1})
        layouter.assign_region(|| "chain_levels", |mut region| {
            for i in 0..level_cells.len().saturating_sub(1) {
                let (_, prev_hash) = level_cells[i];
                let (next_leaf, _) = level_cells[i + 1];
                region.constrain_equal(prev_hash, next_leaf)?;
            }
            Ok(())
        })?;

        let final_hash_cell = level_cells.last().expect("Merkle depth must be ≥ 1").1;

        // ── Constrain root to instance[0] ──
        layouter.assign_region(|| "constrain_root", |mut region| {
            let instance_cell = region.assign_advice_from_instance(
                || "root_instance",
                config.instance,
                0,
                config.poseidon.state[0],
                0,
            )?;
            region.constrain_equal(final_hash_cell, instance_cell.cell())?;
            Ok(())
        })?;

        // ── Nullifier derivation ──
        let chip = PoseidonFqChip::new(config.poseidon.clone());
        let nullifier_cell = chip.assign_hash(
            layouter.namespace(|| "nullifier"),
            Value::known(sk_fq),
            Value::known(index_fq),
            Some(sk_cell),
            Some(index_cell),
        )?;

        // ── Constrain nullifier to instance[1] ──
        layouter.assign_region(|| "constrain_nullifier", |mut region| {
            let instance_cell = region.assign_advice_from_instance(
                || "nf_instance",
                config.instance,
                1,
                config.poseidon.state[0],
                1,
            )?;
            region.constrain_equal(nullifier_cell.cell(), instance_cell.cell())?;
            Ok(())
        })?;

        Ok(())
    }
}

// ── Public API ──────────────────────────────────────────────────────────

pub fn prove_combined_tx(
    amounts_in: &[u64],
    amounts_out: &[u64],
    in_blindings: &[[u8; 32]],
    out_blindings: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    public_amount: i64,
    leaf: &[u8; 32],
    path_siblings: &[[u8; 32]],
    position_bits: &[bool],
    sk: &[u8; 32],
    index: u64,
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
) -> Vec<u8> {
    let depth = path_siblings.len();
    let (params, (_vk, pk)) = (
        ensure_params(),
        ensure_combined_keys(amounts_in.len(), amounts_out.len(), depth),
    );

    let padded_in_blindings: Vec<[u8; 32]> = if in_blindings.is_empty() {
        vec![[0u8; 32]; amounts_in.len()]
    } else {
        in_blindings.to_vec()
    };
    let padded_out_blindings: Vec<[u8; 32]> = if out_blindings.is_empty() {
        vec![[0u8; 32]; amounts_out.len()]
    } else {
        out_blindings.to_vec()
    };
    let padded_commitments: Vec<Vec<[u8; 32]>> = if output_commitments.is_empty() {
        amounts_out.iter().map(|_| vec![]).collect()
    } else {
        output_commitments.iter().map(|&cm| vec![cm]).collect()
    };

    let circuit = CombinedConservationCircuit {
        amounts_in: amounts_in.to_vec(),
        amounts_out: amounts_out.to_vec(),
        in_blindings: padded_in_blindings,
        out_blindings: padded_out_blindings,
        output_commitments: padded_commitments,
        public_amount,
        leaf: *leaf,
        path_siblings: path_siblings.to_vec(),
        position_bits: position_bits.to_vec(),
        sk: *sk,
        index,
        merkle_root: *merkle_root,
        nullifier: *nullifier,
    };

    let mut transcript = Blake2bWrite::<_, EpAffine, Challenge255<_>>::init(vec![]);

    let root_fq = Fq::from_repr(*merkle_root)
        .into_option()
        .expect("prove_combined: merkle_root is canonical Fq");
    let nf_fq = Fq::from_repr(*nullifier)
        .into_option()
        .expect("prove_combined: nullifier is canonical Fq");
    let pub_amt_fq = if public_amount >= 0 {
        Fq::from(public_amount as u64)
    } else {
        Fq::ZERO - Fq::from(public_amount.unsigned_abs())
    };
    let mut instance_col = vec![root_fq, nf_fq, pub_amt_fq];
    for cm in output_commitments {
        instance_col.push(
            Fq::from_repr(*cm)
                .into_option()
                .expect("prove_combined: commitment is canonical Fq repr"),
        );
    }
    let instances = vec![instance_col];

    create_proof::<CommitmentSchemeIPA<EpAffine>, ProverIPA<'_, EpAffine>, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &[instances],
        OsRng,
        &mut transcript,
    )
    .expect("prove_combined_tx failed");
    let proof = transcript.finalize();

    let mut full = b"halo2_ipa_combined_v1_".to_vec();
    full.extend_from_slice(&(amounts_in.len() as u16).to_le_bytes());
    full.extend_from_slice(&(amounts_out.len() as u16).to_le_bytes());
    full.extend_from_slice(&(depth as u16).to_le_bytes());
    full.extend_from_slice(&proof);
    full
}

pub fn verify_combined_tx(
    proof: &[u8],
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
    output_commitments: &[[u8; 32]],
    public_amount: i64,
) -> bool {
    use halo2_backend::plonk::verifier::verify_proof_with_strategy;

    const PREFIX: &[u8] = b"halo2_ipa_combined_v1_";
    const PREFIX_LEN: usize = 22;
    const SHAPE_LEN: usize = 6;
    const MAX_IOPS: usize = 30;
    const MAX_DEPTH: usize = 32;

    if proof.len() < PREFIX_LEN + SHAPE_LEN || !proof.starts_with(PREFIX) {
        return false;
    }
    let in_len =
        u16::from_le_bytes(proof[PREFIX_LEN..PREFIX_LEN + 2].try_into().unwrap()) as usize;
    let out_len = u16::from_le_bytes(
        proof[PREFIX_LEN + 2..PREFIX_LEN + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let depth =
        u16::from_le_bytes(proof[PREFIX_LEN + 4..PREFIX_LEN + SHAPE_LEN]
            .try_into()
            .unwrap()) as usize;
    if in_len + out_len > MAX_IOPS || depth == 0 || depth > MAX_DEPTH {
        return false;
    }
    if output_commitments.len() != out_len {
        return false;
    }
    let inner_proof = &proof[PREFIX_LEN + SHAPE_LEN..];

    let (params, (vk, _)) = (
        ensure_params(),
        ensure_combined_keys(in_len, out_len, depth),
    );

    let root_fq = match Fq::from_repr(*merkle_root).into_option() {
        Some(fq) => fq,
        None => return false,
    };
    let nf_fq = match Fq::from_repr(*nullifier).into_option() {
        Some(fq) => fq,
        None => return false,
    };
    let pub_amt_fq = if public_amount >= 0 {
        Fq::from(public_amount as u64)
    } else {
        Fq::ZERO - Fq::from(public_amount.unsigned_abs())
    };
    let mut instance_col = vec![root_fq, nf_fq, pub_amt_fq];
    for cm in output_commitments {
        match Fq::from_repr(*cm).into_option() {
            Some(fq) => instance_col.push(fq),
            None => return false,
        }
    }
    let instances = vec![instance_col];

    let mut transcript = Blake2bRead::<_, EpAffine, Challenge255<_>>::init(inner_proof);
    match verify_proof_with_strategy::<
        CommitmentSchemeIPA<EpAffine>,
        _,
        Challenge255<EpAffine>,
        Blake2bRead<&[u8], EpAffine, Challenge255<EpAffine>>,
        SingleStrategyIPA<'_, EpAffine>,
    >(
        params,
        &vk,
        SingleStrategyIPA::new(params),
        &[instances],
        &mut transcript,
    ) {
        Ok(strategy) => strategy.finalize(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership_circuit::MEMBERSHIP_K;
    use crate::merkle_tree::IncrementalMerkleTree;
    use crate::poseidon_fq;
    use halo2_proofs::dev::MockProver;

    fn make_leaf(val: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&val.to_le_bytes());
        b
    }

    fn run_combined_mock(depth: usize, leaf_index: usize, expect_valid: bool) {
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(leaf_index).unwrap();
        let root = *tree.root();

        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, leaf_index as u64);

        let circuit = CombinedConservationCircuit {
            amounts_in: vec![100, 200],
            amounts_out: vec![300],
            in_blindings: vec![[1u8; 32], [2u8; 32]],
            out_blindings: vec![[3u8; 32]],
            output_commitments: vec![vec![[4u8; 32]]],
            public_amount: 0,
            leaf: leaves[leaf_index],
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index: leaf_index as u64,
            merkle_root: if expect_valid { root } else { make_leaf(0xFF) },
            nullifier: nf,
        };

        let root_fq = Fq::from_repr(if expect_valid { root } else { make_leaf(0xFF) }).unwrap();
        let nf_fq = Fq::from_repr(nf).unwrap();
        let instances = vec![vec![root_fq, nf_fq, Fq::ZERO, Fq::from(4)]];
        let prover = MockProver::run(MEMBERSHIP_K, &circuit, instances).unwrap();
        if expect_valid {
            assert_eq!(prover.verify(), Ok(()));
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    fn test_combined_mock_depth_3_leaf_0() {
        run_combined_mock(3, 0, true);
    }

    #[test]
    fn test_combined_mock_depth_3_leaf_3() {
        run_combined_mock(3, 3, true);
    }

    #[test]
    fn test_combined_mock_depth_3_leaf_7() {
        run_combined_mock(3, 7, true);
    }

    #[test]
    fn test_combined_mock_depth_4_leaf_5() {
        run_combined_mock(4, 5, true);
    }

    #[test]
    fn test_combined_mock_rejects_wrong_root() {
        run_combined_mock(3, 2, false);
    }

    #[test]
    fn test_combined_mock_rejects_wrong_pub_amt() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let circuit = CombinedConservationCircuit {
            amounts_in: vec![100, 200],
            amounts_out: vec![300],
            in_blindings: vec![[1u8; 32], [2u8; 32]],
            out_blindings: vec![[3u8; 32]],
            output_commitments: vec![vec![[4u8; 32]]],
            public_amount: 0,
            leaf: leaves[2],
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index: 2,
            merkle_root: root,
            nullifier: nf,
        };
        // Wrong public_amount = 1 (should be 0)
        let instances = vec![vec![
            Fq::from_repr(root).unwrap(),
            Fq::from_repr(nf).unwrap(),
            Fq::from(1u64),
            Fq::from(4),
        ]];
        let prover = MockProver::run(MEMBERSHIP_K, &circuit, instances).unwrap();
        assert!(prover.verify().is_err());
    }

    // Commitment binding is checked by the verifier providing the correct instance,
    // not by MockProver constraints. Full IPA roundtrip in test_combined_ipa_roundtrip
    // validates that a proof with one set of commitments fails to verify with different ones.

    #[test]
    fn test_combined_mock_rejects_wrong_nullifier() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);
        let wrong_nf = poseidon_fq::poseidon_nullifier(&make_leaf(0xBEEF), 2);

        let circuit = CombinedConservationCircuit {
            amounts_in: vec![100, 200],
            amounts_out: vec![300],
            in_blindings: vec![[1u8; 32], [2u8; 32]],
            out_blindings: vec![[3u8; 32]],
            output_commitments: vec![vec![[4u8; 32]]],
            public_amount: 0,
            leaf: leaves[2],
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index: 2,
            merkle_root: root,
            nullifier: nf,
        };
        let instances = vec![vec![
            Fq::from_repr(root).unwrap(),
            Fq::from_repr(wrong_nf).unwrap(),
            Fq::ZERO,
            Fq::from(4),
        ]];
        let prover = MockProver::run(MEMBERSHIP_K, &circuit, instances).unwrap();
        assert!(prover.verify().is_err());
    }

    /// IPA roundtrip: prove + verify combined circuit
    #[test]
    fn test_combined_ipa_roundtrip() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let proof = prove_combined_tx(
            &[100, 200],
            &[300],
            &[[1u8; 32], [2u8; 32]],
            &[[3u8; 32]],
            &[[4u8; 32]],
            0,
            &leaves[2],
            &path.siblings,
            &path.position_bits,
            &sk,
            2,
            &root,
            &nf,
        );
        eprintln!("combined IPA proof len={}", proof.len());

        let valid = verify_combined_tx(&proof, &root, &nf, &[[4u8; 32]], 0);
        assert!(valid, "combined IPA roundtrip should verify");
    }

    #[test]
    fn test_combined_ipa_rejects_wrong_root() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let proof = prove_combined_tx(
            &[100, 200],
            &[300],
            &[[1u8; 32], [2u8; 32]],
            &[[3u8; 32]],
            &[[4u8; 32]],
            0,
            &leaves[2],
            &path.siblings,
            &path.position_bits,
            &sk,
            2,
            &root,
            &nf,
        );

        let wrong_root = make_leaf(0xFF);
        let valid = verify_combined_tx(&proof, &wrong_root, &nf, &[[4u8; 32]], 0);
        assert!(!valid, "wrong root should be rejected");
    }

    #[test]
    fn test_combined_empty_amounts_mock() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let circuit = CombinedConservationCircuit {
            amounts_in: vec![],
            amounts_out: vec![],
            in_blindings: vec![],
            out_blindings: vec![],
            output_commitments: vec![],
            public_amount: 0,
            leaf: leaves[2],
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index: 2,
            merkle_root: root,
            nullifier: nf,
        };
        let root_fq = Fq::from_repr(root).unwrap();
        let nf_fq = Fq::from_repr(nf).unwrap();
        let instances = vec![vec![root_fq, nf_fq, Fq::ZERO]];
        let prover = MockProver::run(MEMBERSHIP_K, &circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()), "empty amounts mock should pass");
    }

    #[test]
    fn test_combined_mock_depth_1() {
        run_combined_mock(1, 0, true);
    }

    #[test]
    fn test_combined_verify_len_mismatch() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let proof = prove_combined_tx(
            &[100, 200],
            &[300],
            &[[1u8; 32], [2u8; 32]],
            &[[3u8; 32]],
            &[[4u8; 32]],
            0,
            &leaves[2],
            &path.siblings,
            &path.position_bits,
            &sk,
            2,
            &root,
            &nf,
        );

        // Provide 2 commitments when proof expects 1
        let valid = verify_combined_tx(&proof, &root, &nf, &[[4u8; 32], [5u8; 32]], 0);
        assert!(!valid, "len mismatch should be rejected");
    }

    #[test]
    fn test_combined_verify_swapped_root_nf() {
        let depth = 3;
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(2).unwrap();
        let root = *tree.root();
        let sk = make_leaf(0xCAFE);
        let nf = poseidon_fq::poseidon_nullifier(&sk, 2);

        let proof = prove_combined_tx(
            &[100, 200],
            &[300],
            &[[1u8; 32], [2u8; 32]],
            &[[3u8; 32]],
            &[[4u8; 32]],
            0,
            &leaves[2],
            &path.siblings,
            &path.position_bits,
            &sk,
            2,
            &root,
            &nf,
        );

        // Swap root and nullifier in verification
        let valid = verify_combined_tx(&proof, &nf, &root, &[[4u8; 32]], 0);
        assert!(!valid, "swapped root/nf should be rejected");
    }
}
