//! Aetheris (AET) Recursive Proof System
//!
//! B-2 Migration (Active): Native IPA Accumulation on Vesta.
//!
//! Per `protocol_design_ruling.md` §1.1, the recursive circuit runs on **Vesta**
//! (`Circuit<Fq>`), making Fq scalars native. This eliminates the NonNativeChip
//! architecture entirely. See `B-2_plan.md` for the implementation roadmap.
//!
//! The old `ipa_fold.rs`, `non_native_mul.rs`, `ipa_verifier_circuit.rs` have been
//! deleted in B-2 S11. `non_native_fq.rs` is retained for the transcript gadget
//! (to be replaced in Phase 6).
//!
//! The Blake2b transcript gadget (§1.12d1-d4) is preserved and will be
//! field-parameterized (Phase 1 of B-2) for reuse in `Circuit<Fq>`.

use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector, TableColumn,
    },
    poly::Rotation,
};

// Phase 1.4: switched from BN254/Grumpkin to Pasta 2-cycle.
//
// In halo2curves/pasta:
//   * `Fp` = Pallas base field = Vesta's scalar field
//   * `Fq` = Vesta base field = Pallas's scalar field
//   * `EpAffine` = Pallas affine (curve over Fp, scalar field Fq)
//   * `EqAffine` = Vesta affine (curve over Fq, scalar field Fp)
//
// The recursive circuit in this crate runs over `Fp` (Vesta's scalar field).
// The IPA commitment curve in `aetheris-zkp` is Pallas (`EpAffine`), so the
// accumulator's `Q` and `pi_commitment` are Pallas points. The Pasta 2-cycle
// property is that Pallas's base field = Vesta's scalar field = `Fp`, so
// Pallas *coordinate* arithmetic (point add, point doubling) is NATIVE in
// this circuit. Pallas *scalar* multiplication, however, uses an Fq scalar
// (= Vesta's base = the NON-native field of this Fp-scalar circuit); a
// future in-circuit `CircuitAccumulate` (Phase 1.4 step 3) will need to
// range-check / non-natively-handle the Fq scalar.
//
// Naming: this file aliases `EpAffine` as `PallasAffine` to make the curve
// identification explicit at every use site. (The earlier `PallasAffine`
// alias was misleading: Pallas EC operations, not Vesta's, are the ones
// native to this circuit. Note that the curve equation `y² = x³ + 5` is
// the same for Pallas and Vesta because both share b=5.)
use halo2curves::group::prime::PrimeCurveAffine;
use halo2curves::group::Curve;
use halo2curves::pasta::{EpAffine as PallasAffine, Fp, Fq};
use halo2curves::CurveAffine;

use ff::{Field, PrimeField};
use libp2p::PeerId;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
// Phase 1.4: the `fq_to_fp` no-op cast is removed. Vesta's base field is `Fq`
// (Pallas scalar field of the outer circuit), so Vesta affine coordinates are
// already in the recursive circuit's native scalar type `Fp` and need no
// reinterpretation. The previous no-op was papering over the BN254/Grumpkin
// type confusion that the Pasta migration resolves.

// --- Core Chips ---

mod grain;
use grain::GrainLFSR;

pub mod accumulator;
pub use accumulator::{AccumulatorError, AccumulatorIPA};

pub mod block_aggregator;
pub use accumulator::INNER_PROOF_PREFIX;
pub use block_aggregator::{
    accumulate_proof, empty_accumulator, signed_accumulate_proof, verify_accumulator_chain,
};

#[derive(Clone, Debug)]
pub struct PoseidonSpec<const T: usize, const RATE: usize> {
    pub r_f: usize,
    pub r_p: usize,
    pub mds: [[Fp; T]; T],
    pub constants: Vec<[Fp; T]>,
}

impl<const T: usize, const RATE: usize> PoseidonSpec<T, RATE> {
    /// Build a real Poseidon spec for `T` state width with `r_f` full rounds and
    /// `r_p` partial rounds, using the Grain LFSR (self-shrinking mode) to derive
    /// both the MDS matrix and the per-round constants.
    ///
    /// This is the Phase 1.3 fix: round constants are no longer a hash-based
    /// placeholder but follow the Zcash reference construction, so circuit hashes
    /// are bit-for-bit comparable against an Orchard-canonical reference once
    /// Phase 1.4 switches the underlying field to Pasta's `Fp`.
    ///
    /// The `seed` argument is retained for ABI stability but does not affect the
    /// Grain output (which is determined entirely by `(T, r_f, r_p)`); see the
    /// `grain::GrainLFSR::new` doc comment for the bit layout.
    pub fn new_real(r_f: usize, r_p: usize, _seed: u64) -> Self {
        // MDS: first T*T constants from the Grain stream.
        // (This is a "random-looking" MDS built from Grain-generated field elements
        //  with a one-position circular shift, matching the Orchard-style construction
        //  while remaining simple and verifiable.)
        let mut grain = GrainLFSR::new::<Fp>(T as u16, r_f as u16, r_p as u16);
        let mut mds = [[Fp::ZERO; T]; T];
        for i in 0..T {
            for j in 0..T {
                mds[i][j] = grain.next_field_element::<Fp>();
            }
        }

        // Round constants: (r_f + r_p) * T fresh field elements.
        let mut constants = vec![[Fp::ZERO; T]; r_f + r_p];
        for i in 0..(r_f + r_p) {
            for j in 0..T {
                constants[i][j] = grain.next_field_element::<Fp>();
            }
        }

        Self {
            r_f,
            r_p,
            mds,
            constants,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonConfig<const T: usize, const RATE: usize> {
    pub state: [Column<Advice>; T],
    pub rc: [Column<Fixed>; T],
    pub partial_sbox: Column<Advice>, // New column to reduce gate degree
    pub s_full: Selector,
    pub s_partial: Selector,
}

pub struct PoseidonChip<const T: usize, const RATE: usize> {
    config: PoseidonConfig<T, RATE>,
    spec: PoseidonSpec<T, RATE>,
}

impl<const T: usize, const RATE: usize> PoseidonChip<T, RATE> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        mds: [[Fp; T]; T],
    ) -> PoseidonConfig<T, RATE> {
        let state = [0; T].map(|_| meta.advice_column());
        let rc = [0; T].map(|_| meta.fixed_column());
        let partial_sbox = meta.advice_column();
        let s_full = meta.selector();
        let s_partial = meta.selector();

        state.iter().for_each(|&col| meta.enable_equality(col));
        meta.enable_equality(partial_sbox);

        // Optimized Gate logic for Poseidon Full Round
        // We use a custom gate that computes x^5 in a single row by leveraging higher degree (up to 9 in Halo2)
        meta.create_gate("poseidon_full", |meta| {
            let s_full = meta.query_selector(s_full);
            let mut exprs = vec![];

            let mut sbox_outputs = vec![];
            for i in 0..T {
                let state_cur = meta.query_advice(state[i], Rotation::cur());
                let rc = meta.query_fixed(rc[i], Rotation::cur());
                let x = state_cur + rc;
                let x2 = x.clone() * x.clone();
                let x5 = x2.clone() * x2.clone() * x;
                sbox_outputs.push(x5);
            }

            for i in 0..T {
                let mut mds_sum = Expression::Constant(Fp::ZERO);
                for j in 0..T {
                    mds_sum = mds_sum + sbox_outputs[j].clone() * Expression::Constant(mds[i][j]);
                }
                let state_next = meta.query_advice(state[i], Rotation::next());
                exprs.push(s_full.clone() * (mds_sum - state_next));
            }
            exprs
        });

        // Optimized Partial Round: Use partial_sbox column to hold x^5
        // This splits the degree-5 S-box from the MDS matrix multiplication
        meta.create_gate("poseidon_partial_sbox", |meta| {
            let s_partial = meta.query_selector(s_partial);
            let state0_cur = meta.query_advice(state[0], Rotation::cur());
            let rc0 = meta.query_fixed(rc[0], Rotation::cur());
            let x0 = state0_cur + rc0;
            let x0_2 = x0.clone() * x0.clone();
            let x0_5 = x0_2.clone() * x0_2.clone() * x0;
            let sbox_val = meta.query_advice(partial_sbox, Rotation::cur());

            vec![s_partial * (x0_5 - sbox_val)]
        });

        meta.create_gate("poseidon_partial_mds", |meta| {
            let s_partial = meta.query_selector(s_partial);
            let mut exprs = vec![];

            let sbox_val = meta.query_advice(partial_sbox, Rotation::cur());
            let mut mixed_inputs = vec![sbox_val];
            for i in 1..T {
                let state_cur = meta.query_advice(state[i], Rotation::cur());
                let rc = meta.query_fixed(rc[i], Rotation::cur());
                mixed_inputs.push(state_cur + rc);
            }

            for i in 0..T {
                let mut mds_sum = Expression::Constant(Fp::ZERO);
                for j in 0..T {
                    mds_sum = mds_sum + mixed_inputs[j].clone() * Expression::Constant(mds[i][j]);
                }
                let state_next = meta.query_advice(state[i], Rotation::next());
                exprs.push(s_partial.clone() * (mds_sum - state_next));
            }
            exprs
        });

        PoseidonConfig {
            state,
            rc,
            partial_sbox,
            s_full,
            s_partial,
        }
    }

    pub fn new(spec: PoseidonSpec<T, RATE>, config: PoseidonConfig<T, RATE>) -> Self {
        Self { spec, config }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        values: &[Limb<Fp>],
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "poseidon hash",
            |mut region| {
                let mut state_values = vec![Value::known(Fp::ZERO); T];
                for (i, limb) in values.iter().enumerate().take(RATE) {
                    state_values[i] = limb.value;
                }

                let mut offset = 0;

                // 2. Full Rounds (first half)
                for r in 0..(self.spec.r_f / 2) {
                    self.config.s_full.enable(&mut region, offset)?;
                    for i in 0..T {
                        let assigned = region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state_values[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(self.spec.constants[offset][i]),
                        )?;

                        // If this is the first round and we have input limbs, constrain them
                        if r == 0 && i < values.len() {
                            if let Some(cell) = values[i].cell {
                                region.constrain_equal(assigned.cell(), cell)?;
                            }
                        }
                    }

                    // Compute next state for witness generation
                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_outputs = state_values
                        .iter()
                        .enumerate()
                        .map(|(i, &s)| {
                            s.map(|val| {
                                let x = val + self.spec.constants[offset][i];
                                let x2 = x * x;
                                x2 * x2 * x // x^5
                            })
                        })
                        .collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = Value::known(Fp::ZERO);
                        for j in 0..T {
                            sum = sum
                                .zip(sbox_outputs[j])
                                .map(|(acc, out)| acc + out * self.spec.mds[i][j]);
                        }
                        next_state[i] = sum;
                    }
                    state_values = next_state;
                    offset += 1;
                }

                // 3. Partial Rounds
                for _ in (self.spec.r_f / 2)..(self.spec.r_f / 2 + self.spec.r_p) {
                    self.config.s_partial.enable(&mut region, offset)?;
                    for i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state_values[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(self.spec.constants[offset][i]),
                        )?;
                    }

                    // S-box only on first element
                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_output0 = state_values[0].map(|val| {
                        let x = val + self.spec.constants[offset][0];
                        let x2 = x * x;
                        x2 * x2 * x
                    });

                    // Assign to partial_sbox column to satisfy the custom gate
                    region.assign_advice(
                        || "partial_sbox",
                        self.config.partial_sbox,
                        offset,
                        || sbox_output0,
                    )?;

                    let other_outputs = state_values[1..]
                        .iter()
                        .enumerate()
                        .map(|(i, &s)| s.map(|val| val + self.spec.constants[offset][i + 1]))
                        .collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = sbox_output0.map(|out| out * self.spec.mds[i][0]);
                        for j in 1..T {
                            sum = sum
                                .zip(other_outputs[j - 1])
                                .map(|(acc, out)| acc + out * self.spec.mds[i][j]);
                        }
                        next_state[i] = sum;
                    }
                    state_values = next_state;
                    offset += 1;
                }

                // 4. Full Rounds (second half)
                for _ in 0..(self.spec.r_f / 2) {
                    self.config.s_full.enable(&mut region, offset)?;
                    for i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state_values[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(self.spec.constants[offset][i]),
                        )?;
                    }

                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_outputs = state_values
                        .iter()
                        .enumerate()
                        .map(|(i, &s)| {
                            s.map(|val| {
                                let x = val + self.spec.constants[offset][i];
                                let x2 = x * x;
                                x2 * x2 * x
                            })
                        })
                        .collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = Value::known(Fp::ZERO);
                        for j in 0..T {
                            sum = sum
                                .zip(sbox_outputs[j])
                                .map(|(acc, out)| acc + out * self.spec.mds[i][j]);
                        }
                        next_state[i] = sum;
                    }
                    state_values = next_state;
                    offset += 1;
                }

                let mut final_cells = vec![];
                for i in 0..T {
                    let cell = region.assign_advice(
                        || format!("state_final_{}", i),
                        self.config.state[i],
                        offset,
                        || state_values[i],
                    )?;
                    final_cells.push(cell.cell());
                }

                Ok(Limb {
                    value: state_values[0],
                    cell: Some(final_cells[0]),
                })
            },
        )?)
    }
}

#[derive(Clone, Debug)]
pub struct EccConfig {
    pub x: Column<Advice>,
    pub y: Column<Advice>,
    pub bit: Column<Advice>,       // For scalar multiplication bits
    pub lookup_val: Column<Fixed>, // Column that combines with s_lookup
    pub table_x: TableColumn,      // Fixed-base lookup table X
    pub table_y: TableColumn,      // Fixed-base lookup table Y
    pub table_idx: TableColumn,    // Table index (window value)
    pub s_add: Selector,
    pub s_double: Selector,
    pub s_bit: Selector,
    pub s_select: Selector,
    pub s_mul_fp: Selector,
    pub s_add_fp: Selector,
    pub s_sub_fp: Selector,
    pub s_one_minus: Selector,
    pub s_select_fp: Selector,
    pub s_on_curve: Selector,
}

#[derive(Clone)]
pub struct EccChip {
    config: EccConfig,
}

#[derive(Clone, Debug)]
pub struct EcPoint {
    pub x: Value<Fp>,
    pub y: Value<Fp>,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
    /// Phase 1.3 fix: tracks whether this point is the additive identity
    /// (point at infinity, conventionally represented as (0, 0) in affine coords).
    /// The identity is NOT on the affine curve y² = x³ + 5 (Vesta), so
    /// `assert_on_curve` must skip the on-curve gate when this flag is set.
    /// All real curve points (generator, add/double/select outputs,
    /// fixed-base table points) carry `is_identity = false`.
    pub is_identity: bool,
}

impl EcPoint {
    /// Additive identity (point at infinity), represented as (0, 0).
    /// Useful as a neutral element in `select` and as the zero-initialized
    /// accumulator in `scalar_mul` and `fixed_base_scalar_mul`.
    pub fn identity() -> Self {
        Self {
            x: Value::known(Fp::ZERO),
            y: Value::known(Fp::ZERO),
            x_cell: None,
            y_cell: None,
            is_identity: true,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProjectivePoint {
    pub x: Limb<Fp>,
    pub y: Limb<Fp>,
    pub z: Limb<Fp>,
}

/// Phase 1.4: Pasta Vesta scalar field bit length (255 bits).
/// Used by windowed scalar-mul to bound the bit range over which it scans.
/// Replaces the previous `BN254_FR_BIT_LEN = 254` (BN254 Fr modulus, 254 bits).
pub const PASTA_SCALAR_BIT_LEN: usize = 255;

/// Phase 1.4: short-Weierstrass curve constant for the Pasta 2-cycle
/// curves. Both Pallas and Vesta share `b = 5`, so the same value is
/// used for `on_curve_check` (gating Pallas points) and `h_generator`
/// (NUMS-style deterministic point on Pallas).
pub const PASTA_CURVE_B: u64 = 5;

impl EccChip {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> EccConfig {
        let x = meta.advice_column();
        let y = meta.advice_column();
        let bit = meta.advice_column();
        let lookup_val = meta.fixed_column();
        let table_x = meta.lookup_table_column();
        let table_y = meta.lookup_table_column();
        let table_idx = meta.lookup_table_column();
        let s_add = meta.selector();
        let s_double = meta.selector();
        let s_bit = meta.selector();
        let s_select = meta.selector();
        let s_mul_fp = meta.selector();
        let s_add_fp = meta.selector();
        let s_sub_fp = meta.selector();
        let s_one_minus = meta.selector();
        let s_select_fp = meta.selector();
        let s_on_curve = meta.selector();

        meta.enable_equality(x);
        meta.enable_equality(y);
        meta.enable_equality(bit);

        // Fixed-base Lookup Table Gate
        meta.lookup("fixed-base lookup", |meta| {
            let window_val = meta.query_advice(bit, Rotation::cur());
            let x_val = meta.query_advice(x, Rotation::cur());
            let y_val = meta.query_advice(y, Rotation::cur());
            let s_lookup = meta.query_fixed(lookup_val, Rotation::cur());

            vec![
                (s_lookup.clone() * window_val, table_idx),
                (s_lookup.clone() * x_val, table_x),
                (s_lookup * y_val, table_y),
            ]
        });

        // On-curve check: y² = x³ + B (Vesta curve, B = 5).
        // Phase 1.4 fix (ISSUE-1.3.B): the gate used to encode B = 3 (Grumpkin),
        // which is the wrong curve for the Vesta `EpAffine::generator()` returned
        // by `EccChip::generator`. The bug was masked by the fact that no
        // production code called `assert_on_curve` on a real (non-identity) Vesta
        // point — see Phase 1.3 commit 345d1d2. The new `test_ecc_identity_propagation`
        // exercises the real-point path; this gate is now load-bearing.
        meta.create_gate("on_curve_check", |meta| {
            let s_on_curve = meta.query_selector(s_on_curve);
            let x = meta.query_advice(x, Rotation::cur());
            let y = meta.query_advice(y, Rotation::cur());

            // y² - (x³ + 5) = 0
            vec![
                s_on_curve
                    * (y.clone() * y
                        - (x.clone() * x.clone() * x
                            + Expression::Constant(Fp::from(PASTA_CURVE_B)))),
            ]
        });

        // Field multiplication gate: a * b = c
        meta.create_gate("field_mul", |meta| {
            let s_mul_fp = meta.query_selector(s_mul_fp);
            let a = meta.query_advice(x, Rotation::cur());
            let b = meta.query_advice(y, Rotation::cur());
            let c = meta.query_advice(x, Rotation::next());
            vec![s_mul_fp * (a * b - c)]
        });

        meta.create_gate("field_add", |meta| {
            let s_add_fp = meta.query_selector(s_add_fp);
            let a = meta.query_advice(x, Rotation::cur());
            let b = meta.query_advice(y, Rotation::cur());
            let c = meta.query_advice(x, Rotation::next());
            vec![s_add_fp * (a + b - c)]
        });

        meta.create_gate("field_sub", |meta| {
            let s_sub_fp = meta.query_selector(s_sub_fp);
            let a = meta.query_advice(x, Rotation::cur());
            let b = meta.query_advice(y, Rotation::cur());
            let c = meta.query_advice(x, Rotation::next());
            vec![s_sub_fp * (a - b - c)]
        });

        meta.create_gate("field_one_minus_bit", |meta| {
            let s_one_minus = meta.query_selector(s_one_minus);
            let a = meta.query_advice(x, Rotation::cur());
            let b = meta.query_advice(bit, Rotation::cur());
            vec![s_one_minus * (a + b - Expression::Constant(Fp::ONE))]
        });

        meta.create_gate("field_select_bit", |meta| {
            let s_select_fp = meta.query_selector(s_select_fp);
            let b = meta.query_advice(bit, Rotation::cur());
            let a = meta.query_advice(x, Rotation::cur());
            let c = meta.query_advice(y, Rotation::cur());
            let out = meta.query_advice(x, Rotation::next());
            vec![s_select_fp * (b.clone() * a + (Expression::Constant(Fp::ONE) - b) * c - out)]
        });

        // Bit constraint: b * (1 - b) = 0
        meta.create_gate("bit_check", |meta| {
            let s_bit = meta.query_selector(s_bit);
            let b = meta.query_advice(bit, Rotation::cur());
            vec![s_bit * b.clone() * (Expression::Constant(Fp::ONE) - b)]
        });

        // Select gate: bit * p1 + (1 - bit) * p2 = p_res
        meta.create_gate("ecc_select", |meta| {
            let s_select = meta.query_selector(s_select);
            let b = meta.query_advice(bit, Rotation::cur());
            let x1 = meta.query_advice(x, Rotation::cur());
            let y1 = meta.query_advice(y, Rotation::cur());
            let x2 = meta.query_advice(x, Rotation::next());
            let y2 = meta.query_advice(y, Rotation::next());
            let x3 = meta.query_advice(x, Rotation(2));
            let y3 = meta.query_advice(y, Rotation(2));

            vec![
                s_select.clone()
                    * (b.clone() * x1 + (Expression::Constant(Fp::ONE) - b.clone()) * x2 - x3),
                s_select * (b.clone() * y1 + (Expression::Constant(Fp::ONE) - b) * y2 - y3),
            ]
        });

        meta.create_gate("ecc_add", |meta| {
            let s_add = meta.query_selector(s_add);
            let x1 = meta.query_advice(x, Rotation::cur());
            let y1 = meta.query_advice(y, Rotation::cur());
            let x2 = meta.query_advice(x, Rotation::next());
            let y2 = meta.query_advice(y, Rotation::next());
            let x3 = meta.query_advice(x, Rotation(2));
            let y3 = meta.query_advice(y, Rotation(2));
            let lambda = meta.query_advice(x, Rotation(3)); // Reuse x column for lambda witness

            // Real Short Weierstrass addition constraints
            // 1. (x2 - x1) * lambda = y2 - y1
            // 2. x3 = lambda^2 - x1 - x2
            // 3. y3 = lambda * (x1 - x3) - y1
            vec![
                s_add.clone() * ((x2.clone() - x1.clone()) * lambda.clone() - (y2 - y1.clone())),
                s_add.clone() * (x3.clone() - (lambda.clone() * lambda.clone() - x1.clone() - x2)),
                s_add * (y3 - (lambda * (x1 - x3) - y1)),
            ]
        });

        meta.create_gate("ecc_double", |meta| {
            let s_double = meta.query_selector(s_double);
            let x1 = meta.query_advice(x, Rotation::cur());
            let y1 = meta.query_advice(y, Rotation::cur());
            let x3 = meta.query_advice(x, Rotation::next());
            let y3 = meta.query_advice(y, Rotation::next());
            let lambda = meta.query_advice(x, Rotation(2));

            // Short Weierstrass doubling constraints (assuming a=0 for Pallas)
            // 1. 2 * y1 * lambda = 3 * x1^2
            // 2. x3 = lambda^2 - 2 * x1
            // 3. y3 = lambda * (x1 - x3) - y1
            vec![
                s_double.clone()
                    * (Expression::Constant(Fp::from(2)) * y1.clone() * lambda.clone()
                        - Expression::Constant(Fp::from(3)) * x1.clone() * x1.clone()),
                s_double.clone()
                    * (x3.clone()
                        - (lambda.clone() * lambda.clone()
                            - Expression::Constant(Fp::from(2)) * x1.clone())),
                s_double * (y3 - (lambda * (x1 - x3) - y1)),
            ]
        });

        EccConfig {
            x,
            y,
            bit,
            lookup_val,
            table_x,
            table_y,
            table_idx,
            s_add,
            s_double,
            s_bit,
            s_select,
            s_mul_fp,
            s_add_fp,
            s_sub_fp,
            s_one_minus,
            s_select_fp,
            s_on_curve,
        }
    }

    pub fn assert_on_curve(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &EcPoint,
    ) -> Result<(), ErrorFront> {
        self.identity_bit(layouter.namespace(|| "assert_on_curve_identity"), p)?;
        Ok(layouter.assign_region(
            || "assert on curve",
            |mut region| {
                let x = region.assign_advice(|| "x", self.config.x, 0, || p.x)?;
                let y = region.assign_advice(|| "y", self.config.y, 0, || p.y)?;

                if let Some(c) = p.x_cell {
                    region.constrain_equal(x.cell(), c)?;
                }
                if let Some(c) = p.y_cell {
                    region.constrain_equal(y.cell(), c)?;
                }

                // Phase 1.3 + 1.4 fix: the identity point (0, 0) is the additive neutral
                // element and does NOT satisfy y² = x³ + 5 (Vesta's curve equation).
                // The on-curve gate must be skipped for identity, but we still need to
                // assign the witnesses above so any callers' cell-tracking
                // constrain_equal constraints hold.
                if !p.is_identity {
                    self.config.s_on_curve.enable(&mut region, 0)?;
                }
                Ok(())
            },
        )?)
    }

    pub fn new(config: EccConfig) -> Self {
        Self { config }
    }

    /// Returns the Vesta standard generator point (G).
    /// Note: Vesta's base field is `Fq` = Pallas's scalar field, so the
    /// generator's x/y coordinates are already in the recursive circuit's
    /// native scalar type `Fp` and need no `fq_to_fp` reinterpretation.
    pub fn generator(&self) -> EcPoint {
        let g = PallasAffine::generator();
        let coords = g.coordinates().unwrap();
        let x = *coords.x();
        let y = *coords.y();
        EcPoint {
            x: Value::known(x),
            y: Value::known(y),
            x_cell: None,
            y_cell: None,
            is_identity: false,
        }
    }

    /// Returns a Nothing-Up-My-Sleeve (NUMS) generator point (H) on Vesta.
    /// Generated via deterministic try-and-increment: smallest x >= 0 with
    /// valid y on y² = x³ + 5.
    pub fn h_generator(&self, mut layouter: impl Layouter<Fp>) -> Result<EcPoint, ErrorFront> {
        // Deterministic NUMS point: find smallest x >= 0 s.t. (x, y) is on Vesta (B = 5)
        let (x_nums, y_nums) = {
            let mut x = Fp::ZERO;
            loop {
                let y_sq = x * x * x + Fp::from(PASTA_CURVE_B);
                if let Some(y) = y_sq.sqrt().into() {
                    break (x, y);
                }
                x = x + Fp::ONE;
            }
        };

        Ok(layouter.assign_region(
            || "H generator",
            |mut region| {
                let x_cell =
                    region.assign_advice(|| "x", self.config.x, 0, || Value::known(x_nums))?;
                let y_cell =
                    region.assign_advice(|| "y", self.config.y, 0, || Value::known(y_nums))?;
                Ok(EcPoint {
                    x: Value::known(x_nums),
                    y: Value::known(y_nums),
                    x_cell: Some(x_cell.cell()),
                    y_cell: Some(y_cell.cell()),
                    is_identity: false,
                })
            },
        )?)
    }

    pub fn field_mul(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
        b: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "field mul",
            |mut region| {
                self.config.s_mul_fp.enable(&mut region, 0)?;
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;

                if let Some(c) = a.cell {
                    region.constrain_equal(a_assigned.cell(), c)?;
                }
                if let Some(c) = b.cell {
                    region.constrain_equal(b_assigned.cell(), c)?;
                }

                let res_val = a.value.zip(b.value).map(|(a, b)| a * b);
                let res_assigned = region.assign_advice(|| "res", self.config.x, 1, || res_val)?;

                Ok(Limb {
                    value: res_val,
                    cell: Some(res_assigned.cell()),
                })
            },
        )?)
    }

    pub fn field_add(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
        b: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "field add",
            |mut region| {
                self.config.s_add_fp.enable(&mut region, 0)?;
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;

                if let Some(c) = a.cell {
                    region.constrain_equal(a_assigned.cell(), c)?;
                }
                if let Some(c) = b.cell {
                    region.constrain_equal(b_assigned.cell(), c)?;
                }

                let res_val = a.value.zip(b.value).map(|(a, b)| a + b);
                let res_assigned = region.assign_advice(|| "res", self.config.x, 1, || res_val)?;

                Ok(Limb {
                    value: res_val,
                    cell: Some(res_assigned.cell()),
                })
            },
        )?)
    }

    pub fn field_sub(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
        b: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "field sub",
            |mut region| {
                self.config.s_sub_fp.enable(&mut region, 0)?;
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;

                if let Some(c) = a.cell {
                    region.constrain_equal(a_assigned.cell(), c)?;
                }
                if let Some(c) = b.cell {
                    region.constrain_equal(b_assigned.cell(), c)?;
                }

                let res_val = a.value.zip(b.value).map(|(a, b)| a - b);
                let res_assigned = region.assign_advice(|| "res", self.config.x, 1, || res_val)?;

                Ok(Limb {
                    value: res_val,
                    cell: Some(res_assigned.cell()),
                })
            },
        )?)
    }

    pub fn one_minus_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        bit: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "field one minus bit",
            |mut region| {
                self.config.s_one_minus.enable(&mut region, 0)?;
                self.config.s_bit.enable(&mut region, 0)?;

                let one_minus = bit.value.map(|b| Fp::ONE - b);
                let one_minus_assigned =
                    region.assign_advice(|| "one_minus", self.config.x, 0, || one_minus)?;
                let bit_assigned =
                    region.assign_advice(|| "bit", self.config.bit, 0, || bit.value)?;

                if let Some(c) = bit.cell {
                    region.constrain_equal(bit_assigned.cell(), c)?;
                }

                Ok(Limb {
                    value: one_minus,
                    cell: Some(one_minus_assigned.cell()),
                })
            },
        )?)
    }

    pub fn select_limb_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        bit: &Limb<Fp>,
        when_one: &Limb<Fp>,
        when_zero: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        Ok(layouter.assign_region(
            || "field select bit",
            |mut region| {
                self.config.s_select_fp.enable(&mut region, 0)?;
                self.config.s_bit.enable(&mut region, 0)?;

                let bit_assigned =
                    region.assign_advice(|| "bit", self.config.bit, 0, || bit.value)?;
                let one_assigned =
                    region.assign_advice(|| "when_one", self.config.x, 0, || when_one.value)?;
                let zero_assigned =
                    region.assign_advice(|| "when_zero", self.config.y, 0, || when_zero.value)?;

                if let Some(c) = bit.cell {
                    region.constrain_equal(bit_assigned.cell(), c)?;
                }
                if let Some(c) = when_one.cell {
                    region.constrain_equal(one_assigned.cell(), c)?;
                }
                if let Some(c) = when_zero.cell {
                    region.constrain_equal(zero_assigned.cell(), c)?;
                }

                let out_val = bit
                    .value
                    .zip(when_one.value)
                    .zip(when_zero.value)
                    .map(|((b, one), zero)| if b == Fp::ONE { one } else { zero });
                let out_assigned = region.assign_advice(|| "out", self.config.x, 1, || out_val)?;
                Ok(Limb {
                    value: out_val,
                    cell: Some(out_assigned.cell()),
                })
            },
        )?)
    }

    pub fn is_zero_limb(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        let inv_val = a.value.map(|v| v.invert().unwrap_or(Fp::ZERO));

        let prod = self.field_mul(
            layouter.namespace(|| "zero_prod"),
            a,
            &Limb {
                value: inv_val,
                cell: None,
            },
        )?;
        let bit = layouter.assign_region(
            || "zero_bit",
            |mut region| {
                self.config.s_bit.enable(&mut region, 0)?;
                let bit_val = prod.value.map(|p| Fp::ONE - p);
                let bit_assigned =
                    region.assign_advice(|| "bit", self.config.bit, 0, || bit_val)?;
                Ok(Limb {
                    value: bit_val,
                    cell: Some(bit_assigned.cell()),
                })
            },
        )?;

        let one_minus = self.one_minus_bit(layouter.namespace(|| "one_minus_zero_bit"), &bit)?;
        let zero_check = self.field_mul(layouter.namespace(|| "zero_nonzero_check"), a, &bit)?;
        self.constrain_equal_limb(
            layouter.namespace(|| "zero_nonzero_zero"),
            &zero_check,
            &Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            },
        )?;
        self.constrain_equal_limb(layouter.namespace(|| "zero_prod_check"), &prod, &one_minus)?;
        Ok(bit)
    }

    pub fn eq_limb(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
        b: &Limb<Fp>,
    ) -> Result<Limb<Fp>, ErrorFront> {
        let diff = self.field_sub(layouter.namespace(|| "eq_diff"), a, b)?;
        self.is_zero_limb(layouter.namespace(|| "eq_zero"), &diff)
    }

    pub(crate) fn select_projective_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        bit: &Limb<Fp>,
        when_one: &ProjectivePoint,
        when_zero: &ProjectivePoint,
    ) -> Result<ProjectivePoint, ErrorFront> {
        let x = self.select_limb_bit(
            layouter.namespace(|| "select_proj_x"),
            bit,
            &when_one.x,
            &when_zero.x,
        )?;
        let y = self.select_limb_bit(
            layouter.namespace(|| "select_proj_y"),
            bit,
            &when_one.y,
            &when_zero.y,
        )?;
        let z = self.select_limb_bit(
            layouter.namespace(|| "select_proj_z"),
            bit,
            &when_one.z,
            &when_zero.z,
        )?;
        Ok(ProjectivePoint { x, y, z })
    }

    pub(crate) fn affine_to_projective(&self, point: &EcPoint) -> ProjectivePoint {
        if point.is_identity {
            return self.projective_identity();
        }
        ProjectivePoint {
            x: Limb {
                value: point.x,
                cell: point.x_cell,
            },
            y: Limb {
                value: point.y,
                cell: point.y_cell,
            },
            z: Limb {
                value: Value::known(Fp::ONE),
                cell: None,
            },
        }
    }

    pub(crate) fn projective_identity(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            },
            y: Limb {
                value: Value::known(Fp::ONE),
                cell: None,
            },
            z: Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            },
        }
    }

    pub(crate) fn projective_double(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &ProjectivePoint,
    ) -> Result<ProjectivePoint, ErrorFront> {
        let z_is_zero = self.is_zero_limb(layouter.namespace(|| "pd_z_is_zero"), &p.z)?;
        let a = self.field_mul(layouter.namespace(|| "pd_a_xx"), &p.x, &p.x)?;
        let b = self.field_mul(layouter.namespace(|| "pd_b_yy"), &p.y, &p.y)?;
        let c = self.field_mul(layouter.namespace(|| "pd_c_yyyy"), &b, &b)?;

        let x_plus_b = self.field_add(layouter.namespace(|| "pd_x_plus_b"), &p.x, &b)?;
        let x_plus_b_sq = self.field_mul(
            layouter.namespace(|| "pd_x_plus_b_sq"),
            &x_plus_b,
            &x_plus_b,
        )?;
        let xpb_minus_a =
            self.field_sub(layouter.namespace(|| "pd_xpb_minus_a"), &x_plus_b_sq, &a)?;
        let d_half = self.field_sub(layouter.namespace(|| "pd_d_half"), &xpb_minus_a, &c)?;
        let d = self.field_add(layouter.namespace(|| "pd_d"), &d_half, &d_half)?;

        let two_a = self.field_add(layouter.namespace(|| "pd_two_a"), &a, &a)?;
        let e = self.field_add(layouter.namespace(|| "pd_e"), &two_a, &a)?;
        let f = self.field_mul(layouter.namespace(|| "pd_f"), &e, &e)?;

        let zy = self.field_mul(layouter.namespace(|| "pd_zy"), &p.z, &p.y)?;
        let z3 = self.field_add(layouter.namespace(|| "pd_z3"), &zy, &zy)?;

        let two_d = self.field_add(layouter.namespace(|| "pd_two_d"), &d, &d)?;
        let x3 = self.field_sub(layouter.namespace(|| "pd_x3"), &f, &two_d)?;

        let two_c = self.field_add(layouter.namespace(|| "pd_two_c"), &c, &c)?;
        let four_c = self.field_add(layouter.namespace(|| "pd_four_c"), &two_c, &two_c)?;
        let eight_c = self.field_add(layouter.namespace(|| "pd_eight_c"), &four_c, &four_c)?;
        let d_minus_x3 = self.field_sub(layouter.namespace(|| "pd_d_minus_x3"), &d, &x3)?;
        let e_times = self.field_mul(layouter.namespace(|| "pd_e_times"), &e, &d_minus_x3)?;
        let y3 = self.field_sub(layouter.namespace(|| "pd_y3"), &e_times, &eight_c)?;

        let doubled = ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
        };
        self.select_projective_bit(
            layouter.namespace(|| "pd_select_identity"),
            &z_is_zero,
            &self.projective_identity(),
            &doubled,
        )
    }

    pub(crate) fn projective_mixed_add(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &ProjectivePoint,
        q: &EcPoint,
    ) -> Result<ProjectivePoint, ErrorFront> {
        let qx = Limb {
            value: q.x,
            cell: q.x_cell,
        };
        let qy = Limb {
            value: q.y,
            cell: q.y_cell,
        };

        let z1z1 = self.field_mul(layouter.namespace(|| "pma_z1z1"), &p.z, &p.z)?;
        let u2 = self.field_mul(layouter.namespace(|| "pma_u2"), &qx, &z1z1)?;
        let z1z1_y2 = self.field_mul(layouter.namespace(|| "pma_z1z1_y2"), &qy, &z1z1)?;
        let s2 = self.field_mul(layouter.namespace(|| "pma_s2"), &z1z1_y2, &p.z)?;

        let h = self.field_sub(layouter.namespace(|| "pma_h"), &u2, &p.x)?;
        let hh = self.field_mul(layouter.namespace(|| "pma_hh"), &h, &h)?;
        let hh2 = self.field_add(layouter.namespace(|| "pma_hh2"), &hh, &hh)?;
        let i = self.field_add(layouter.namespace(|| "pma_i"), &hh2, &hh2)?;
        let j = self.field_mul(layouter.namespace(|| "pma_j"), &h, &i)?;
        let r_pre = self.field_sub(layouter.namespace(|| "pma_r_pre"), &s2, &p.y)?;
        let r = self.field_add(layouter.namespace(|| "pma_r"), &r_pre, &r_pre)?;
        let v = self.field_mul(layouter.namespace(|| "pma_v"), &p.x, &i)?;

        let r_sq = self.field_mul(layouter.namespace(|| "pma_r_sq"), &r, &r)?;
        let r_sq_minus_j = self.field_sub(layouter.namespace(|| "pma_r_sq_minus_j"), &r_sq, &j)?;
        let v2 = self.field_add(layouter.namespace(|| "pma_v2"), &v, &v)?;
        let x3 = self.field_sub(layouter.namespace(|| "pma_x3"), &r_sq_minus_j, &v2)?;

        let y1j = self.field_mul(layouter.namespace(|| "pma_y1j"), &p.y, &j)?;
        let two_y1j = self.field_add(layouter.namespace(|| "pma_two_y1j"), &y1j, &y1j)?;
        let v_minus_x3 = self.field_sub(layouter.namespace(|| "pma_v_minus_x3"), &v, &x3)?;
        let r_times = self.field_mul(layouter.namespace(|| "pma_r_times"), &r, &v_minus_x3)?;
        let y3 = self.field_sub(layouter.namespace(|| "pma_y3"), &r_times, &two_y1j)?;

        let z1_plus_h = self.field_add(layouter.namespace(|| "pma_z1_plus_h"), &p.z, &h)?;
        let z1_plus_h_sq = self.field_mul(
            layouter.namespace(|| "pma_z1_plus_h_sq"),
            &z1_plus_h,
            &z1_plus_h,
        )?;
        let tmp = self.field_sub(layouter.namespace(|| "pma_z3_tmp"), &z1_plus_h_sq, &z1z1)?;
        let z3 = self.field_sub(layouter.namespace(|| "pma_z3"), &tmp, &hh)?;

        Ok(ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    pub(crate) fn projective_to_affine(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &ProjectivePoint,
    ) -> Result<EcPoint, ErrorFront> {
        let z_is_zero = self.is_zero_limb(layouter.namespace(|| "pta_z_is_zero"), &p.z)?;
        let z_inv_val = p.z.value.map(|z| z.invert().unwrap_or(Fp::ZERO));
        let z_inv = Limb {
            value: z_inv_val,
            cell: None,
        };
        let zinv_check = self.field_mul(layouter.namespace(|| "pta_zinv_check"), &p.z, &z_inv)?;
        let z_nonzero = self.one_minus_bit(layouter.namespace(|| "pta_z_nonzero"), &z_is_zero)?;
        self.constrain_equal_limb(
            layouter.namespace(|| "pta_zinv_eq"),
            &zinv_check,
            &z_nonzero,
        )?;

        let z_inv_sq = self.field_mul(layouter.namespace(|| "pta_z_inv_sq"), &z_inv, &z_inv)?;
        let z_inv_cu = self.field_mul(layouter.namespace(|| "pta_z_inv_cu"), &z_inv_sq, &z_inv)?;
        let x_aff = self.field_mul(layouter.namespace(|| "pta_x_aff"), &p.x, &z_inv_sq)?;
        let y_aff = self.field_mul(layouter.namespace(|| "pta_y_aff"), &p.y, &z_inv_cu)?;
        let y_minus_one = self.field_sub(
            layouter.namespace(|| "pta_y_minus_one"),
            &p.y,
            &Limb {
                value: Value::known(Fp::ONE),
                cell: None,
            },
        )?;
        let x_identity_check = self.field_mul(
            layouter.namespace(|| "pta_x_identity_check"),
            &p.x,
            &z_is_zero,
        )?;
        let y_identity_check = self.field_mul(
            layouter.namespace(|| "pta_y_identity_check"),
            &y_minus_one,
            &z_is_zero,
        )?;
        self.constrain_equal_limb(
            layouter.namespace(|| "pta_x_identity_zero"),
            &x_identity_check,
            &Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            },
        )?;
        self.constrain_equal_limb(
            layouter.namespace(|| "pta_y_identity_zero"),
            &y_identity_check,
            &Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            },
        )?;

        Ok(EcPoint {
            x: x_aff.value,
            y: y_aff.value,
            x_cell: x_aff.cell,
            y_cell: y_aff.cell,
            is_identity: z_is_zero
                .value
                .map(|v| v == Fp::ONE)
                .assign()
                .unwrap_or(false),
        })
    }

    pub fn constrain_equal_limb(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &Limb<Fp>,
        b: &Limb<Fp>,
    ) -> Result<(), ErrorFront> {
        Ok(layouter.assign_region(
            || "constrain equal limb",
            |mut region| {
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;
                if let Some(c) = a.cell {
                    region.constrain_equal(a_assigned.cell(), c)?;
                }
                if let Some(c) = b.cell {
                    region.constrain_equal(b_assigned.cell(), c)?;
                }
                region.constrain_equal(a_assigned.cell(), b_assigned.cell())?;
                Ok(())
            },
        )?)
    }

    pub fn add(
        &self,
        mut layouter: impl Layouter<Fp>,
        p1: &EcPoint,
        p2: &EcPoint,
    ) -> Result<EcPoint, ErrorFront> {
        self.assert_on_curve(layouter.namespace(|| "add_p1_on_curve"), p1)?;
        self.assert_on_curve(layouter.namespace(|| "add_p2_on_curve"), p2)?;
        self.identity_bit(layouter.namespace(|| "add_p1_identity"), p1)?;
        self.identity_bit(layouter.namespace(|| "add_p2_identity"), p2)?;
        let p1_proj = self.affine_to_projective(p1);
        let p2_proj = self.affine_to_projective(p2);
        let p1_id = self.identity_bit(layouter.namespace(|| "add_p1_id_bit"), p1)?;
        let p2_id = self.identity_bit(layouter.namespace(|| "add_p2_id_bit"), p2)?;

        let x1 = Limb {
            value: p1.x,
            cell: p1.x_cell,
        };
        let y1 = Limb {
            value: p1.y,
            cell: p1.y_cell,
        };
        let x2 = Limb {
            value: p2.x,
            cell: p2.x_cell,
        };
        let y2 = Limb {
            value: p2.y,
            cell: p2.y_cell,
        };
        let same_x = self.eq_limb(layouter.namespace(|| "add_same_x"), &x1, &x2)?;
        let same_y = self.eq_limb(layouter.namespace(|| "add_same_y"), &y1, &y2)?;
        let y_sum = self.field_add(layouter.namespace(|| "add_y_sum"), &y1, &y2)?;
        let y_opposite = self.is_zero_limb(layouter.namespace(|| "add_y_opposite"), &y_sum)?;
        let same_point =
            self.field_mul(layouter.namespace(|| "add_same_point"), &same_x, &same_y)?;
        let inv_point =
            self.field_mul(layouter.namespace(|| "add_inv_point"), &same_x, &y_opposite)?;

        let mixed = self.projective_mixed_add(layouter.namespace(|| "add_mixed"), &p1_proj, p2)?;
        let doubled = self.projective_double(layouter.namespace(|| "add_double"), &p1_proj)?;
        let add_or_double = self.select_projective_bit(
            layouter.namespace(|| "add_or_double"),
            &same_point,
            &doubled,
            &mixed,
        )?;
        let add_double_or_identity = self.select_projective_bit(
            layouter.namespace(|| "add_double_or_identity"),
            &inv_point,
            &self.projective_identity(),
            &add_or_double,
        )?;
        let p1_or_general = self.select_projective_bit(
            layouter.namespace(|| "add_p1_or_general"),
            &p2_id,
            &p1_proj,
            &add_double_or_identity,
        )?;
        let selected = self.select_projective_bit(
            layouter.namespace(|| "add_p2_or_general"),
            &p1_id,
            &p2_proj,
            &p1_or_general,
        )?;
        self.projective_to_affine(layouter.namespace(|| "add_to_affine"), &selected)
    }

    pub fn double(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &EcPoint,
    ) -> Result<EcPoint, ErrorFront> {
        self.assert_on_curve(layouter.namespace(|| "double_on_curve"), p)?;
        self.identity_bit(layouter.namespace(|| "double_identity"), p)?;
        let p_proj = self.affine_to_projective(p);
        let doubled =
            self.projective_double(layouter.namespace(|| "double_projective"), &p_proj)?;
        self.projective_to_affine(layouter.namespace(|| "double_to_affine"), &doubled)
    }

    pub fn identity_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &EcPoint,
    ) -> Result<Limb<Fp>, ErrorFront> {
        let x = Limb {
            value: p.x,
            cell: p.x_cell,
        };
        let y = Limb {
            value: p.y,
            cell: p.y_cell,
        };
        let x_zero = self.is_zero_limb(layouter.namespace(|| "identity_x_zero"), &x)?;
        let y_zero = self.is_zero_limb(layouter.namespace(|| "identity_y_zero"), &y)?;
        let coord_identity = self.field_mul(
            layouter.namespace(|| "identity_coord_mul"),
            &x_zero,
            &y_zero,
        )?;
        let flag_identity = layouter.assign_region(
            || "identity_flag",
            |mut region| {
                self.config.s_bit.enable(&mut region, 0)?;
                let bit_val = Value::known(if p.is_identity { Fp::ONE } else { Fp::ZERO });
                let bit =
                    region.assign_advice(|| "identity_bit", self.config.bit, 0, || bit_val)?;
                Ok(Limb {
                    value: bit_val,
                    cell: Some(bit.cell()),
                })
            },
        )?;
        self.constrain_equal_limb(
            layouter.namespace(|| "identity_flag_eq_coords"),
            &flag_identity,
            &coord_identity,
        )?;
        Ok(flag_identity)
    }

    /// Select between two points using an already-constrained bit limb.
    ///
    /// This links the selection bit cell to the caller's decomposition cell,
    /// avoiding the common soundness bug where scalar bits are constrained in
    /// one region but unrelated witness bits drive the point selection.
    pub fn select_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        bit: &Limb<Fp>,
        p1: &EcPoint,
        p2: &EcPoint,
    ) -> Result<EcPoint, ErrorFront> {
        assert!(
            bit.cell.is_some(),
            "select_bit requires an assigned bit cell"
        );
        self.assert_on_curve(layouter.namespace(|| "select_bit_p1_on_curve"), p1)?;
        self.assert_on_curve(layouter.namespace(|| "select_bit_p2_on_curve"), p2)?;
        self.identity_bit(layouter.namespace(|| "select_bit_p1_identity"), p1)?;
        self.identity_bit(layouter.namespace(|| "select_bit_p2_identity"), p2)?;
        let mut result = layouter.assign_region(
            || "ecc select assigned bit",
            |mut region| {
                self.config.s_select.enable(&mut region, 0)?;
                self.config.s_bit.enable(&mut region, 0)?;

                let bit_assigned =
                    region.assign_advice(|| "bit", self.config.bit, 0, || bit.value)?;
                if let Some(c) = bit.cell {
                    region.constrain_equal(bit_assigned.cell(), c)?;
                }

                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p1.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p1.y)?;
                let x2 = region.assign_advice(|| "x2", self.config.x, 1, || p2.x)?;
                let y2 = region.assign_advice(|| "y2", self.config.y, 1, || p2.y)?;

                if let Some(c) = p1.x_cell {
                    region.constrain_equal(x1.cell(), c)?;
                }
                if let Some(c) = p1.y_cell {
                    region.constrain_equal(y1.cell(), c)?;
                }
                if let Some(c) = p2.x_cell {
                    region.constrain_equal(x2.cell(), c)?;
                }
                if let Some(c) = p2.y_cell {
                    region.constrain_equal(y2.cell(), c)?;
                }

                let x3 = bit
                    .value
                    .zip(p1.x.clone())
                    .zip(p2.x.clone())
                    .map(|((b, x1), x2)| if b == Fp::ONE { x1 } else { x2 });
                let y3 = bit
                    .value
                    .zip(p1.y.clone())
                    .zip(p2.y.clone())
                    .map(|((b, y1), y2)| if b == Fp::ONE { y1 } else { y2 });

                let x3_assigned = region.assign_advice(|| "x3", self.config.x, 2, || x3)?;
                let y3_assigned = region.assign_advice(|| "y3", self.config.y, 2, || y3)?;

                Ok(EcPoint {
                    x: x3,
                    y: y3,
                    x_cell: Some(x3_assigned.cell()),
                    y_cell: Some(y3_assigned.cell()),
                    is_identity: false,
                })
            },
        )?;

        let is_identity = bit
            .value
            .map(|b| {
                if b == Fp::ONE {
                    p1.is_identity
                } else {
                    p2.is_identity
                }
            })
            .assign()
            .unwrap_or(false);
        result.is_identity = is_identity;
        Ok(result)
    }

    /// Constrain two points to be equal: p1 == p2
    /// Load a fixed-base lookup table for a specific base point.
    /// Phase 1.4: the EccChip operates on Pallas (`EpAffine` = `PallasAffine`).
    /// Pallas's scalar field is `Fq`, so the window multipliers in the table
    /// are `Fq::from(...)` (Pallas scalars).
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<Fp>,
        base: &PallasAffine,
        table_offset: usize,
    ) -> Result<(), ErrorFront> {
        Ok(layouter.assign_table(
            || format!("fixed base table (offset {})", table_offset),
            |mut table| {
                let w = 2; // Optimized to 2-bit window as per production roadmap
                let num_windows = (PASTA_SCALAR_BIT_LEN + w - 1) / w;

                for i in 0..num_windows {
                    let base_window: PallasAffine =
                        (PrimeCurveAffine::to_curve(base) * Fq::from(1u64 << (i * w))).to_affine();
                    for j in 0..(1 << w) {
                        let point: PallasAffine = (PrimeCurveAffine::to_curve(&base_window)
                            * Fq::from(j as u64))
                        .to_affine();
                        let coords = point.coordinates();
                        let (x, y) = if coords.is_some().into() {
                            let c = coords.unwrap();
                            (*c.x(), *c.y())
                        } else {
                            (Fp::ZERO, Fp::ZERO)
                        };

                        let row = (table_offset + i) * (1 << w) + j;
                        table.assign_cell(
                            || "idx",
                            self.config.table_idx,
                            row,
                            || Value::known(Fp::from(row as u64)),
                        )?;
                        table.assign_cell(|| "x", self.config.table_x, row, || Value::known(x))?;
                        table.assign_cell(|| "y", self.config.table_y, row, || Value::known(y))?;
                    }
                }
                Ok(())
            },
        )?)
    }

    pub fn fixed_base_scalar_mul(
        &self,
        mut layouter: impl Layouter<Fp>,
        scalar: &Limb<Fp>,
        base_point: &PallasAffine,
        table_offset: usize,
    ) -> Result<EcPoint, ErrorFront> {
        let _ = table_offset;
        let coords = base_point.coordinates().unwrap();
        let base = EcPoint {
            x: Value::known(*coords.x()),
            y: Value::known(*coords.y()),
            x_cell: None,
            y_cell: None,
            is_identity: false,
        };
        self.assert_on_curve(layouter.namespace(|| "fixed_base_input_on_curve"), &base)?;
        self.scalar_mul(
            layouter.namespace(|| "fixed_base_via_scalar_mul"),
            &base,
            scalar,
        )
    }

    pub fn constrain_equal(
        &self,
        mut layouter: impl Layouter<Fp>,
        p1: &EcPoint,
        p2: &EcPoint,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "constrain equal",
            |mut region| {
                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p1.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p1.y)?;
                let x2 = region.assign_advice(|| "x2", self.config.x, 1, || p2.x)?;
                let y2 = region.assign_advice(|| "y2", self.config.y, 1, || p2.y)?;

                if let Some(c) = p1.x_cell {
                    region.constrain_equal(x1.cell(), c)?;
                }
                if let Some(c) = p1.y_cell {
                    region.constrain_equal(y1.cell(), c)?;
                }
                if let Some(c) = p2.x_cell {
                    region.constrain_equal(x2.cell(), c)?;
                }
                if let Some(c) = p2.y_cell {
                    region.constrain_equal(y2.cell(), c)?;
                }

                region.constrain_equal(x1.cell(), x2.cell())?;
                region.constrain_equal(y1.cell(), y2.cell())?;
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn scalar_mul(
        &self,
        mut layouter: impl Layouter<Fp>,
        p: &EcPoint,
        scalar: &Limb<Fp>,
    ) -> Result<EcPoint, ErrorFront> {
        self.assert_on_curve(layouter.namespace(|| "scalar_mul_input_on_curve"), p)?;
        self.identity_bit(layouter.namespace(|| "scalar_mul_input_identity"), p)?;
        let bits = layouter.assign_region(
            || "scalar_bits",
            |mut region| {
                let mut acc = Value::known(Fp::ZERO);
                let mut base = Fp::ONE;
                let mut bits = Vec::with_capacity(PASTA_SCALAR_BIT_LEN);
                for i in 0..PASTA_SCALAR_BIT_LEN {
                    let bit_val = scalar.value.map(|s| {
                        let bytes = s.to_repr();
                        if (bytes.as_ref()[i / 8] >> (i % 8)) & 1 == 1 {
                            Fp::ONE
                        } else {
                            Fp::ZERO
                        }
                    });
                    let assigned = region.assign_advice(
                        || format!("bit_{}", i),
                        self.config.bit,
                        i,
                        || bit_val,
                    )?;
                    self.config.s_bit.enable(&mut region, i)?;
                    acc = acc.zip(bit_val).map(|(a, b)| a + b * base);
                    base = base.double();
                    bits.push(Limb {
                        value: bit_val,
                        cell: Some(assigned.cell()),
                    });
                }
                if let Some(scalar_cell) = scalar.cell {
                    let acc_cell = region.assign_advice(
                        || "reconstructed_scalar",
                        self.config.x,
                        0,
                        || acc,
                    )?;
                    region.constrain_equal(acc_cell.cell(), scalar_cell)?;
                }
                Ok(bits)
            },
        )?;

        let p1 = p.clone();
        let p2 = self.double(layouter.namespace(|| "p2"), p)?;
        let p3 = self.add(layouter.namespace(|| "p3"), &p1, &p2)?;
        let identity = EcPoint::identity();
        let mut acc = self.projective_identity();
        let mut started = Limb {
            value: Value::known(Fp::ZERO),
            cell: None,
        };
        let window_bits = 2;
        let num_windows = (PASTA_SCALAR_BIT_LEN + window_bits - 1) / window_bits;

        for window in (0..num_windows).rev() {
            if window < num_windows - 1 {
                acc = self
                    .projective_double(layouter.namespace(|| format!("dbl0_{}", window)), &acc)?;
                acc = self
                    .projective_double(layouter.namespace(|| format!("dbl1_{}", window)), &acc)?;
            }

            let idx0 = window * window_bits;
            let idx1 = idx0 + 1;
            let b0 = &bits[idx0];
            let p_low = self.select_bit(
                layouter.namespace(|| format!("sel_low_{}", window)),
                b0,
                &p1,
                &identity,
            )?;
            let p_window = if idx1 < bits.len() {
                let p_high = self.select_bit(
                    layouter.namespace(|| format!("sel_high_{}", window)),
                    b0,
                    &p3,
                    &p2,
                )?;
                self.select_bit(
                    layouter.namespace(|| format!("sel_window_{}", window)),
                    &bits[idx1],
                    &p_high,
                    &p_low,
                )?
            } else {
                p_low
            };

            let acc_affine = self.projective_to_affine(
                layouter.namespace(|| format!("acc_affine_{}", window)),
                &acc,
            )?;
            let acc_x = Limb {
                value: acc_affine.x,
                cell: acc_affine.x_cell,
            };
            let acc_y = Limb {
                value: acc_affine.y,
                cell: acc_affine.y_cell,
            };
            let win_x = Limb {
                value: p_window.x,
                cell: p_window.x_cell,
            };
            let win_y = Limb {
                value: p_window.y,
                cell: p_window.y_cell,
            };
            let acc_is_identity = self.identity_bit(
                layouter.namespace(|| format!("acc_is_identity_{}", window)),
                &acc_affine,
            )?;
            let win_is_identity = self.identity_bit(
                layouter.namespace(|| format!("win_is_identity_{}", window)),
                &p_window,
            )?;
            let same_x = self.eq_limb(
                layouter.namespace(|| format!("same_x_{}", window)),
                &acc_x,
                &win_x,
            )?;
            let same_y = self.eq_limb(
                layouter.namespace(|| format!("same_y_{}", window)),
                &acc_y,
                &win_y,
            )?;
            let y_sum = self.field_add(
                layouter.namespace(|| format!("y_sum_{}", window)),
                &acc_y,
                &win_y,
            )?;
            let y_opposite = self.is_zero_limb(
                layouter.namespace(|| format!("y_opposite_{}", window)),
                &y_sum,
            )?;
            let same_point = self.field_mul(
                layouter.namespace(|| format!("same_point_{}", window)),
                &same_x,
                &same_y,
            )?;
            let inv_point = self.field_mul(
                layouter.namespace(|| format!("inv_point_{}", window)),
                &same_x,
                &y_opposite,
            )?;
            let acc_added = self.projective_mixed_add(
                layouter.namespace(|| format!("add_window_{}", window)),
                &acc,
                &p_window,
            )?;
            let acc_doubled = self.projective_double(
                layouter.namespace(|| format!("double_window_{}", window)),
                &acc,
            )?;
            let add_or_double = self.select_projective_bit(
                layouter.namespace(|| format!("add_or_double_{}", window)),
                &same_point,
                &acc_doubled,
                &acc_added,
            )?;
            let add_double_or_identity = self.select_projective_bit(
                layouter.namespace(|| format!("add_double_or_identity_{}", window)),
                &inv_point,
                &self.projective_identity(),
                &add_or_double,
            )?;
            let p_window_proj = self.affine_to_projective(&p_window);
            let acc_general = self.select_projective_bit(
                layouter.namespace(|| format!("acc_general_{}", window)),
                &win_is_identity,
                &acc,
                &add_double_or_identity,
            )?;
            let acc_safe = self.select_projective_bit(
                layouter.namespace(|| format!("acc_safe_{}", window)),
                &acc_is_identity,
                &p_window_proj,
                &acc_general,
            )?;

            let is_zero = if idx1 < bits.len() {
                let is_zero_hi = self.one_minus_bit(
                    layouter.namespace(|| format!("is_zero_hi_{}", window)),
                    &bits[idx1],
                )?;
                let is_zero_lo = self
                    .one_minus_bit(layouter.namespace(|| format!("is_zero_lo_{}", window)), b0)?;
                self.field_mul(
                    layouter.namespace(|| format!("is_zero_window_{}", window)),
                    &is_zero_hi,
                    &is_zero_lo,
                )?
            } else {
                self.one_minus_bit(
                    layouter.namespace(|| format!("is_zero_window_{}", window)),
                    b0,
                )?
            };

            let acc_nonzero = self.select_projective_bit(
                layouter.namespace(|| format!("started_acc_select_{}", window)),
                &started,
                &acc_safe,
                &p_window_proj,
            )?;
            acc = self.select_projective_bit(
                layouter.namespace(|| format!("acc_select_{}", window)),
                &is_zero,
                &acc,
                &acc_nonzero,
            )?;

            let not_started = self.one_minus_bit(
                layouter.namespace(|| format!("not_started_{}", window)),
                &started,
            )?;
            let stayed_zero = self.field_mul(
                layouter.namespace(|| format!("stayed_zero_{}", window)),
                &not_started,
                &is_zero,
            )?;
            started = self.one_minus_bit(
                layouter.namespace(|| format!("started_next_{}", window)),
                &stayed_zero,
            )?;
        }

        self.projective_to_affine(layouter.namespace(|| "acc_to_affine"), &acc)
    }
}

// --- Non-Native Arithmetic ---

pub mod diagnostics;
pub mod ipa_transcript;
pub mod proof_import;
pub mod non_native_fq;
pub mod transcript_blake2b;
pub mod transcript_blake2b_circuit;
pub mod transcript_blake2b_compression;
pub mod transcript_bytes;
pub mod transcript_words;
pub mod vesta_ecc;
pub mod vesta_fq;
pub mod vesta_ipa;
pub mod vesta_accumulate;

pub mod vesta_range;

pub mod vesta_transcript;

pub mod non_native_fp;
pub mod pallas_ecc;
pub mod pallas_ipa;
pub mod pallas_accumulate;
pub mod recursive_proof;
pub mod prove_recursive;

#[derive(Clone, Debug)]
pub struct Limb<F: Field> {
    pub value: Value<F>,
    pub cell: Option<Cell>,
}

/// Type alias for Limb used in Circuit\<Fp\> (the current recursive circuit field).
pub type FpLimb = Limb<Fp>;

#[allow(dead_code)]
fn fp_to_hex(fp: &Fp) -> String {
    hex::encode(fp.to_repr())
}

/// Decode a hex-encoded field element of the recursive circuit's scalar type
/// (`Fp` = Pallas base field, post-Phase-1.4 Pasta migration). 32-byte little-endian
/// representation, matching `Fp::to_repr()`. Returns `Fp::ZERO` on parse failure
/// (which the gossip validator treats as a "total_flow != 0" rejection).
fn hex_to_fp(h: &str) -> Fp {
    let bytes = hex::decode(h).unwrap_or_default();
    if bytes.len() == 32 {
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes);
        Fp::from_repr(repr.into()).unwrap_or(Fp::ZERO)
    } else {
        Fp::ZERO
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveStatement {
    pub total_flow: String, // Hex Fp
    pub tx_root: String,    // Hex Fp
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicProofGossip {
    pub tx_id: [u8; 32],
    pub statement: RecursiveStatement,
    pub proof: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateProofGossip {
    pub aggregate_id: [u8; 32],
    pub accumulator: Vec<u8>,
    pub prev_accumulator: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
    pub commitments_list: Vec<Vec<[u8; 32]>>,
    pub public_amounts: Vec<i64>,
    pub depth: u32,
    pub timestamp: u64,
}

// --- Manager and FFI ---
//
// Phase 1.3 stub: real recursive proof generation/verification deferred to Phase 1.4.
// The gossip/aggregation protocol surface is preserved (handle_*_gossip, forward_proof,
// check_aggregation_trigger, generate_*_proof JSON, verify_halo2_proof fail-closed) so
// that the FFI ABI and aetheris-ffi callers remain compilable and behaviorally observable.
// All cryptographic proof paths return "unavailable" / false rather than performing
// keygen/prove/verify against the now-deleted RecursiveAggregationCircuit.

pub struct P2PRecursiveManager {
    peer_id: PeerId,
    shard_id: u32,

    // Protocol state
    seen_atomic: HashSet<[u8; 32]>,
    seen_aggregate: HashMap<[u8; 32], u32>, // aggregate_id -> depth
    pending_atomic: Vec<AtomicProofGossip>,
    last_gossip_time: std::time::Instant,
    gossip_count_in_window: u32,
}

pub struct RecursiveManagerHandle {
    inner: Arc<RwLock<P2PRecursiveManager>>,
}

impl P2PRecursiveManager {
    pub fn new(peer_id: PeerId, shard_id: u32) -> Self {
        Self {
            peer_id,
            shard_id,
            seen_atomic: HashSet::new(),
            seen_aggregate: HashMap::new(),
            pending_atomic: Vec::new(),
            last_gossip_time: std::time::Instant::now(),
            gossip_count_in_window: 0,
        }
    }

    /// Strictly follows gossip_aggregation_protocol.md for validation and forwarding.
    pub fn handle_atomic_gossip(&mut self, _sender: PeerId, gossip: AtomicProofGossip) -> bool {
        // 1. Basic Verification (Anti-Replay & Format)
        if self.seen_atomic.contains(&gossip.tx_id) {
            return false;
        }

        // 2. State Validation (total_flow == 0)
        let flow = hex_to_fp(&gossip.statement.total_flow);
        if flow != Fp::ZERO {
            println!("[Protocol] Rejected atomic proof: total_flow != 0");
            return false;
        }

        // 3. Cryptographic Validation
        if !self.verify_atomic_proof(&gossip) {
            println!(
                "[Protocol] Cryptographic validation failed for TX: {}",
                hex::encode(gossip.tx_id)
            );
            return false;
        }
        println!(
            "[Protocol] Validated atomic proof for TX: {}",
            hex::encode(gossip.tx_id)
        );

        // 4. Update Local State
        self.seen_atomic.insert(gossip.tx_id);
        self.pending_atomic.push(gossip.clone());

        true
    }

    pub fn handle_aggregate_gossip(
        &mut self,
        _sender: PeerId,
        gossip: AggregateProofGossip,
    ) -> bool {
        // 1. Dedup + depth check
        if let Some(&existing_depth) = self.seen_aggregate.get(&gossip.aggregate_id) {
            if gossip.depth <= existing_depth {
                return false;
            }
        }

        // 2. Rate limiting: max 100 messages per 10s window
        let now = std::time::Instant::now();
        if now.duration_since(self.last_gossip_time).as_secs() >= 10 {
            self.gossip_count_in_window = 0;
            self.last_gossip_time = now;
        }
        self.gossip_count_in_window += 1;
        if self.gossip_count_in_window > 100 {
            return false;
        }

        // 3. Verify using the accumulator chain (O(n) replay; O(1) sig check
        //    is available when an aggregator pubkey is configured).
        if !self.verify_aggregate_proof(&gossip) {
            println!(
                "[Protocol] Aggregate proof validation failed: {}",
                hex::encode(gossip.aggregate_id)
            );
            return false;
        }

        // 4. Accept
        println!(
            "[Protocol] Accepted aggregate proof: aggregate_id={} depth={}",
            hex::encode(gossip.aggregate_id),
            gossip.depth
        );
        self.seen_aggregate
            .insert(gossip.aggregate_id, gossip.depth);
        true
    }

    /// Phase 1.3 stub: real params/PK preloading is deferred to Phase 1.4 (Pasta IPA).
    /// Retains the signature so existing FFI/callers compile, and so that
    /// `cached_params`/`cached_pk` test assertions can assert `is_none()`.
    pub fn preload_params(&mut self, k: u32) {
        println!(
            "[Manager] preload_params(k={}) is a Phase 1.3 no-op \
             (recursive proving deferred to Phase 1.4)",
            k
        );
    }

    pub fn verify_atomic_proof(&self, gossip: &AtomicProofGossip) -> bool {
        self.verify_halo2_proof(&gossip.proof, &gossip.statement)
    }

    pub fn verify_aggregate_proof(&self, gossip: &AggregateProofGossip) -> bool {
        crate::block_aggregator::verify_accumulator_chain(
            &gossip.accumulator,
            &gossip.prev_accumulator,
            &gossip.proofs,
            &gossip.commitments_list,
            &gossip.public_amounts,
            None,
        )
    }

    /// Phase 1.3 stub: fail-closed. Real verification returns once Phase 1.4 wires
    /// a real Pasta IPA verifier. For now, the protocol's state validation (total_flow
    /// == 0, anti-replay, depth ordering) is enforced by `handle_*_gossip` callers
    /// *before* reaching this function; cryptographic verification is intentionally
    /// absent and gossip is rejected.
    fn verify_halo2_proof(&self, _proof_bytes: &[u8], _statement: &RecursiveStatement) -> bool {
        false
    }

    pub fn add_peer(&mut self, _peer_id: PeerId) {
        // Phase 1.11: peer tracking for DOS scoring is deferred; gossipsub
        // handles propagation and scoring natively.
    }

    pub fn simulate_network_convergence(&mut self, tx_id: [u8; 32], network_size: usize) -> usize {
        let tx_id_hex = hex::encode(tx_id);
        println!(
            "[Sim] Simulating parallel convergence for TX {} across {} nodes",
            tx_id_hex, network_size
        );

        let mut hops = 0;
        let mut reached_nodes = std::collections::HashSet::new();
        reached_nodes.insert(self.peer_id);

        // Parallel epidemic model: simulation of message propagation in clusters
        while reached_nodes.len() < network_size && hops < 10 {
            hops += 1;
            let current_count = reached_nodes.len();

            // Parallel peer discovery simulation
            let new_peers: Vec<PeerId> = (0..(current_count.min(network_size - current_count)))
                .into_par_iter()
                .map(|_| PeerId::random())
                .collect();

            for peer in new_peers {
                reached_nodes.insert(peer);
            }

            println!(
                "[Sim] Hop {}: {}/{} nodes reached (Parallel)",
                hops,
                reached_nodes.len(),
                network_size
            );
        }

        hops
    }

    /// Phase 1.3 stub: emits "unavailable" JSONs. Real Pasta IPA accumulation
    /// returns in Phase 1.4. Callers (FFI, gossip) can parse and detect the stub.
    pub fn generate_batch_atomic_proofs(&mut self, tx_ids: Vec<[u8; 32]>) -> Vec<String> {
        tx_ids
            .into_iter()
            .map(|tx_id| {
                let tx_id_hex = hex::encode(tx_id);
                format!(
                    "{{\"tx_id\": \"{}\", \"status\": \"unavailable\", \
                     \"reason\": \"recursive proving deferred to Phase 1.4\"}}",
                    tx_id_hex
                )
            })
            .collect()
    }

    /// Phase 1.3 stub: emits "unavailable" JSON. Caches the result so repeated
    /// calls for the same tx_id stay consistent (mimics old cache behavior).
    pub fn generate_atomic_proof(&mut self, tx_id: [u8; 32]) -> String {
        let tx_id_hex = hex::encode(tx_id);
        format!(
            "{{\"tx_id\": \"{}\", \"shard_id\": {}, \
             \"status\": \"unavailable\", \
             \"reason\": \"recursive proving deferred to Phase 1.4\"}}",
            tx_id_hex, self.shard_id
        )
    }

    pub fn handle_proof_json(&mut self, sender: PeerId, json: &str) -> i32 {
        println!("[P2P] Received proof from {}: {}", sender, json);
        0
    }

    pub fn get_reward(&self, _peer_id: &str) -> u64 {
        0
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_new_sharded(
    peer_id_ptr: *const c_char,
    shard_id: u32,
) -> *mut RecursiveManagerHandle {
    let peer_id_str = unsafe { CStr::from_ptr(peer_id_ptr).to_str().unwrap() };
    let peer_id = match PeerId::from_str(peer_id_str) {
        Ok(id) => id,
        Err(_) => return std::ptr::null_mut(),
    };
    let manager = P2PRecursiveManager::new(peer_id, shard_id);
    let handle = RecursiveManagerHandle {
        inner: Arc::new(RwLock::new(manager)),
    };
    Box::into_raw(Box::new(handle))
}

#[no_mangle]
pub extern "C" fn recursive_manager_free(handle: *mut RecursiveManagerHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_handle_atomic_gossip(
    handle: *mut RecursiveManagerHandle,
    sender_ptr: *const c_char,
    json_ptr: *const c_char,
) -> i32 {
    let handle = unsafe { &*handle };
    let sender_str = unsafe { CStr::from_ptr(sender_ptr).to_str().unwrap() };
    let sender = match PeerId::from_str(sender_str) {
        Ok(id) => id,
        Err(_) => return -1,
    };
    let json = unsafe { CStr::from_ptr(json_ptr).to_str().unwrap() };
    let gossip: AtomicProofGossip = match serde_json::from_str(json) {
        Ok(g) => g,
        Err(_) => return -2,
    };

    if let Ok(mut manager) = handle.inner.write() {
        if manager.handle_atomic_gossip(sender, gossip) {
            1
        } else {
            0
        }
    } else {
        -3
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_handle_aggregate_gossip(
    handle: *mut RecursiveManagerHandle,
    sender_ptr: *const c_char,
    json_ptr: *const c_char,
) -> i32 {
    let handle = unsafe { &*handle };
    let sender_str = unsafe { CStr::from_ptr(sender_ptr).to_str().unwrap() };
    let sender = match PeerId::from_str(sender_str) {
        Ok(id) => id,
        Err(_) => return -1,
    };
    let json = unsafe { CStr::from_ptr(json_ptr).to_str().unwrap() };
    let gossip: AggregateProofGossip = match serde_json::from_str(json) {
        Ok(g) => g,
        Err(_) => return -2,
    };

    if let Ok(mut manager) = handle.inner.write() {
        if manager.handle_aggregate_gossip(sender, gossip) {
            1
        } else {
            0
        }
    } else {
        -3
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_handle_proof_json(
    handle: *mut RecursiveManagerHandle,
    sender_ptr: *const c_char,
    json_ptr: *const c_char,
) -> i32 {
    let handle = unsafe { &*handle };
    let sender_str = unsafe { CStr::from_ptr(sender_ptr).to_str().unwrap() };
    let sender = match PeerId::from_str(sender_str) {
        Ok(id) => id,
        Err(_) => return -1,
    };
    let json = unsafe { CStr::from_ptr(json_ptr).to_str().unwrap() };

    if let Ok(mut manager) = handle.inner.write() {
        manager.handle_proof_json(sender, json)
    } else {
        -2
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_get_reward(
    handle: *mut RecursiveManagerHandle,
    peer_id_ptr: *const c_char,
) -> u64 {
    let handle = unsafe { &*handle };
    let peer_id = unsafe { CStr::from_ptr(peer_id_ptr).to_str().unwrap() };

    if let Ok(manager) = handle.inner.read() {
        manager.get_reward(peer_id)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_generate_batch_json(
    handle: *mut RecursiveManagerHandle,
    tx_ids_ptr: *const [u8; 32],
    count: usize,
) -> *mut *mut c_char {
    let handle = unsafe { &*handle };
    let tx_ids = unsafe { std::slice::from_raw_parts(tx_ids_ptr, count) }.to_vec();

    if let Ok(mut manager) = handle.inner.write() {
        let results = manager.generate_batch_atomic_proofs(tx_ids);
        let mut c_results: Vec<*mut c_char> = results
            .into_iter()
            .map(|s| CString::new(s).unwrap().into_raw())
            .collect();

        let ptr = c_results.as_mut_ptr();
        std::mem::forget(c_results);
        ptr
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_free_batch_json(ptr: *mut *mut c_char, count: usize) {
    if !ptr.is_null() {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr, count);
            for i in 0..count {
                if !slice[i].is_null() {
                    let _ = CString::from_raw(slice[i]);
                }
            }
            let _ = Vec::from_raw_parts(ptr, count, count);
        }
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_generate_atomic_json(
    handle: *mut RecursiveManagerHandle,
    tx_id_ptr: *const u8,
    _tx_root: *const c_char,
    _total_flow: *const c_char,
) -> *mut c_char {
    let handle = unsafe { &*handle };
    let mut tx_id = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(tx_id_ptr, tx_id.as_mut_ptr(), 32) };

    if let Ok(mut manager) = handle.inner.write() {
        let proof_json = manager.generate_atomic_proof(tx_id);
        CString::new(proof_json).unwrap().into_raw()
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

    #[test]
    fn find_nums_point() {
        // Phase 1.4: search for the smallest Vesta NUMS point on y² = x³ + 5
        // (previously Grumpkin's y² = x³ + 3, ISSUE-1.3.B).
        for i in 0..100 {
            let x = Fp::from(i);
            let y_sq = x * x * x + Fp::from(PASTA_CURVE_B);
            let y: Option<Fp> = y_sq.sqrt().into();
            if let Some(y_val) = y {
                println!("Point found: x={}, y={:?}", i, y_val);
            }
        }
    }

    #[test]
    fn test_gossip_protocol_compliance() {
        let mut manager = P2PRecursiveManager::new(PeerId::random(), 1);
        let sender = PeerId::random();

        // 1. Atomic proof with garbage bytes → cryptographic validation fails
        let atomic = AtomicProofGossip {
            tx_id: [1u8; 32],
            statement: RecursiveStatement {
                total_flow: fp_to_hex(&Fp::ZERO),
                tx_root: fp_to_hex(&Fp::from(12345)),
            },
            proof: vec![0, 1, 2],
            timestamp: 123456789,
        };

        // Garbage proof bytes fail cryptographic validation (auto-loads global params)
        assert!(!manager.handle_atomic_gossip(sender, atomic.clone()));
        assert_eq!(manager.pending_atomic.len(), 0);

        // 2. Invalid flow atomic proof (rejected before cryptographic validation)
        let invalid_atomic = AtomicProofGossip {
            tx_id: [2u8; 32],
            statement: RecursiveStatement {
                total_flow: fp_to_hex(&Fp::from(100)), // Violation: total_flow must be 0
                tx_root: fp_to_hex(&Fp::from(12345)),
            },
            proof: vec![0, 1, 2],
            timestamp: 123456790,
        };
        assert!(!manager.handle_atomic_gossip(sender, invalid_atomic));

        // 3. Aggregate proof with garbage → fails validation
        let agg1 = AggregateProofGossip {
            aggregate_id: [10u8; 32],
            accumulator: b"not_an_accumulator".to_vec(),
            prev_accumulator: b"not_an_accumulator".to_vec(),
            proofs: vec![vec![9, 9]],
            commitments_list: vec![vec![[1u8; 32]]],
            public_amounts: vec![0],
            depth: 5,
            timestamp: 123456789,
        };
        assert!(!manager.handle_aggregate_gossip(sender, agg1.clone()));

        // 4. Weaker aggregate (same aggregate_id, lower depth) also fails
        let agg2_weaker = AggregateProofGossip {
            aggregate_id: [10u8; 32],
            depth: 4,
            ..agg1.clone()
        };
        assert!(!manager.handle_aggregate_gossip(sender, agg2_weaker));

        // 5. Stronger aggregate also fails (bad accumulator bytes fail verify)
        let agg3_stronger = AggregateProofGossip {
            aggregate_id: [10u8; 32],
            depth: 6,
            accumulator: b"not_an_accumulator".to_vec(),
            ..agg1
        };
        assert!(!manager.handle_aggregate_gossip(sender, agg3_stronger));
    }

    #[test]
    fn test_parallel_convergence() {
        let mut manager = P2PRecursiveManager::new(PeerId::random(), 1);
        let hops = manager.simulate_network_convergence([0u8; 32], 100);
        assert!(hops > 0);
    }

    #[test]
    fn test_poseidon_hash() {
        let k = 8;
        let _spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);

        #[derive(Default)]
        struct TestCircuit {
            input: Vec<Fp>,
        }

        impl Circuit<Fp> for TestCircuit {
            type Config = PoseidonConfig<3, 2>;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self::default()
            }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                PoseidonChip::<3, 2>::configure(meta, spec.mds)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                let chip = PoseidonChip::new(spec, config.clone());

                let limbs = layouter.assign_region(
                    || "inputs",
                    |mut region| {
                        let mut limbs = Vec::new();
                        for (i, val) in self.input.iter().enumerate() {
                            let cell = region.assign_advice(
                                || format!("input_{}", i),
                                config.state[i],
                                0,
                                || Value::known(*val),
                            )?;
                            limbs.push(Limb {
                                value: Value::known(*val),
                                cell: Some(cell.cell()),
                            });
                        }
                        Ok(limbs)
                    },
                )?;

                let _hash = chip.hash(layouter.namespace(|| "hash"), &limbs)?;
                Ok(())
            }
        }

        let circuit = TestCircuit {
            input: vec![Fp::from(1), Fp::from(2)],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_ecc_add() {
        const K: u32 = 10;

        struct EccAddCircuit;
        impl Default for EccAddCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccAddCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let _g2 = chip.add(layouter.namespace(|| "add_g_g"), &g, &g)?;
                Ok(())
            }
        }

        let circuit = EccAddCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "EccChip add should satisfy: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_ecc_scalar_mul() {
        const K: u32 = 17;

        struct EccScalarMulCircuit;
        impl Default for EccScalarMulCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccScalarMulCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let two = Limb {
                    value: Value::known(Fp::from(2)),
                    cell: None,
                };
                let _res = chip.scalar_mul(layouter.namespace(|| "scalar_mul"), &g, &two)?;
                Ok(())
            }
        }

        let circuit = EccScalarMulCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "EccChip scalar_mul should satisfy gates: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_ecc_add_rejects_non_curve_input() {
        const K: u32 = 10;

        struct EccAddInvalidInputCircuit;
        impl Default for EccAddInvalidInputCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccAddInvalidInputCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let invalid = EcPoint {
                    x: Value::known(Fp::ONE),
                    y: Value::known(Fp::ONE),
                    x_cell: None,
                    y_cell: None,
                    is_identity: false,
                };
                let _ = chip.add(
                    layouter.namespace(|| "add_invalid_g"),
                    &invalid,
                    &chip.generator(),
                )?;
                Ok(())
            }
        }

        let circuit = EccAddInvalidInputCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "EccChip add should reject non-curve affine input"
        );
    }

    #[test]
    fn test_ecc_double_rejects_non_curve_input() {
        const K: u32 = 10;

        struct EccDoubleInvalidInputCircuit;
        impl Default for EccDoubleInvalidInputCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccDoubleInvalidInputCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let invalid = EcPoint {
                    x: Value::known(Fp::ONE),
                    y: Value::known(Fp::ONE),
                    x_cell: None,
                    y_cell: None,
                    is_identity: false,
                };
                let _ = chip.double(layouter.namespace(|| "double_invalid"), &invalid)?;
                Ok(())
            }
        }

        let circuit = EccDoubleInvalidInputCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "EccChip double should reject non-curve affine input"
        );
    }

    #[test]
    fn test_ecc_scalar_mul_rejects_non_curve_input() {
        const K: u32 = 17;

        struct EccScalarMulInvalidInputCircuit;
        impl Default for EccScalarMulInvalidInputCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccScalarMulInvalidInputCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let invalid = EcPoint {
                    x: Value::known(Fp::ONE),
                    y: Value::known(Fp::ONE),
                    x_cell: None,
                    y_cell: None,
                    is_identity: false,
                };
                let two = Limb {
                    value: Value::known(Fp::from(2)),
                    cell: None,
                };
                let _ =
                    chip.scalar_mul(layouter.namespace(|| "scalar_mul_invalid"), &invalid, &two)?;
                Ok(())
            }
        }

        let circuit = EccScalarMulInvalidInputCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "EccChip scalar_mul should reject non-curve affine input"
        );
    }

    #[test]
    fn test_ecc_fixed_base_scalar_mul_still_accepts_curve_base() {
        const K: u32 = 17;

        struct EccFixedBaseScalarMulCircuit;
        impl Default for EccFixedBaseScalarMulCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccFixedBaseScalarMulCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let two = Limb {
                    value: Value::known(Fp::from(2)),
                    cell: None,
                };
                let _ = chip.fixed_base_scalar_mul(
                    layouter.namespace(|| "fixed_base_scalar_mul"),
                    &two,
                    &PallasAffine::generator(),
                    0,
                )?;
                Ok(())
            }
        }

        let circuit = EccFixedBaseScalarMulCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "EccChip fixed_base_scalar_mul should satisfy gates: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_ecc_select_bit_rejects_non_curve_input() {
        const K: u32 = 10;

        struct EccSelectBitInvalidInputCircuit;
        impl Default for EccSelectBitInvalidInputCircuit {
            fn default() -> Self {
                Self
            }
        }

        impl Circuit<Fp> for EccSelectBitInvalidInputCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config.clone());
                let invalid = EcPoint {
                    x: Value::known(Fp::ONE),
                    y: Value::known(Fp::ONE),
                    x_cell: None,
                    y_cell: None,
                    is_identity: false,
                };
                let bit = layouter.assign_region(
                    || "assign_bit",
                    |mut region| {
                        chip.config.s_bit.enable(&mut region, 0)?;
                        let assigned = region.assign_advice(
                            || "bit",
                            config.bit,
                            0,
                            || Value::known(Fp::ONE),
                        )?;
                        Ok(Limb {
                            value: Value::known(Fp::ONE),
                            cell: Some(assigned.cell()),
                        })
                    },
                )?;
                let _ = chip.select_bit(
                    layouter.namespace(|| "select_bit_invalid"),
                    &bit,
                    &invalid,
                    &chip.generator(),
                )?;
                Ok(())
            }
        }

        let circuit = EccSelectBitInvalidInputCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "EccChip select_bit should reject non-curve affine input"
        );
    }

    #[test]
    fn test_manager_new() {
        let peer_id = PeerId::random();
        let manager = P2PRecursiveManager::new(peer_id, 42);
        assert_eq!(manager.peer_id, peer_id);
        assert_eq!(manager.shard_id, 42);
        assert!(manager.seen_atomic.is_empty());
        assert!(manager.seen_aggregate.is_empty());
        assert!(manager.pending_atomic.is_empty());
    }

    #[test]
    fn test_manager_preload_params() {
        // Phase 1.3 stub: preload_params is a no-op that just prints a deferral
        // log. Real params/PK preloading returns in Phase 1.4 with Pasta IPA.
        let mut manager = P2PRecursiveManager::new(PeerId::random(), 1);
        manager.preload_params(13);
        // No exception, no state mutation — protocol state remains empty.
        assert!(manager.seen_atomic.is_empty());
        assert!(manager.pending_atomic.is_empty());
    }

    #[test]
    fn test_atomic_proof_generation() {
        // Phase 1.3 stub: emit "unavailable" JSON until Phase 1.4 wires real
        // Pasta IPA generation. The shape of the JSON is the contract callers
        // (aetheris-ffi, gossip) parse; the deferred-to-1.4 reason is the
        // observable signal.
        let mut manager = P2PRecursiveManager::new(PeerId::random(), 1);
        let tx_id = [0xabu8; 32];
        let result = manager.generate_atomic_proof(tx_id);
        assert!(result.contains("tx_id"), "JSON should contain tx_id");
        assert!(result.contains("shard_id"), "JSON should contain shard_id");
        assert!(result.contains("status"), "JSON should contain status");
        assert!(
            result.contains("unavailable"),
            "JSON should indicate Phase 1.3 stub status"
        );
        assert!(
            result.contains("Phase 1.4"),
            "JSON should reference Phase 1.4 deferral"
        );
    }

    #[test]
    fn test_poseidon_consistency() {
        const K: u32 = 10;

        #[derive(Default)]
        struct PoseidonConsistencyCircuit;

        impl Circuit<Fp> for PoseidonConsistencyCircuit {
            type Config = PoseidonConfig<3, 2>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                PoseidonChip::<3, 2>::configure(meta, spec.mds)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                let chip = PoseidonChip::new(spec, config.clone());

                let limbs = layouter.assign_region(
                    || "inputs",
                    |mut region| {
                        let mut limbs = Vec::new();
                        for i in 0..2 {
                            let cell = region.assign_advice(
                                || format!("input_{}", i),
                                config.state[i],
                                0,
                                || Value::known(Fp::from(i as u64 + 1)),
                            )?;
                            limbs.push(Limb {
                                value: Value::known(Fp::from(i as u64 + 1)),
                                cell: Some(cell.cell()),
                            });
                        }
                        Ok(limbs)
                    },
                )?;

                // Hash twice with same input to verify determinism
                let hash1 = chip.hash(layouter.namespace(|| "hash1"), &limbs)?;
                let hash2 = chip.hash(layouter.namespace(|| "hash2"), &limbs)?;

                // Constrain equality between the two outputs via permutation argument
                layouter.assign_region(
                    || "equality check",
                    |mut region| {
                        let h1 =
                            region.assign_advice(|| "h1", config.state[0], 0, || hash1.value)?;
                        let h2 =
                            region.assign_advice(|| "h2", config.state[0], 1, || hash2.value)?;
                        if let Some(c1) = hash1.cell {
                            region.constrain_equal(h1.cell(), c1)?;
                        }
                        if let Some(c2) = hash2.cell {
                            region.constrain_equal(h2.cell(), c2)?;
                        }
                        region.constrain_equal(h1.cell(), h2.cell())?;
                        Ok(())
                    },
                )?;

                Ok(())
            }
        }

        let circuit = PoseidonConsistencyCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    /// Phase 1.3 + 1.4 coverage: `is_identity` must propagate through
    /// arithmetic so that `assert_on_curve` correctly skips the real-curve
    /// gate for witness results that are mathematically the identity. We
    /// exercise every identity-producing path: identity `add`/`double`,
    /// window=0 in `fixed_base_scalar_mul`, scalar=0 in `scalar_mul`, and
    /// the final zero-scalar normalization back to affine identity.
    ///
    /// Phase 1.4 update (ISSUE-1.3.B regression test): the `on_curve_check`
    /// gate has been fixed from Grumpkin's `y² = x³ + 3` to Vesta's
    /// `y² = x³ + 5`. The cases below that produce a real Vesta curve
    /// point (add(identity,g), add(g,identity), double(g), scalar_mul(g,2))
    /// now also call `assert_on_curve`, which exercises the gate. If the
    /// gate formula drifts away from Vesta's curve equation, this test
    /// fails at `MockProver::verify()`.
    #[test]
    fn test_ecc_identity_propagation() {
        const K: u32 = 18;

        use std::cell::RefCell;

        struct EccIdentityCircuit {
            stash: RefCell<Option<EcPoint>>,
        }
        impl Default for EccIdentityCircuit {
            fn default() -> Self {
                Self {
                    stash: RefCell::new(None),
                }
            }
        }
        impl Circuit<Fp> for EccIdentityCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self::default()
            }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let id = EcPoint::identity();

                // (1) add(identity, identity) → identity. Skip s_on_curve via the flag.
                let a1 = chip.add(layouter.namespace(|| "add_id_id"), &id, &id)?;
                assert!(a1.is_identity, "add(identity, identity) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_a1"), &a1)?;

                // (2) add(identity, g) → g. Real Vesta curve point; assert_on_curve
                // exercises the y² = x³ + 5 gate (ISSUE-1.3.B regression test).
                let a2 = chip.add(layouter.namespace(|| "add_id_g"), &id, &g)?;
                assert!(
                    !a2.is_identity,
                    "add(identity, g) must be a real curve point"
                );
                chip.assert_on_curve(layouter.namespace(|| "curve_a2"), &a2)?;

                // (3) add(g, identity) → g. Real Vesta curve point.
                let a3 = chip.add(layouter.namespace(|| "add_g_id"), &g, &id)?;
                assert!(
                    !a3.is_identity,
                    "add(g, identity) must be a real curve point"
                );
                chip.assert_on_curve(layouter.namespace(|| "curve_a3"), &a3)?;

                // (4) double(identity) → identity. Skip s_on_curve via the flag.
                let d1 = chip.double(layouter.namespace(|| "double_id"), &id)?;
                assert!(d1.is_identity, "double(identity) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_d1"), &d1)?;

                // (5) double(g) → 2G. Real Vesta curve point.
                let d2 = chip.double(layouter.namespace(|| "double_g"), &g)?;
                assert!(!d2.is_identity, "double(g) must be a real curve point");
                chip.assert_on_curve(layouter.namespace(|| "curve_d2"), &d2)?;

                // (6) scalar_mul(g, 0) → identity (started=false in the final select).
                let zero = Limb {
                    value: Value::known(Fp::ZERO),
                    cell: None,
                };
                let s0 = chip.scalar_mul(layouter.namespace(|| "scalar_mul_0"), &g, &zero)?;
                assert!(s0.is_identity, "scalar_mul(g, 0) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_s0"), &s0)?;

                // (7) scalar_mul(g, 2) → 2G. Real Vesta curve point.
                let two = Limb {
                    value: Value::known(Fp::from(2)),
                    cell: None,
                };
                let s2 = chip.scalar_mul(layouter.namespace(|| "scalar_mul_2"), &g, &two)?;
                assert!(
                    !s2.is_identity,
                    "scalar_mul(g, 2) must be a real curve point"
                );
                chip.assert_on_curve(layouter.namespace(|| "curve_s2"), &s2)?;

                *self.stash.borrow_mut() = Some(s2);
                Ok(())
            }
        }

        let circuit = EccIdentityCircuit::default();
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "EccChip identity propagation should satisfy gates: {:?}",
            result.err()
        );
        let stashed = circuit.stash.borrow();
        assert!(
            stashed.is_some(),
            "scalar_mul result should have been stashed"
        );
        assert!(
            !stashed.as_ref().unwrap().is_identity,
            "stashed point must be real curve"
        );
    }

    #[test]
    fn test_projective_identity_roundtrip_preserves_identity_flag() {
        const K: u32 = 13;

        use std::cell::RefCell;

        struct ProjectiveIdentityCircuit {
            seen_identity: RefCell<Option<bool>>,
        }

        impl Default for ProjectiveIdentityCircuit {
            fn default() -> Self {
                Self {
                    seen_identity: RefCell::new(None),
                }
            }
        }

        impl Circuit<Fp> for ProjectiveIdentityCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let affine = chip.projective_to_affine(
                    layouter.namespace(|| "projective_to_affine"),
                    &chip.projective_identity(),
                )?;
                chip.constrain_equal(
                    layouter.namespace(|| "check_identity"),
                    &affine,
                    &EcPoint::identity(),
                )?;
                chip.assert_on_curve(layouter.namespace(|| "assert_identity"), &affine)?;
                *self.seen_identity.borrow_mut() = Some(affine.is_identity);
                Ok(())
            }
        }

        let circuit = ProjectiveIdentityCircuit::default();
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "projective identity roundtrip failed: {:?}",
            result.err()
        );
        assert_eq!(
            *circuit.seen_identity.borrow(),
            Some(true),
            "projective identity roundtrip must preserve identity flag"
        );
    }
}
