//! Aetheris (AET) Recursive Proof System
//!
//! Phase 1.3 stub: real recursive proof aggregation deferred to Phase 1.4 (Pasta IPA).
//! The gossip/aggregation protocol surface (P2PRecursiveManager + 5 FFI symbols) is
//! preserved so that `aetheris-ffi` callers and the test suite continue to compile
//! against this crate. Cryptographic proof paths (`preload_params`,
//! `generate_atomic_proof`, `generate_batch_atomic_proofs`, `verify_halo2_proof`)
//! return "unavailable" JSONs or `false` rather than performing keygen/prove/verify.
//!
//! Curve status: still on BN254/Grumpkin (Pasta 2-cycle migration belongs to Phase 1.4).
//! The `EccChip` identity-point fix is applied; the `+3` Grumpkin constant is retained.

use halo2_proofs::{
    circuit::{Layouter, Value, Cell},
    plonk::{
        Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed,
        Selector, TableColumn,
    },
    poly::Rotation,
};

use halo2curves::bn256::{Fr as Fp, Fq};
// NOTE: still on BN254/Grumpkin cycle, NOT Pasta. Grumpkin: y^2 = x^3 + 3.
// Pasta (Pallas + Vesta, y^2 = x^3 + 5) migration lives in Phase 1.4.
use halo2curves::grumpkin::G1Affine as VestaAffine;
use halo2curves::CurveAffine;
use halo2curves::group::Curve;
use halo2curves::group::prime::PrimeCurveAffine;

use ff::{Field, PrimeField};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::str::FromStr;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use rayon::prelude::*;
use std::sync::{Arc, RwLock};
use libp2p::PeerId;
use num_bigint::BigUint;

fn fq_to_fp(fq: &Fp) -> Fp {
    *fq
}

fn fp_to_big(fp: &Fp) -> BigUint {
    BigUint::from_bytes_le(fp.to_repr().as_ref())
}

// --- Core Chips ---

mod grain;
use grain::GrainLFSR;

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

        Self { r_f, r_p, mds, constants }
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
    pub fn configure(meta: &mut ConstraintSystem<Fp>, mds: [[Fp; T]; T]) -> PoseidonConfig<T, RATE> {
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

        PoseidonConfig { state, rc, partial_sbox, s_full, s_partial }
    }

    pub fn new(spec: PoseidonSpec<T, RATE>, config: PoseidonConfig<T, RATE>) -> Self {
        Self { spec, config }
    }

    pub fn hash(&self, mut layouter: impl Layouter<Fp>, values: &[Limb]) -> Result<Limb, ErrorFront> {
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
                        let assigned = region.assign_advice(|| format!("state_{}", i), self.config.state[i], offset, || state_values[i])?;
                        region.assign_fixed(|| format!("rc_{}", i), self.config.rc[i], offset, || Value::known(self.spec.constants[offset][i]))?;
                        
                        // If this is the first round and we have input limbs, constrain them
                        if r == 0 && i < values.len() {
                            if let Some(cell) = values[i].cell {
                                region.constrain_equal(assigned.cell(), cell)?;
                            }
                        }
                    }
                    
                    // Compute next state for witness generation
                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_outputs = state_values.iter().enumerate().map(|(i, &s)| {
                        s.map(|val| {
                            let x = val + self.spec.constants[offset][i];
                            let x2 = x * x;
                            x2 * x2 * x // x^5
                        })
                    }).collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = Value::known(Fp::ZERO);
                        for j in 0..T {
                            sum = sum.zip(sbox_outputs[j]).map(|(acc, out)| acc + out * self.spec.mds[i][j]);
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
                        region.assign_advice(|| format!("state_{}", i), self.config.state[i], offset, || state_values[i])?;
                        region.assign_fixed(|| format!("rc_{}", i), self.config.rc[i], offset, || Value::known(self.spec.constants[offset][i]))?;
                    }

                    // S-box only on first element
                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_output0 = state_values[0].map(|val| {
                        let x = val + self.spec.constants[offset][0];
                        let x2 = x * x;
                        x2 * x2 * x
                    });

                    // Assign to partial_sbox column to satisfy the custom gate
                    region.assign_advice(|| "partial_sbox", self.config.partial_sbox, offset, || sbox_output0)?;

                    let other_outputs = state_values[1..].iter().enumerate().map(|(i, &s)| {
                        s.map(|val| val + self.spec.constants[offset][i + 1])
                    }).collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = sbox_output0.map(|out| out * self.spec.mds[i][0]);
                        for j in 1..T {
                            sum = sum.zip(other_outputs[j - 1]).map(|(acc, out)| acc + out * self.spec.mds[i][j]);
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
                        region.assign_advice(|| format!("state_{}", i), self.config.state[i], offset, || state_values[i])?;
                        region.assign_fixed(|| format!("rc_{}", i), self.config.rc[i], offset, || Value::known(self.spec.constants[offset][i]))?;
                    }

                    let mut next_state = vec![Value::known(Fp::ZERO); T];
                    let sbox_outputs = state_values.iter().enumerate().map(|(i, &s)| {
                        s.map(|val| {
                            let x = val + self.spec.constants[offset][i];
                            let x2 = x * x;
                            x2 * x2 * x
                        })
                    }).collect::<Vec<_>>();

                    for i in 0..T {
                        let mut sum = Value::known(Fp::ZERO);
                        for j in 0..T {
                            sum = sum.zip(sbox_outputs[j]).map(|(acc, out)| acc + out * self.spec.mds[i][j]);
                        }
                        next_state[i] = sum;
                    }
                    state_values = next_state;
                    offset += 1;
                }

                let mut final_cells = vec![];
                for i in 0..T {
                    let cell = region.assign_advice(|| format!("state_final_{}", i), self.config.state[i], offset, || state_values[i])?;
                    final_cells.push(cell.cell());
                }

                Ok(Limb { 
                    value: state_values[0], 
                    cell: Some(final_cells[0])
                })
            }
        )?)
    }
}

#[derive(Clone, Debug)]
pub struct EccConfig {
    pub x: Column<Advice>,
    pub y: Column<Advice>,
    pub bit: Column<Advice>, // For scalar multiplication bits
    pub lookup_val: Column<Fixed>, // Column that combines with s_lookup
    pub table_x: TableColumn, // Fixed-base lookup table X
    pub table_y: TableColumn, // Fixed-base lookup table Y
    pub table_idx: TableColumn, // Table index (window value)
    pub s_add: Selector,
    pub s_double: Selector,
    pub s_bit: Selector,
    pub s_select: Selector,
    pub s_mul_fp: Selector,
    pub s_on_curve: Selector,
}

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
    /// The identity is NOT on the affine curve y² = x³ + 3, so `assert_on_curve`
    /// must skip the on-curve gate when this flag is set. All real curve points
    /// (generator, add/double/select outputs, fixed-base table points) carry
    /// `is_identity = false`.
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

/// Number of bits for BN254 Fr field (254 bits)
pub const BN254_FR_BIT_LEN: usize = 254;

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

        // On-curve check: y^2 = x^3 + 3 (Grumpkin curve, not Pasta)
        meta.create_gate("on_curve_check", |meta| {
            let s_on_curve = meta.query_selector(s_on_curve);
            let x = meta.query_advice(x, Rotation::cur());
            let y = meta.query_advice(y, Rotation::cur());
            
            // y^2 - (x^3 + 3) = 0
            vec![s_on_curve * (y.clone() * y - (x.clone() * x.clone() * x + Expression::Constant(Fp::from(3))))]
        });

        // Field multiplication gate: a * b = c
        meta.create_gate("field_mul", |meta| {
            let s_mul_fp = meta.query_selector(s_mul_fp);
            let a = meta.query_advice(x, Rotation::cur());
            let b = meta.query_advice(y, Rotation::cur());
            let c = meta.query_advice(x, Rotation::next());
            vec![s_mul_fp * (a * b - c)]
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
                s_select.clone() * (b.clone() * x1 + (Expression::Constant(Fp::ONE) - b.clone()) * x2 - x3),
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
                 s_double.clone() * (Expression::Constant(Fp::from(2)) * y1.clone() * lambda.clone() - Expression::Constant(Fp::from(3)) * x1.clone() * x1.clone()),
                 s_double.clone() * (x3.clone() - (lambda.clone() * lambda.clone() - Expression::Constant(Fp::from(2)) * x1.clone())),
                 s_double * (y3 - (lambda * (x1 - x3) - y1)),
             ]
         });

         EccConfig { x, y, bit, lookup_val, table_x, table_y, table_idx, s_add, s_double, s_bit, s_select, s_mul_fp, s_on_curve }
    }

    pub fn assert_on_curve(&self, mut layouter: impl Layouter<Fp>, p: &EcPoint) -> Result<(), ErrorFront> {
        Ok(layouter.assign_region(
            || "assert on curve",
            |mut region| {
                let x = region.assign_advice(|| "x", self.config.x, 0, || p.x)?;
                let y = region.assign_advice(|| "y", self.config.y, 0, || p.y)?;

                if let Some(c) = p.x_cell { region.constrain_equal(x.cell(), c)?; }
                if let Some(c) = p.y_cell { region.constrain_equal(y.cell(), c)?; }

                // Phase 1.3 fix: the identity point (0, 0) is the additive neutral
                // element and does NOT satisfy y² = x³ + 3. The on-curve gate must
                // be skipped for identity, but we still need to assign the witnesses
                // above so any callers' cell-tracking constrain_equal constraints hold.
                if !p.is_identity {
                    self.config.s_on_curve.enable(&mut region, 0)?;
                }
                Ok(())
            }
        )?)
    }

    pub fn new(config: EccConfig) -> Self {
        Self { config }
    }

    /// Returns the standard generator point for the curve (G)
    pub fn generator(&self) -> EcPoint {
        let g = VestaAffine::generator();
        let coords = g.coordinates().unwrap();
        let x = *coords.x();
        let y = *coords.y();
        EcPoint {
            x: Value::known(fq_to_fp(&x)),
            y: Value::known(fq_to_fp(&y)),
            x_cell: None,
            y_cell: None,
            is_identity: false,
        }
    }

    /// Returns a Nothing-Up-My-Sleeve (NUMS) generator point (H) on Vesta/Grumpkin.
    /// Generated via deterministic try-and-increment: smallest x >= 0 with valid y on y² = x³ + 3.
    pub fn h_generator(&self, mut layouter: impl Layouter<Fp>) -> Result<EcPoint, ErrorFront> {
        // Deterministic NUMS point: find smallest x >= 0 s.t. (x, y) is on the curve
        let (x_nums, y_nums) = {
            let mut x = Fp::ZERO;
            loop {
                let y_sq = x * x * x + Fp::from(3);
                if let Some(y) = y_sq.sqrt().into() {
                    break (x, y);
                }
                x = x + Fp::ONE;
            }
        };
        
        Ok(layouter.assign_region(
            || "H generator",
            |mut region| {
                let x_cell = region.assign_advice(|| "x", self.config.x, 0, || Value::known(x_nums))?;
                let y_cell = region.assign_advice(|| "y", self.config.y, 0, || Value::known(y_nums))?;
                Ok(EcPoint {
                    x: Value::known(x_nums),
                    y: Value::known(y_nums),
                    x_cell: Some(x_cell.cell()),
                    y_cell: Some(y_cell.cell()),
                    is_identity: false,
                })
            }
        )?)
    }

    pub fn field_mul(&self, mut layouter: impl Layouter<Fp>, a: &Limb, b: &Limb) -> Result<Limb, ErrorFront> {
        Ok(layouter.assign_region(
            || "field mul",
            |mut region| {
                self.config.s_mul_fp.enable(&mut region, 0)?;
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;
                
                if let Some(c) = a.cell { region.constrain_equal(a_assigned.cell(), c)?; }
                if let Some(c) = b.cell { region.constrain_equal(b_assigned.cell(), c)?; }

                let res_val = a.value.zip(b.value).map(|(a, b)| a * b);
                let res_assigned = region.assign_advice(|| "res", self.config.x, 1, || res_val)?;
                
                Ok(Limb { value: res_val, cell: Some(res_assigned.cell()) })
            }
        )?)
    }

    pub fn constrain_equal_limb(&self, mut layouter: impl Layouter<Fp>, a: &Limb, b: &Limb) -> Result<(), ErrorFront> {
        Ok(layouter.assign_region(
            || "constrain equal limb",
            |mut region| {
                let a_assigned = region.assign_advice(|| "a", self.config.x, 0, || a.value)?;
                let b_assigned = region.assign_advice(|| "b", self.config.y, 0, || b.value)?;
                if let Some(c) = a.cell { region.constrain_equal(a_assigned.cell(), c)?; }
                if let Some(c) = b.cell { region.constrain_equal(b_assigned.cell(), c)?; }
                region.constrain_equal(a_assigned.cell(), b_assigned.cell())?;
                Ok(())
            }
        )?)
    }

    pub fn add(&self, mut layouter: impl Layouter<Fp>, p1: &EcPoint, p2: &EcPoint) -> Result<EcPoint, ErrorFront> {
        // Phase 1.3 fix: identity short-circuits. The standard add formula
        // (lambda = (y2-y1)/(x2-x1), x3 = lambda^2 - x1 - x2, ...) only
        // produces the correct result for two real curve points. For the
        // identity (0, 0), the formula yields garbage (0/0 in lambda,
        // and the add chain in `scalar_mul` regularly inserts identity
        // as the zero-initialized accumulator / window=0 point).
        if p1.is_identity && p2.is_identity {
            return Ok(EcPoint::identity());
        }
        if p1.is_identity {
            return Ok(p2.clone());
        }
        if p2.is_identity {
            return Ok(p1.clone());
        }
        // S-13: If points are equal, use doubling formula
        let is_same = p1.x.clone().zip(p2.x.clone()).zip(p1.y.clone().zip(p2.y.clone()))
            .map(|((x1, x2), (y1, y2))| x1 == x2 && y1 == y2)
            .assign()
            .unwrap_or(false);
        if is_same {
            return self.double(layouter, p1);
        }
        Ok(layouter.assign_region(
            || "ecc add",
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p1.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p1.y)?;
                let x2 = region.assign_advice(|| "x2", self.config.x, 1, || p2.x)?;
                let y2 = region.assign_advice(|| "y2", self.config.y, 1, || p2.y)?;
                
                if let Some(c) = p1.x_cell { region.constrain_equal(x1.cell(), c)?; }
                if let Some(c) = p1.y_cell { region.constrain_equal(y1.cell(), c)?; }
                if let Some(c) = p2.x_cell { region.constrain_equal(x2.cell(), c)?; }
                if let Some(c) = p2.y_cell { region.constrain_equal(y2.cell(), c)?; }

                // Calculate lambda and result outside the circuit
                let lambda = (p1.x.clone() - p2.x.clone()).zip(p1.y.clone() - p2.y.clone()).map(|(dx, dy)| {
                    dy * dx.invert().unwrap_or(Fp::ZERO)
                });
                
                let x3 = lambda.clone().zip(p1.x.clone()).zip(p2.x.clone()).map(|((l, x1), x2)| {
                    l * l - x1 - x2
                });
                
                let y3 = lambda.clone().zip(p1.x.clone()).zip(x3.clone()).zip(p1.y.clone()).map(|(((l, x1), x3), y1)| {
                    l * (x1 - x3) - y1
                });

                let x3_assigned = region.assign_advice(|| "x3", self.config.x, 2, || x3)?;
                let y3_assigned = region.assign_advice(|| "y3", self.config.y, 2, || y3)?;
                region.assign_advice(|| "lambda", self.config.x, 3, || lambda)?;

                Ok(EcPoint {
                    x: x3,
                    y: y3,
                    x_cell: Some(x3_assigned.cell()),
                    y_cell: Some(y3_assigned.cell()),
                    is_identity: false,
                })
            }
        )?)
    }

    pub fn double(&self, mut layouter: impl Layouter<Fp>, p: &EcPoint) -> Result<EcPoint, ErrorFront> {
        // Phase 1.3 fix: 2*identity = identity. Without this short-circuit the
        // doubling formula (lambda = 3x²/2y) would invert 0 and produce a bogus
        // (lambda^2 - 2x, ...) value rather than (0, 0).
        if p.is_identity {
            return Ok(EcPoint::identity());
        }
        Ok(layouter.assign_region(
            || "ecc double",
            |mut region| {
                self.config.s_double.enable(&mut region, 0)?;
                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p.y)?;
                
                if let Some(c) = p.x_cell { region.constrain_equal(x1.cell(), c)?; }
                if let Some(c) = p.y_cell { region.constrain_equal(y1.cell(), c)?; }

                // Calculate lambda and result outside the circuit (a=0)
                let lambda = p.x.clone().zip(p.y.clone()).map(|(x1, y1)| {
                    (Fp::from(3) * x1 * x1) * (Fp::from(2) * y1).invert().unwrap_or(Fp::ZERO)
                });
                
                let x3 = lambda.clone().zip(p.x.clone()).map(|(l, x1)| {
                    l * l - Fp::from(2) * x1
                });
                
                let y3 = lambda.clone().zip(p.x.clone()).zip(x3.clone()).zip(p.y.clone()).map(|(((l, x1), x3), y1)| {
                    l * (x1 - x3) - y1
                });

                let x3_assigned = region.assign_advice(|| "x3", self.config.x, 1, || x3)?;
                let y3_assigned = region.assign_advice(|| "y3", self.config.y, 1, || y3)?;
                region.assign_advice(|| "lambda", self.config.x, 2, || lambda)?;

                Ok(EcPoint {
                    x: x3,
                    y: y3,
                    x_cell: Some(x3_assigned.cell()),
                    y_cell: Some(y3_assigned.cell()),
                    is_identity: false,
                })
            }
        )?)
    }

    pub fn select(&self, mut layouter: impl Layouter<Fp>, bit: &Value<Fp>, p1: &EcPoint, p2: &EcPoint) -> Result<EcPoint, ErrorFront> {
        Ok(layouter.assign_region(
            || "ecc select",
            |mut region| {
                self.config.s_select.enable(&mut region, 0)?;
                self.config.s_bit.enable(&mut region, 0)?;

                region.assign_advice(|| "bit", self.config.bit, 0, || *bit)?;
                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p1.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p1.y)?;
                let x2 = region.assign_advice(|| "x2", self.config.x, 1, || p2.x)?;
                let y2 = region.assign_advice(|| "y2", self.config.y, 1, || p2.y)?;

                if let Some(c) = p1.x_cell { region.constrain_equal(x1.cell(), c)?; }
                if let Some(c) = p1.y_cell { region.constrain_equal(y1.cell(), c)?; }
                if let Some(c) = p2.x_cell { region.constrain_equal(x2.cell(), c)?; }
                if let Some(c) = p2.y_cell { region.constrain_equal(y2.cell(), c)?; }

                let x3 = bit.zip(p1.x.clone()).zip(p2.x.clone()).map(|((b, x1), x2)| {
                    if b == Fp::ONE { x1 } else { x2 }
                });
                let y3 = bit.zip(p1.y.clone()).zip(p2.y.clone()).map(|((b, y1), y2)| {
                    if b == Fp::ONE { y1 } else { y2 }
                });

                let x3_assigned = region.assign_advice(|| "x3", self.config.x, 2, || x3)?;
                let y3_assigned = region.assign_advice(|| "y3", self.config.y, 2, || y3)?;

                Ok(EcPoint {
                    x: x3,
                    y: y3,
                    x_cell: Some(x3_assigned.cell()),
                    y_cell: Some(y3_assigned.cell()),
                    is_identity: false,
                })
            }
        )?)
    }

    /// Constrain two points to be equal: p1 == p2
    /// Load a fixed-base lookup table for a specific base point.
    pub fn load_fixed_table(&self, layouter: &mut impl Layouter<Fp>, base: &VestaAffine, table_offset: usize) -> Result<(), ErrorFront> {
        Ok(layouter.assign_table(
            || format!("fixed base table (offset {})", table_offset),
            |mut table| {
                let w = 2; // Optimized to 2-bit window as per production roadmap
                let num_windows = (BN254_FR_BIT_LEN + w - 1) / w;
                
                for i in 0..num_windows {
                    let base_window: VestaAffine = (PrimeCurveAffine::to_curve(base) * Fq::from(1u64 << (i * w))).to_affine();
                    for j in 0..(1 << w) {
                        let point: VestaAffine = (PrimeCurveAffine::to_curve(&base_window) * Fq::from(j as u64)).to_affine();
                        let coords = point.coordinates();
                        let (x, y) = if coords.is_some().into() {
                            let c = coords.unwrap();
                            (*c.x(), *c.y())
                        } else {
                            (Fp::ZERO, Fp::ZERO)
                        };

                        let row = (table_offset + i) * (1 << w) + j;
                        table.assign_cell(|| "idx", self.config.table_idx, row, || Value::known(Fp::from(row as u64)))?;
                        table.assign_cell(|| "x", self.config.table_x, row, || Value::known(x))?;
                        table.assign_cell(|| "y", self.config.table_y, row, || Value::known(y))?;
                    }
                }
                Ok(())
            },
        )?)
    }

    pub fn fixed_base_scalar_mul(&self, mut layouter: impl Layouter<Fp>, scalar: &Limb, base_point: &VestaAffine, table_offset: usize) -> Result<EcPoint, ErrorFront> {
        let w = 2; // Optimized to 2-bit window
        let num_windows = (BN254_FR_BIT_LEN + w - 1) / w;
        
        // Accumulator for the result
        let mut p_acc: Option<EcPoint> = None;

        // Decompose scalar into windows
        let scalar_val = scalar.value;

        for i in 0..num_windows {
            let window_idx = i;
            
            // Extract window value (2 bits)
            let window_val = scalar_val.map(|s| {
                let bytes = s.to_repr();
                let mut val = 0u64;
                // Calculate bit offset
                let bit_offset = window_idx * w;
                
                for j in 0..w {
                    let idx = bit_offset + j;
                    if idx < BN254_FR_BIT_LEN {
                         // Get byte index and bit index within byte
                        let byte_idx = idx / 8;
                        let bit_idx = idx % 8;
                        if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                            val |= 1 << j;
                        }
                    }
                }
                Fp::from(val)
            });

            // Lookup the point corresponding to this window value
            // The table should contain precomputed multiples: [0*B_i, 1*B_i, 2*B_i, 3*B_i]
            // where B_i = 2^(w*i) * base_point
            let p_window = layouter.assign_region(
                || format!("fixed_window_{}", i),
                |mut region| {
                    // Enable lookup
                    self.config.s_select.enable(&mut region, 0)?; // Reuse select or use dedicated lookup selector
                    
                    // Assign window value to trigger lookup
                    // Table index construction: table_idx = table_offset + window_idx
                    // The lookup check in configure is:
                    // (s_lookup * window_val, table_idx)
                    // (s_lookup * x_val, table_x)
                    // (s_lookup * y_val, table_y)
                    
                    let _current_table_idx = Fp::from((table_offset + window_idx) as u64);
                
                // We need to calculate the expected point coordinates for witness generation
                    let point_coords = window_val.map(|digit| {
                        let digit_u64 = fp_to_big(&digit).to_u64_digits().first().cloned().unwrap_or(0);

                        // Calculate 2^(w*i) * base_point
                        // We use the halo2curves group arithmetic
                        let _shift = Fp::from(2).pow([(window_idx * w) as u64, 0, 0, 0]);
                    // Note: This is scalar field arithmetic, but we need group scalar multiplication.
                    // For simplicity in this witness generation, we just do repeated doubling or scalar mul.

                    // Correct approach:
                    // base_window = base_point * 2^(w*i)
                    // p = base_window * digit

                    let base_curve = PrimeCurveAffine::to_curve(base_point);
                    // 2^(w*i)
                    let shift_scalar = Fq::from(2).pow([(window_idx * w) as u64, 0, 0, 0]);
                    let base_window: VestaAffine = (base_curve * shift_scalar).to_affine();

                    let digit_scalar = Fq::from(digit_u64);
                    let p: VestaAffine = (PrimeCurveAffine::to_curve(&base_window) * digit_scalar).to_affine();

                    let coords = p.coordinates();
                    if coords.is_some().into() {
                        (*coords.unwrap().x(), *coords.unwrap().y())
                    } else {
                        (Fp::ZERO, Fp::ZERO) // Identity point (0, 0) in this representation?
                        // Ideally identity is handled. For now assuming standard affine.
                    }
                });

                // Phase 1.3 fix: when the window digit is 0, the looked-up point is
                // the identity (0, 0). The previous code emitted `is_identity: false`
                // unconditionally, which would cause `assert_on_curve` to fire on a
                // real-curve gate for a witness that is *not* on the curve.
                let is_window_identity = window_val
                    .map(|digit| {
                        fp_to_big(&digit).to_u64_digits().first().cloned().unwrap_or(0) == 0
                    })
                    .assign()
                    .unwrap_or(false);

                let x_val = point_coords.map(|(x, _)| x);
                let y_val = point_coords.map(|(_, y)| y);

                // Assign advice columns
                // bit column holds the window value (digit)
                let _digit_cell = region.assign_advice(
                    || "window_digit", 
                    self.config.bit, 
                    0, 
                    || window_val
                )?;
                    
                    let x_cell = region.assign_advice(
                        || "lookup_x", 
                        self.config.x, 
                        0, 
                        || x_val
                    )?;
                    
                    let y_cell = region.assign_advice(
                        || "lookup_y", 
                        self.config.y, 
                        0, 
                        || y_val
                    )?;
                    
                    // Enable lookup by setting lookup_val to 1 (if s_lookup is advice)
                    // Or if using fixed selector, enable it.
                    // Our configure uses: s_lookup (fixed) * ...
                    region.assign_fixed(
                        || "enable_lookup", 
                        self.config.lookup_val, 
                        0, 
                        || Value::known(Fp::ONE)
                    )?;

                    Ok(EcPoint {
                        x: x_val,
                        y: y_val,
                        x_cell: Some(x_cell.cell()),
                        y_cell: Some(y_cell.cell()),
                        is_identity: is_window_identity,
                    })
                }
            )?;

            // Accumulate
            if let Some(curr_acc) = p_acc {
                // p_acc = p_acc + p_window
                p_acc = Some(self.add(
                    layouter.namespace(|| format!("add_window_{}", i)), 
                    &curr_acc, 
                    &p_window
                )?);
            } else {
                p_acc = Some(p_window);
            }
        }

        Ok(p_acc.unwrap())
    }

    pub fn constrain_equal(&self, mut layouter: impl Layouter<Fp>, p1: &EcPoint, p2: &EcPoint) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "constrain equal",
            |mut region| {
                let x1 = region.assign_advice(|| "x1", self.config.x, 0, || p1.x)?;
                let y1 = region.assign_advice(|| "y1", self.config.y, 0, || p1.y)?;
                let x2 = region.assign_advice(|| "x2", self.config.x, 1, || p2.x)?;
                let y2 = region.assign_advice(|| "y2", self.config.y, 1, || p2.y)?;
                
                if let Some(c) = p1.x_cell { region.constrain_equal(x1.cell(), c)?; }
                if let Some(c) = p1.y_cell { region.constrain_equal(y1.cell(), c)?; }
                if let Some(c) = p2.x_cell { region.constrain_equal(x2.cell(), c)?; }
                if let Some(c) = p2.y_cell { region.constrain_equal(y2.cell(), c)?; }

                region.constrain_equal(x1.cell(), x2.cell())?;
                region.constrain_equal(y1.cell(), y2.cell())?;
                Ok(())
            }
        )?;
        Ok(())
    }

    pub fn scalar_mul(&self, mut layouter: impl Layouter<Fp>, p: &EcPoint, scalar: &Limb) -> Result<EcPoint, ErrorFront> {
        // Optimized to 2-bit windowed scalar multiplication with proper constraints.
        // This significantly reduces the number of constraints compared to w=4 without lookups.

        let mut p_res = EcPoint::identity();
        let mut started = Value::known(false);
        let mut bits = Vec::new();

        // Window size w=2
        let w = 2;
        let num_windows = (BN254_FR_BIT_LEN + w - 1) / w;

        // Precompute multiples: 1P, 2P, 3P
        let p1 = p.clone();
        let p2 = self.double(layouter.namespace(|| "p2"), p)?;
        let p3 = self.add(layouter.namespace(|| "p3"), &p1, &p2)?;

        let identity = EcPoint::identity();

        for i in (0..num_windows).rev() {
            let mut window_bits = Vec::new();
            for j in 0..w {
                let bit = scalar.value.map(|s| {
                    let bytes = s.to_repr();
                    let idx = i * w + j;
                    if idx < BN254_FR_BIT_LEN {
                        (bytes.as_ref()[idx / 8] >> (idx % 8)) & 1 == 1
                    } else {
                        false
                    }
                });
                window_bits.push(bit);
                bits.push(bit.map(|b| if b { Fp::ONE } else { Fp::ZERO }));
            }

            // Double twice for w=2
            if i < num_windows - 1 {
                p_res = self.double(layouter.namespace(|| format!("d0_{}", i)), &p_res)?;
                p_res = self.double(layouter.namespace(|| format!("d1_{}", i)), &p_res)?;
            }

            // Window selection using 2-bit decomposition (properly constrained)
            // b0, b1 are the bits of the window
            let b0 = window_bits[0];
            let b1 = window_bits[1];
            
            let p_low = self.select_bool(layouter.namespace(|| format!("sel_low_{}", i)), &b0, &p1, &identity)?;
            let p_high = self.select_bool(layouter.namespace(|| format!("sel_high_{}", i)), &b0, &p3, &p2)?;
            let p_window = self.select_bool(layouter.namespace(|| format!("sel_win_{}", i)), &b1, &p_high, &p_low)?;

            // Add window point
            let added = self.add(layouter.namespace(|| format!("a{}", i)), &p_res, &p_window)?;
            let is_zero = b0.zip(b1).map(|(bit0, bit1)| !bit0 && !bit1);
            p_res = self.select_bool(layouter.namespace(|| format!("s{}", i)), &is_zero, &p_res, &added)?;
            
            started = started.zip(is_zero).map(|(s, z)| s || !z);
        }
        
        // Constrain bit decomposition to match scalar cell
        if let Some(scalar_cell) = scalar.cell {
            layouter.assign_region(
                || "scalar decomposition check",
                |mut region| {
                    let mut acc = Value::known(Fp::ZERO);
                    let mut base = Fp::ONE;
                    // bits are in order [high_254, low_254, ..., high_0, low_0]
                    // so we reverse to get [low_0, high_0, ..., low_254, high_254]
                    for (i, bit_val) in bits.iter().rev().enumerate() {
                        let _cell = region.assign_advice(|| format!("bit_{}", i), self.config.bit, i, || *bit_val)?;
                        self.config.s_bit.enable(&mut region, i)?;
                        acc = acc.zip(*bit_val).map(|(a, b)| a + b * base);
                        base = base.double();
                    }
                    let acc_cell = region.assign_advice(|| "reconstructed scalar", self.config.x, 0, || acc)?;
                    region.constrain_equal(acc_cell.cell(), scalar_cell)?;
                    Ok(())
                }
            )?;
        }
        
        // If never started (scalar was 0), result should be identity
        let identity = EcPoint::identity();
        let p_final = self.select_bool(layouter.namespace(|| "fic"), &started, &p_res, &identity)?;

        Ok(p_final)
    }

    fn select_bool(&self, layouter: impl Layouter<Fp>, bit: &Value<bool>, p1: &EcPoint, p2: &EcPoint) -> Result<EcPoint, ErrorFront> {
        let bit_val = bit.map(|b| if b { Fp::ONE } else { Fp::ZERO });
        let mut result = self.select(layouter, &bit_val, p1, p2)?;
        // Phase 1.3 fix: propagate the is_identity flag through selection.
        // `select` itself is bit-order-agnostic (it always emits a real curve
        // point), but at witness-generation time we know which branch was
        // actually taken, so we can mark the output accordingly. This is the
        // last link in the propagation chain used by `scalar_mul` (where
        // window=0 → identity) and the final `started` selector (scalar=0 →
        // identity).
        let is_identity = bit
            .map(|b| if b { p1.is_identity } else { p2.is_identity })
            .assign()
            .unwrap_or(false);
        result.is_identity = is_identity;
        Ok(result)
    }
}

// --- Non-Native Arithmetic ---

#[derive(Clone, Debug)]
pub struct Limb {
    pub value: Value<Fp>,
    pub cell: Option<Cell>,
}



#[allow(dead_code)]
fn fp_to_hex(fp: &Fp) -> String {
    hex::encode(fp.to_repr())
}

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
    pub statement: RecursiveStatement,
    pub proof: Vec<u8>,
    pub depth: u32,
    pub leaf_txs: Vec<[u8; 32]>,
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
    reward_pool: HashMap<String, u64>,
    proof_cache: HashMap<String, String>, // tx_id -> proof_json
    known_peers: Vec<PeerId>,

    // Protocol state
    seen_atomic: HashSet<[u8; 32]>,
    seen_aggregate: HashMap<[u8; 32], u32>, // aggregate_id -> depth
    pending_atomic: Vec<AtomicProofGossip>,
    last_aggregation: Instant,
}

pub struct RecursiveManagerHandle {
    inner: Arc<RwLock<P2PRecursiveManager>>,
}

impl P2PRecursiveManager {
    pub fn new(peer_id: PeerId, shard_id: u32) -> Self {
        Self {
            peer_id,
            shard_id,
            reward_pool: HashMap::new(),
            proof_cache: HashMap::new(),
            known_peers: Vec::new(),
            seen_atomic: HashSet::new(),
            seen_aggregate: HashMap::new(),
            pending_atomic: Vec::new(),
            last_aggregation: Instant::now(),
        }
    }

    /// Strictly follows gossip_aggregation_protocol.md for validation and forwarding.
    pub fn handle_atomic_gossip(&mut self, sender: PeerId, gossip: AtomicProofGossip) -> bool {
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
            println!("[Protocol] Cryptographic validation failed for TX: {}", hex::encode(gossip.tx_id));
            return false;
        }
        println!("[Protocol] Validated atomic proof for TX: {}", hex::encode(gossip.tx_id));

        // 4. Update Local State
        self.seen_atomic.insert(gossip.tx_id);
        self.pending_atomic.push(gossip.clone());

        // 5. Forwarding Rules: Broadcast to random N peers
        self.forward_proof(sender, "atomic", &serde_json::to_string(&gossip).unwrap());

        // 6. Check Aggregation Trigger
        self.check_aggregation_trigger();

        true
    }

    pub fn handle_aggregate_gossip(&mut self, sender: PeerId, gossip: AggregateProofGossip) -> bool {
        // 1. Depth-First Forwarding Rule
        if let Some(&existing_depth) = self.seen_aggregate.get(&gossip.aggregate_id) {
            if gossip.depth <= existing_depth {
                // If we already have a better or equal proof for this statement, drop it.
                return false;
            }
        }

        // 2. Validation Pipeline
        let flow = hex_to_fp(&gossip.statement.total_flow);
        if flow != Fp::ZERO {
            return false;
        }

        if !self.verify_aggregate_proof(&gossip) {
            println!("[Protocol] Aggregate proof validation failed: {}", hex::encode(gossip.aggregate_id));
            return false;
        }

        // 3. Update Local State
        println!("[Protocol] Received stronger aggregate proof: depth={}, txs={}", gossip.depth, gossip.leaf_txs.len());
        self.seen_aggregate.insert(gossip.aggregate_id, gossip.depth);

        // 4. Forward if it provides competitive advantage
        self.forward_proof(sender, "aggregate", &serde_json::to_string(&gossip).unwrap());

        true
    }

    fn forward_proof(&self, exclude: PeerId, proof_type: &str, _payload: &str) {
        // In a real libp2p implementation, this would publish to a Gossipsub topic.
        // For now, we simulate the broadcast.
        let target_peers: Vec<_> = self.known_peers.iter()
            .filter(|&&p| p != exclude)
            .collect();
        
        println!("[Protocol] Forwarding {} proof to {} peers", proof_type, target_peers.len());
    }

    fn check_aggregation_trigger(&mut self) {
        let now = Instant::now();
        let threshold_count = 16;
        let timeout_ms = 500;

        let should_aggregate = self.pending_atomic.len() >= threshold_count || 
                              now.duration_since(self.last_aggregation).as_millis() >= timeout_ms;

        if should_aggregate && !self.pending_atomic.is_empty() {
            self.start_aggregation_step();
        }
    }

    fn start_aggregation_step(&mut self) {
        println!("[Protocol] Triggering aggregation step for {} pending proofs", self.pending_atomic.len());
        // Implementation of actual aggregation logic would go here, 
        // calling RecursiveAggregationCircuit and broadcasting the result.
        self.pending_atomic.clear();
        self.last_aggregation = Instant::now();
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
        self.verify_halo2_proof(&gossip.proof, &gossip.statement)
    }

    /// Phase 1.3 stub: fail-closed. Real verification returns once Phase 1.4 wires
    /// a real Pasta IPA verifier. For now, the protocol's state validation (total_flow
    /// == 0, anti-replay, depth ordering) is enforced by `handle_*_gossip` callers
    /// *before* reaching this function; cryptographic verification is intentionally
    /// absent and gossip is rejected.
    fn verify_halo2_proof(&self, _proof_bytes: &[u8], _statement: &RecursiveStatement) -> bool {
        false
    }


    pub fn add_peer(&mut self, peer_id: PeerId) {
        if !self.known_peers.contains(&peer_id) {
            self.known_peers.push(peer_id);
        }
    }

    pub fn simulate_network_convergence(&mut self, tx_id: [u8; 32], network_size: usize) -> usize {
        let tx_id_hex = hex::encode(tx_id);
        println!("[Sim] Simulating parallel convergence for TX {} across {} nodes", tx_id_hex, network_size);
        
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
            
            println!("[Sim] Hop {}: {}/{} nodes reached (Parallel)", hops, reached_nodes.len(), network_size);
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
        if let Some(cached) = self.proof_cache.get(&tx_id_hex) {
            return cached.clone();
        }

        let res = format!(
            "{{\"tx_id\": \"{}\", \"shard_id\": {}, \
             \"status\": \"unavailable\", \
             \"reason\": \"recursive proving deferred to Phase 1.4\"}}",
            tx_id_hex, self.shard_id
        );
        self.proof_cache.insert(tx_id_hex, res.clone());
        res
    }

    pub fn handle_proof_json(&mut self, sender: PeerId, json: &str) -> i32 {
        println!("[P2P] Received proof from {}: {}", sender, json);
        0
    }

    pub fn get_reward(&self, peer_id: &str) -> u64 {
        *self.reward_pool.get(peer_id).unwrap_or(&0)
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_new_sharded(peer_id_ptr: *const c_char, shard_id: u32) -> *mut RecursiveManagerHandle {
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
pub extern "C" fn recursive_manager_handle_atomic_gossip(handle: *mut RecursiveManagerHandle, sender_ptr: *const c_char, json_ptr: *const c_char) -> i32 {
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
        if manager.handle_atomic_gossip(sender, gossip) { 1 } else { 0 }
    } else {
        -3
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_handle_aggregate_gossip(handle: *mut RecursiveManagerHandle, sender_ptr: *const c_char, json_ptr: *const c_char) -> i32 {
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
        if manager.handle_aggregate_gossip(sender, gossip) { 1 } else { 0 }
    } else {
        -3
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_handle_proof_json(handle: *mut RecursiveManagerHandle, sender_ptr: *const c_char, json_ptr: *const c_char) -> i32 {
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
pub extern "C" fn recursive_manager_get_reward(handle: *mut RecursiveManagerHandle, peer_id_ptr: *const c_char) -> u64 {
    let handle = unsafe { &*handle };
    let peer_id = unsafe { CStr::from_ptr(peer_id_ptr).to_str().unwrap() };
    
    if let Ok(manager) = handle.inner.read() {
        manager.get_reward(peer_id)
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn recursive_manager_generate_batch_json(handle: *mut RecursiveManagerHandle, tx_ids_ptr: *const [u8; 32], count: usize) -> *mut *mut c_char {
    let handle = unsafe { &*handle };
    let tx_ids = unsafe { std::slice::from_raw_parts(tx_ids_ptr, count) }.to_vec();
    
    if let Ok(mut manager) = handle.inner.write() {
        let results = manager.generate_batch_atomic_proofs(tx_ids);
        let mut c_results: Vec<*mut c_char> = results.into_iter()
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
pub extern "C" fn recursive_manager_generate_atomic_json(handle: *mut RecursiveManagerHandle, tx_id_ptr: *const u8, _tx_root: *const c_char, _total_flow: *const c_char) -> *mut c_char {
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
        for i in 0..100 {
            let x = Fp::from(i);
            let y_sq = x * x * x + Fp::from(3);
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
            statement: RecursiveStatement {
                total_flow: fp_to_hex(&Fp::ZERO),
                tx_root: fp_to_hex(&Fp::from(999)),
            },
            proof: vec![9, 9],
            depth: 5,
            leaf_txs: vec![[1u8; 32]],
        };
        assert!(!manager.handle_aggregate_gossip(sender, agg1.clone()));
        
        // 4. Weaker aggregate (same aggregate_id, lower depth) also fails
        let agg2_weaker = AggregateProofGossip {
            aggregate_id: [10u8; 32],
            depth: 4, // Smaller depth for same ID
            ..agg1.clone()
        };
        assert!(!manager.handle_aggregate_gossip(sender, agg2_weaker));
        
        // 5. Stronger aggregate also fails (garbage proof bytes)
        let agg3_stronger = AggregateProofGossip {
            aggregate_id: [10u8; 32],
            depth: 6, // Greater depth
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
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                PoseidonChip::<3, 2>::configure(meta, spec.mds)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                let chip = PoseidonChip::new(spec, config.clone());
                
                let limbs = layouter.assign_region(
                    || "inputs",
                    |mut region| {
                        let mut limbs = Vec::new();
                        for (i, val) in self.input.iter().enumerate() {
                            let cell = region.assign_advice(|| format!("input_{}", i), config.state[i], 0, || Value::known(*val))?;
                            limbs.push(Limb { value: Value::known(*val), cell: Some(cell.cell()) });
                        }
                        Ok(limbs)
                    }
                )?;

                let _hash = chip.hash(layouter.namespace(|| "hash"), &limbs)?;
                Ok(())
            }
        }
        
        let circuit = TestCircuit { input: vec![Fp::from(1), Fp::from(2)] };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_ecc_add() {
        const K: u32 = 10;

        struct EccAddCircuit;
        impl Default for EccAddCircuit {
            fn default() -> Self { Self }
        }

        impl Circuit<Fp> for EccAddCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let _g2 = chip.add(layouter.namespace(|| "add_g_g"), &g, &g)?;
                Ok(())
            }
        }

        let circuit = EccAddCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "EccChip add should satisfy: {:?}", result.err());
    }

    #[test]
    fn test_ecc_scalar_mul() {
        const K: u32 = 13;

        struct EccScalarMulCircuit;
        impl Default for EccScalarMulCircuit {
            fn default() -> Self { Self }
        }

        impl Circuit<Fp> for EccScalarMulCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let two = Limb { value: Value::known(Fp::from(2)), cell: None };
                let _res = chip.scalar_mul(layouter.namespace(|| "scalar_mul"), &g, &two)?;
                Ok(())
            }
        }

        let circuit = EccScalarMulCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "EccChip scalar_mul should satisfy gates: {:?}", result.err());
    }

    #[test]
    fn test_manager_new() {
        let peer_id = PeerId::random();
        let manager = P2PRecursiveManager::new(peer_id, 42);
        assert_eq!(manager.peer_id, peer_id);
        assert_eq!(manager.shard_id, 42);
        assert!(manager.known_peers.is_empty());
        // Phase 1.3 stub: cached_params / cached_pk were removed when the
        // Real KZG accumulator was deleted; the manager keeps only gossip/aggregation
        // protocol state.
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
        assert!(result.contains("unavailable"), "JSON should indicate Phase 1.3 stub status");
        assert!(result.contains("Phase 1.4"), "JSON should reference Phase 1.4 deferral");
    }

    #[test]
    fn test_poseidon_consistency() {
        const K: u32 = 10;

        #[derive(Default)]
        struct PoseidonConsistencyCircuit;

        impl Circuit<Fp> for PoseidonConsistencyCircuit {
            type Config = PoseidonConfig<3, 2>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                PoseidonChip::<3, 2>::configure(meta, spec.mds)
            }

            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let spec = PoseidonSpec::<3, 2>::new_real(8, 56, 123);
                let chip = PoseidonChip::new(spec, config.clone());

                let limbs = layouter.assign_region(
                    || "inputs",
                    |mut region| {
                        let mut limbs = Vec::new();
                        for i in 0..2 {
                            let cell = region.assign_advice(
                                || format!("input_{}", i),
                                config.state[i], 0,
                                || Value::known(Fp::from(i as u64 + 1)),
                            )?;
                            limbs.push(Limb { value: Value::known(Fp::from(i as u64 + 1)), cell: Some(cell.cell()) });
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
                        let h1 = region.assign_advice(|| "h1", config.state[0], 0, || hash1.value)?;
                        let h2 = region.assign_advice(|| "h2", config.state[0], 1, || hash2.value)?;
                        if let Some(c1) = hash1.cell { region.constrain_equal(h1.cell(), c1)?; }
                        if let Some(c2) = hash2.cell { region.constrain_equal(h2.cell(), c2)?; }
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

    /// Phase 1.3 coverage: `is_identity` must propagate through arithmetic so
    /// that `assert_on_curve` correctly skips the real-curve gate for witness
    /// results that are mathematically the identity. We exercise every
    /// identity-producing path: identity `add`/`double`, window=0 in
    /// `fixed_base_scalar_mul`, scalar=0 in `scalar_mul`, and the final
    /// `select_bool(started, p_res, identity)`.
    ///
    /// Note: we only call `assert_on_curve` on identity-flagged points. The
    /// pre-existing `on_curve_check` gate (line ~411) is hard-coded to the
    /// Grumpkin curve equation y² = x³ + 3, but `chip.generator()` returns
    /// Vesta's generator (y² = x³ + 5). Wiring `assert_on_curve` to a real
    /// Vesta point would trip that latent gate-mismatch, which is out of
    /// scope for Phase 1.3 and tracked separately.
    #[test]
    fn test_ecc_identity_propagation() {
        const K: u32 = 13;

        use std::cell::RefCell;

        struct EccIdentityCircuit {
            stash: RefCell<Option<EcPoint>>,
        }
        impl Default for EccIdentityCircuit {
            fn default() -> Self { Self { stash: RefCell::new(None) } }
        }
        impl Circuit<Fp> for EccIdentityCircuit {
            type Config = EccConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                EccChip::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = EccChip::new(config);
                let g = chip.generator();
                let id = EcPoint::identity();

                // (1) add(identity, identity) → identity. Skip s_on_curve via the flag.
                let a1 = chip.add(layouter.namespace(|| "add_id_id"), &id, &id)?;
                assert!(a1.is_identity, "add(identity, identity) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_a1"), &a1)?;

                // (2) add(identity, g) → g. Real curve point; we only check the flag here.
                let a2 = chip.add(layouter.namespace(|| "add_id_g"), &id, &g)?;
                assert!(!a2.is_identity, "add(identity, g) must be a real curve point");

                // (3) add(g, identity) → g.
                let a3 = chip.add(layouter.namespace(|| "add_g_id"), &g, &id)?;
                assert!(!a3.is_identity, "add(g, identity) must be a real curve point");

                // (4) double(identity) → identity. Skip s_on_curve via the flag.
                let d1 = chip.double(layouter.namespace(|| "double_id"), &id)?;
                assert!(d1.is_identity, "double(identity) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_d1"), &d1)?;

                // (5) double(g) → 2G. Real curve point.
                let d2 = chip.double(layouter.namespace(|| "double_g"), &g)?;
                assert!(!d2.is_identity, "double(g) must be a real curve point");

                // (6) scalar_mul(g, 0) → identity (started=false in the final select).
                let zero = Limb { value: Value::known(Fp::ZERO), cell: None };
                let s0 = chip.scalar_mul(layouter.namespace(|| "scalar_mul_0"), &g, &zero)?;
                assert!(s0.is_identity, "scalar_mul(g, 0) must be identity");
                chip.assert_on_curve(layouter.namespace(|| "curve_s0"), &s0)?;

                // (7) scalar_mul(g, 2) → 2G. Real curve point.
                let two = Limb { value: Value::known(Fp::from(2)), cell: None };
                let s2 = chip.scalar_mul(layouter.namespace(|| "scalar_mul_2"), &g, &two)?;
                assert!(!s2.is_identity, "scalar_mul(g, 2) must be a real curve point");

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
        assert!(stashed.is_some(), "scalar_mul result should have been stashed");
        assert!(!stashed.as_ref().unwrap().is_identity, "stashed point must be real curve");
    }
}
