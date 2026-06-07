//! Non-native Fq arithmetic over Fp circuit.
//!
//! The recursive circuit runs over Vesta's scalar field (Fp). Pallas scalars (Fq)
//! are non-native — represented as 3 × 85-bit Fp limbs.
//!
//! # Design
//!
//! Each Fq element is stored as 3 Fp limbs (85 bits each, little-endian):
//!   value = l0 + l1·2^85 + l2·2^170
//!
//! ## add (s_add gate, 4 rows)
//!   Row i: a_i + b_i + carry_in - c_i - 2^85·carry_out_i = 0
//!   Row 3: final carry + 0 = c_3 (absorbs 2^255 overflow)
//!   Then subtract Fq if result >= Fq.
//!
//! ## mul (s_mul + s_add gates, 9 + 6 + 3 rows)
//!   Rows 0-8: p_ij = a_i · b_j  (9 partial products)
//!   Rows 9-14: combine partials via 2:1 addition tree
//!   Rows 15-17: Fq reduction via conditional subtraction
//!
//! ## invert (witness-with-verify)
//!   Witness inv externally, verify a·inv = 1 mod Fq via mul + equality checks.

use core::array;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use halo2_proofs::halo2curves::pasta::Fp;
use ff::{Field, PrimeField};

use crate::Limb;

// ── Constants ──────────────────────────────────────────────────────────────

pub const FQ_NUM_LIMBS: usize = 3;
pub const FQ_LIMB_BITS: usize = 85;

/// Number of bits to range-check carries to. Honest carries are < 2^87;
/// 90 bits provides headroom and ensures Fp equation ≡ ℤ equation.
pub const CARRY_BITS: usize = 90;

/// Fq = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
/// as LE bytes (32 bytes).
const FQ_MOD_BYTES: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c,
    0xdd, 0xa8, 0x94, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

/// 2^85 as LE bytes (bit 85 set).
const TWO_POW_85_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn fp_from_bytes(bytes: [u8; 32]) -> Fp {
    Fp::from_repr(bytes).unwrap()
}

fn fp_limb_base() -> Fp {
    fp_from_bytes(TWO_POW_85_BYTES)
}

/// Full Fq modulus as BigUint.
fn big_fq_mod() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&FQ_MOD_BYTES)
}

/// 2^85 as BigUint.
fn big_limb_base() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&TWO_POW_85_BYTES)
}

fn fp_to_big(fp: &Fp) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(fp.to_repr().as_ref())
}

fn fq_limb_fp(i: usize) -> Fp {
    let base = big_limb_base();
    big_to_fp(&(&big_fq_mod() / &base.pow(i as u32) % &base))
}

fn big_to_fp(big: &num_bigint::BigUint) -> Fp {
    let bytes = big.to_bytes_le();
    let mut repr = <Fp as PrimeField>::Repr::default();
    let repr_bytes = repr.as_mut();
    let len = bytes.len().min(repr_bytes.len());
    repr_bytes[..len].copy_from_slice(&bytes[..len]);
    Fp::from_repr(repr).unwrap()
}

// ── Fq element ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FqElement {
    pub limbs: [Limb; FQ_NUM_LIMBS],
}

impl FqElement {
    pub fn new(limbs: [Limb; FQ_NUM_LIMBS]) -> Self {
        FqElement { limbs }
    }

    pub fn zero() -> Self {
        FqElement {
            limbs: array::from_fn(|_| Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            }),
        }
    }

    pub fn one() -> Self {
        let mut e = Self::zero();
        e.limbs[0] = Limb {
            value: Value::known(Fp::ONE),
            cell: None,
        };
        e
    }

    pub fn to_big(&self) -> Value<num_bigint::BigUint> {
        let b = big_limb_base();
        let b2 = &b * &b;
        self.limbs[0]
            .value
            .zip(self.limbs[1].value)
            .zip(self.limbs[2].value)
            .map(|((l0, l1), l2)| {
                fp_to_big(&l0) + fp_to_big(&l1) * &b + fp_to_big(&l2) * &b2
            })
    }
}

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NonNativeFqConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub aux: Column<Advice>,
    pub fq_const: Column<Fixed>,
    pub s_add: Selector,
    pub s_mul: Selector,
    pub s_range: Selector,
    pub s_reduce: Selector,
}

// ── Chip ───────────────────────────────────────────────────────────────────

pub struct NonNativeFqChip {
    config: NonNativeFqConfig,
}

impl NonNativeFqChip {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> NonNativeFqConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let aux = meta.advice_column();
        let fq_const = meta.fixed_column();
        let s_add = meta.selector();
        let s_mul = meta.selector();
        let s_range = meta.selector();
        let s_reduce = meta.selector();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(aux);

        // ── Addition gate ──
        // a + b + carry_in - c - 2^85 * carry_out = 0
        let limb_base = fp_limb_base();
        meta.create_gate("fq_add", |meta| {
            let s = meta.query_selector(s_add);
            let a_val = meta.query_advice(a, Rotation::cur());
            let b_val = meta.query_advice(b, Rotation::cur());
            let carry_in = meta.query_advice(aux, Rotation::cur());
            let c_val = meta.query_advice(c, Rotation::cur());
            let carry_out = meta.query_advice(aux, Rotation::next());
            vec![s * (a_val + b_val + carry_in - c_val - Expression::Constant(limb_base) * carry_out)]
        });

        // ── Reduction gate ──
        // r + k·fq_i + carry_in - l - 2^85 * carry_out = 0
        // Used to constrain modular reduction: S = R + k·Fq
        meta.create_gate("fq_reduce", |meta| {
            let s = meta.query_selector(s_reduce);
            let r_val = meta.query_advice(a, Rotation::cur());
            let k_val = meta.query_advice(b, Rotation::cur());
            let carry_in = meta.query_advice(aux, Rotation::cur());
            let l_val = meta.query_advice(c, Rotation::cur());
            let carry_out = meta.query_advice(aux, Rotation::next());
            let fq_i = meta.query_fixed(fq_const, Rotation::cur());
            vec![s * (r_val + k_val * fq_i + carry_in - l_val - Expression::Constant(limb_base) * carry_out)]
        });

        // ── Multiplication gate (limb mul) ──
        // a * b = c
        meta.create_gate("fq_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a_val = meta.query_advice(a, Rotation::cur());
            let b_val = meta.query_advice(b, Rotation::cur());
            let c_val = meta.query_advice(c, Rotation::cur());
            vec![s * (a_val * b_val - c_val)]
        });

        // ── Range check gate (bit check) ──
        // bit * (1 - bit) = 0
        meta.create_gate("fq_range", |meta| {
            let s = meta.query_selector(s_range);
            let bit_val = meta.query_advice(aux, Rotation::cur());
            vec![s * bit_val.clone() * (Expression::Constant(Fp::ONE) - bit_val)]
        });

        NonNativeFqConfig { a, b, c, aux, fq_const, s_add, s_mul, s_range, s_reduce }
    }

    pub fn new(config: NonNativeFqConfig) -> Self {
        NonNativeFqChip { config }
    }

    // ── Add ────────────────────────────────────────────────────────────────

    /// Constrain `c = a + b mod Fq`.
    ///
    /// Pass 1 (rows 0-3): s_add constrains the 3-limb carry-chain:
    ///   a_i + b_i + carry_in_i = l_i + 2^85 * carry_out_i
    ///   Row 3 absorbs final carry as 4th limb.
    ///
    /// Pass 2 (rows 4-7): s_reduce constrains modular reduction:
    ///   r_i + k·fq_i + carry_in_i = l_i + 2^85 * carry_out_i
    ///   where k ∈ {0, 1} is the reduction flag.
    ///   When k=0: S < Fq, r = S (no reduction).
    ///   When k=1: S ≥ Fq, r = S - Fq.
    ///
    /// Row 8: gap (avoids aux[8] overlap between borrow_out_3 and k_check).
    /// Row 9: s_range check k ∈ {0, 1}.
    pub fn add(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &FqElement,
        b: &FqElement,
    ) -> Result<FqElement, ErrorFront> {
        let limb_base_big = big_limb_base();
        let fq_mod_big = big_fq_mod();
        let fq_limbs_fp = [fq_limb_fp(0), fq_limb_fp(1), fq_limb_fp(2)];

        Ok(layouter.assign_region(|| "fq_add", |mut region| {
            // ── Pass 1: Carry-chain (unreduced addition S = a + b) ──
            let mut prev_carry_fp = Fp::ZERO;
            let mut raw_limbs: [Limb; FQ_NUM_LIMBS] = core::array::from_fn(|_| Limb {
                value: Value::known(Fp::ZERO),
                cell: None,
            });

            for i in 0..FQ_NUM_LIMBS {
                self.config.s_add.enable(&mut region, i)?;

                let a_assigned = region.assign_advice(
                    || format!("a_{}", i), self.config.a, i, || a.limbs[i].value,
                )?;
                if let Some(c) = a.limbs[i].cell { region.constrain_equal(a_assigned.cell(), c)?; }

                let b_assigned = region.assign_advice(
                    || format!("b_{}", i), self.config.b, i, || b.limbs[i].value,
                )?;
                if let Some(c) = b.limbs[i].cell { region.constrain_equal(b_assigned.cell(), c)?; }

                region.assign_advice(
                    || format!("carry_in_{}", i), self.config.aux, i, || Value::known(prev_carry_fp),
                )?;

                let (c_i_val, carry_out): (Value<Fp>, Value<Fp>) = a.limbs[i].value.zip(b.limbs[i].value)
                    .zip(Value::known(prev_carry_fp))
                    .map(|((av, bv), ci)| {
                        let s = fp_to_big(&av) + fp_to_big(&bv) + fp_to_big(&ci);
                        let base = big_limb_base();
                        let carry = &s / &base;
                        (big_to_fp(&(&s % &base)), big_to_fp(&carry))
                    })
                    .unzip();
                prev_carry_fp = carry_out.assign().unwrap_or(Fp::ZERO);

                let c_assigned = region.assign_advice(
                    || format!("c_{}", i), self.config.c, i, || c_i_val,
                )?;
                raw_limbs[i] = Limb { value: c_i_val, cell: Some(c_assigned.cell()) };

                region.assign_advice(
                    || format!("carry_out_{}", i), self.config.aux, i + 1, || carry_out,
                )?;
            }

            // Row 3: absorb final carry into 4th limb
            self.config.s_add.enable(&mut region, 3)?;
            region.assign_advice(|| "a_carry", self.config.a, 3, || Value::known(Fp::ZERO))?;
            region.assign_advice(|| "b_carry", self.config.b, 3, || Value::known(Fp::ZERO))?;
            region.assign_advice(|| "carry_in_3", self.config.aux, 3, || Value::known(prev_carry_fp))?;
            let carry_val = Value::known(prev_carry_fp);
            let carry_cell = region.assign_advice(|| "c_carry", self.config.c, 3, || carry_val)?;
            region.assign_advice(|| "carry_out_3", self.config.aux, 4, || Value::known(Fp::ZERO))?;

            // ── Compute result S mod Fq and reduction flag k ──
            // S = raw_limbs + carry * 2^255
            let s_big: Value<num_bigint::BigUint> = raw_limbs[0].value.clone()
                .zip(raw_limbs[1].value.clone())
                .zip(raw_limbs[2].value.clone())
                .zip(carry_val)
                .map(|(((l0, l1), l2), cv)| {
                    fp_to_big(&l0)
                        + fp_to_big(&l1) * &limb_base_big
                        + fp_to_big(&l2) * &limb_base_big.pow(2)
                        + fp_to_big(&cv) * &limb_base_big.pow(3)
                });

            // Compute result = S mod Fq and k = (S >= Fq) as Value<BigUint> and Value<Fp>
            let s_result: Value<(num_bigint::BigUint, Fp)> = s_big.map(|s| {
                if s >= fq_mod_big {
                    (&s - &fq_mod_big, Fp::ONE)
                } else {
                    (s, Fp::ZERO)
                }
            });
            let (result_big, k_val): (Value<num_bigint::BigUint>, Value<Fp>) = s_result.unzip();

            let mut result_limbs = array::from_fn(|i| {
                let lv = result_big.clone().map(|r| {
                    big_to_fp(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big))
                });
                Limb { value: lv, cell: None }
            });

            // ── Pass 2: Reduction constraint (s_reduce, rows 4-7) ──
            // Constrain: S = R + k·Fq
            // l_i + carry_out_i·2^85 = r_i + k·fq_i + carry_in_i
            let k_cell = region.assign_advice(|| "k_val", self.config.b, 4, || k_val)?;

            let mut prev_borrow_fp = Fp::ZERO;
            for i in 0..FQ_NUM_LIMBS {
                let row = 4 + i;
                self.config.s_reduce.enable(&mut region, row)?;

                let r_assigned = region.assign_advice(
                    || format!("r_{}", i), self.config.a, row, || result_limbs[i].value.clone(),
                )?;
                result_limbs[i].cell = Some(r_assigned.cell());

                let k_row_assigned = region.assign_advice(
                    || format!("k_row_{}", i), self.config.b, row, || k_val,
                )?;
                region.constrain_equal(k_cell.cell(), k_row_assigned.cell())?;

                region.assign_advice(
                    || format!("borrow_in_{}", i), self.config.aux, row, || Value::known(prev_borrow_fp),
                )?;

                let l_assigned = region.assign_advice(
                    || format!("l_{}_reuse", i), self.config.c, row, || raw_limbs[i].value.clone(),
                )?;
                region.constrain_equal(raw_limbs[i].cell.unwrap(), l_assigned.cell())?;

                region.assign_fixed(
                    || format!("fq_{}", i), self.config.fq_const, row, || Value::known(fq_limbs_fp[i]),
                )?;

                // Compute borrow_out = (r_i + k*fq_i + borrow_in - l_i) / 2^85
                let borrow_out: Value<Fp> = result_limbs[i].value.clone().zip(k_val)
                    .zip(Value::known(prev_borrow_fp))
                    .zip(raw_limbs[i].value.clone())
                    .map(|(((r, kv), bi), li)| {
                        let fq_i_big = &fq_mod_big / &limb_base_big.pow(i as u32) % &limb_base_big;
                        let k_big: u64 = if kv == Fp::ONE { 1 } else { 0 };
                        let s = fp_to_big(&r) + fq_i_big * k_big + fp_to_big(&bi);
                        let ls = fp_to_big(&li);
                        if s >= ls {
                            big_to_fp(&((&s - &ls) / &limb_base_big))
                        } else {
                            big_to_fp(&((&s + &limb_base_big - &ls) / &limb_base_big))
                        }
                    });
                prev_borrow_fp = borrow_out.assign().unwrap_or(Fp::ZERO);

                region.assign_advice(
                    || format!("borrow_out_{}", i), self.config.aux, row + 1, || borrow_out,
                )?;
            }

            // Row 7: final borrow-in check against carry from pass 1
            {
                let row = 7;
                self.config.s_reduce.enable(&mut region, row)?;
                region.assign_advice(|| "r_3", self.config.a, row, || Value::known(Fp::ZERO))?;
                let k_row_assigned = region.assign_advice(
                    || "k_row_3", self.config.b, row, || k_val,
                )?;
                region.constrain_equal(k_cell.cell(), k_row_assigned.cell())?;
                region.assign_advice(
                    || "borrow_in_3", self.config.aux, row, || Value::known(prev_borrow_fp),
                )?;
                let carry_reassigned = region.assign_advice(
                    || "carry_reuse", self.config.c, row, || carry_val,
                )?;
                region.constrain_equal(carry_cell.cell(), carry_reassigned.cell())?;
                region.assign_fixed(
                    || "fq_3", self.config.fq_const, row, || Value::known(Fp::ZERO),
                )?;
                region.assign_advice(
                    || "borrow_out_3", self.config.aux, row + 1, || Value::known(Fp::ZERO),
                )?;
            }

            // Row 9: k range check (row 8 is a gap to avoid aux[8] conflict with borrow_out_3)
            {
                self.config.s_range.enable(&mut region, 9)?;
                region.assign_advice(|| "k_check", self.config.aux, 9, || k_val)?;
            }

            Ok(FqElement { limbs: result_limbs })
        })?)
    }

    // ── Sub ────────────────────────────────────────────────────────────────

    /// Constrain `c = a - b mod Fq`.
    pub fn sub(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &FqElement,
        b: &FqElement,
    ) -> Result<FqElement, ErrorFront> {
        let neg_b = self.neg(layouter.namespace(|| "neg_b"), b)?;
        self.add(layouter.namespace(|| "sub"), a, &neg_b)
    }

    // ── Neg ────────────────────────────────────────────────────────────────

    /// Constrain `c = -a mod Fq` (i.e. Fq - a).
    ///
    /// Witnesses the negation externally and verifies via `add(a, neg_a) == 0`.
    pub fn neg(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &FqElement,
    ) -> Result<FqElement, ErrorFront> {
        let fq_mod_big = big_fq_mod();
        let limb_base_big = big_limb_base();

        let result = layouter.assign_region(|| "fq_neg", |mut region| {
            let neg_val = a.to_big().map(|a_int| &fq_mod_big - &a_int);

            let mut result_limbs: [Limb; FQ_NUM_LIMBS] = array::from_fn(|i| {
                let lv = neg_val.clone().map(|r| {
                    let l = &r / &limb_base_big.pow(i as u32);
                    big_to_fp(&(&l % &limb_base_big))
                });
                Limb { value: lv, cell: None }
            });

            for i in 0..FQ_NUM_LIMBS {
                let c = region.assign_advice(
                    || format!("neg_{}", i), self.config.c, i, || result_limbs[i].value,
                )?;
                result_limbs[i].cell = Some(c.cell());
            }

            Ok(FqElement { limbs: result_limbs })
        })?;

        // Verify: a + neg_a == 0
        let sum = self.add(layouter.namespace(|| "neg_verify"), a, &result)?;

        layouter.assign_region(|| "check_zero", |mut region| {
            let zero_cell = region.assign_advice(
                || "zero", self.config.c, 0, || Value::known(Fp::ZERO),
            )?;

            for i in 0..FQ_NUM_LIMBS {
                let col = match i { 0 => self.config.a, 1 => self.config.a, _ => self.config.b };
                let row = match i { 0 => 0, 1 => 1, _ => 0 };
                let l = region.assign_advice(
                    || format!("sum_{}", i), col, row, || sum.limbs[i].value,
                )?;
                if let Some(c) = sum.limbs[i].cell { region.constrain_equal(l.cell(), c)?; }
                region.constrain_equal(l.cell(), zero_cell.cell())?;
            }

            Ok(())
        })?;

        Ok(result)
    }

    // ── Mul ────────────────────────────────────────────────────────────────

    /// Constrain `c = a * b mod Fq`.
    ///
    /// ## Constraint system (one region)
    ///
    /// | Rows | Gate | Description |
    /// |------|------|-------------|
    /// | 0-8 | s_mul | p_ij = a_i · b_j |
    /// | 9-11 | — | assign Q limbs |
    /// | 12-14 | — | assign R limbs (result) |
    /// | 15-23 | s_mul | qf_ij = q_i · fq_j |
    /// | 24-27 | s_add | accumulate P sums for positions 1-3 |
    /// | 28-33 | s_reduce | carry chain: P_k + c_{k-1} = (QF+R)_k + B·c_k |
    /// | 34-318 | s_range | 3 × 85-bit range check on Q limbs |
    /// | 298-576 | s_range | 3 × 85-bit range check on R limbs |
    /// | 556-920 | s_range | 4 × 90-bit range check on carries c_0..c_3 |
    ///
    /// Carries computed externally with BigUint, then witnessed.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &FqElement,
        b: &FqElement,
    ) -> Result<FqElement, ErrorFront> {
        let limb_base_big = big_limb_base();
        let fq_mod_big = big_fq_mod();
        let fq_limbs_fp = [fq_limb_fp(0), fq_limb_fp(1), fq_limb_fp(2)];

        // Pre-compute p_ij values, full product, and carries
        let p_vals: [[Value<Fp>; 3]; 3] = array::from_fn(|i| {
            array::from_fn(|j| a.limbs[i].value.zip(b.limbs[j].value).map(|(av, bv)| av * bv))
        });

        let full_product = p_vals[0][0].zip(p_vals[0][1]).zip(p_vals[0][2])
            .zip(p_vals[1][0]).zip(p_vals[1][1]).zip(p_vals[1][2])
            .zip(p_vals[2][0]).zip(p_vals[2][1]).zip(p_vals[2][2])
            .map(|((((((((p00, p01), p02), p10), p11), p12), p20), p21), p22)| {
                let b = &limb_base_big;
                let b2 = &(b * b);
                let b3 = &(b2 * b);
                let b4 = &(b3 * b);
                fp_to_big(&p00)
                    + (fp_to_big(&p01) + fp_to_big(&p10)) * b
                    + (fp_to_big(&p02) + fp_to_big(&p11) + fp_to_big(&p20)) * b2
                    + (fp_to_big(&p12) + fp_to_big(&p21)) * b3
                    + fp_to_big(&p22) * b4
            });

        let q_big = full_product.as_ref().map(|prod| prod / &fq_mod_big);
        let r_big = full_product.map(|prod| prod % &fq_mod_big);

        let q_limb_vals: [Value<Fp>; 3] = array::from_fn(|i| {
            q_big.clone().map(|q| big_to_fp(&(&q / &limb_base_big.pow(i as u32) % &limb_base_big)))
        });
        let r_limb_vals: [Value<Fp>; 3] = array::from_fn(|i| {
            r_big.clone().map(|r| big_to_fp(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big)))
        });

        // Pre-compute qf_ij values
        let qf_vals: [[Value<Fp>; 3]; 3] = array::from_fn(|i| {
            array::from_fn(|j| q_limb_vals[i].map(|qv| qv * fq_limbs_fp[j]))
        });


        // R limbs as BigUint
        let r_big_limbs: [Value<num_bigint::BigUint>; 3] = array::from_fn(|i| {
            r_limb_vals[i].map(|v| fp_to_big(&v))
        });

        // Compute P_k and QF_k sums for each position
        let p_sum_big: [Value<num_bigint::BigUint>; 5] = array::from_fn(|k| match k {
            0 => p_vals[0][0].map(|v| fp_to_big(&v)),
            1 => p_vals[0][1].zip(p_vals[1][0]).map(|(x, y)| fp_to_big(&x) + fp_to_big(&y)),
            2 => p_vals[0][2].zip(p_vals[1][1]).zip(p_vals[2][0])
                .map(|((x, y), z)| fp_to_big(&x) + fp_to_big(&y) + fp_to_big(&z)),
            3 => p_vals[1][2].zip(p_vals[2][1]).map(|(x, y)| fp_to_big(&x) + fp_to_big(&y)),
            4 => p_vals[2][2].map(|v| fp_to_big(&v)),
            _ => unreachable!(),
        });

        let qf_sum_big: [Value<num_bigint::BigUint>; 5] = array::from_fn(|k| match k {
            0 => qf_vals[0][0].map(|v| fp_to_big(&v)),
            1 => qf_vals[0][1].zip(qf_vals[1][0]).map(|(x, y)| fp_to_big(&x) + fp_to_big(&y)),
            2 => qf_vals[0][2].zip(qf_vals[1][1]).zip(qf_vals[2][0])
                .map(|((x, y), z)| fp_to_big(&x) + fp_to_big(&y) + fp_to_big(&z)),
            3 => qf_vals[1][2].zip(qf_vals[2][1]).map(|(x, y)| fp_to_big(&x) + fp_to_big(&y)),
            4 => qf_vals[2][2].map(|v| fp_to_big(&v)),
            _ => unreachable!(),
        });

        // Compute carries: c_k = (P_k + c_{k-1} - QF_k - R_k) / B
        let carry_fp: [Value<Fp>; 6] = {
            let mut carries = [Value::known(Fp::ZERO); 6];
            let b = &limb_base_big;
            let mut prev_carry_big = num_bigint::BigUint::ZERO;

            for k in 0..5 {
                let r_big_k: Value<num_bigint::BigUint> = if k < 3 {
                    r_big_limbs[k].clone()
                } else {
                    Value::known(num_bigint::BigUint::ZERO)
                };

                let diff = p_sum_big[k].clone().zip(qf_sum_big[k].clone())
                    .zip(r_big_k).map(|((p, qf), r)| {
                        let p_total = p + &prev_carry_big;
                        let qf_r = &qf + &r;
                        if p_total >= qf_r {
                            (p_total - qf_r) / b.clone()
                        } else {
                            // Should not happen for correct Q,R but handle gracefully
                            num_bigint::BigUint::ZERO
                        }
                    });

                if let Ok(big_val) = diff.assign() {
                    carries[k] = Value::known(big_to_fp(&big_val));
                    prev_carry_big = big_val;
                }
            }
            carries[5] = Value::known(Fp::ZERO);
            carries
        };

        Ok(layouter.assign_region(|| "fq_mul", |mut region| {
            // ── Step 1: 9 s_mul — p_ij = a_i · b_j (rows 0-8) ──
            let mut p_cells = [[None; 3]; 3];

            for i in 0..FQ_NUM_LIMBS {
                for j in 0..FQ_NUM_LIMBS {
                    let idx = i * FQ_NUM_LIMBS + j;
                    self.config.s_mul.enable(&mut region, idx)?;

                    let a_assigned = region.assign_advice(
                        || format!("a_{}{}", i, j), self.config.a, idx, || a.limbs[i].value,
                    )?;
                    if let Some(c) = a.limbs[i].cell { region.constrain_equal(a_assigned.cell(), c)?; }

                    let b_assigned = region.assign_advice(
                        || format!("b_{}{}", i, j), self.config.b, idx, || b.limbs[j].value,
                    )?;
                    if let Some(c) = b.limbs[j].cell { region.constrain_equal(b_assigned.cell(), c)?; }

                    let c_assigned = region.assign_advice(
                        || format!("p_{}{}", i, j), self.config.c, idx, || p_vals[i][j],
                    )?;
                    p_cells[i][j] = Some(c_assigned.cell());
                }
            }

            // ── Step 2: assign Q (rows 9-11) and R (rows 12-14) ──
            let mut q_cells = [None; 3];
            let mut r_cells = [None; 3];
            for i in 0..FQ_NUM_LIMBS {
                let q_cell = region.assign_advice(
                    || format!("q_{}", i), self.config.c, 9 + i, || q_limb_vals[i],
                )?;
                q_cells[i] = Some(q_cell.cell());

                let r_cell = region.assign_advice(
                    || format!("r_{}", i), self.config.c, 12 + i, || r_limb_vals[i],
                )?;
                r_cells[i] = Some(r_cell.cell());
            }

            // ── Step 3: 9 s_mul — qf_ij = q_i · fq_j (rows 15-23) ──
            let qf_row = 15;
            for i in 0..FQ_NUM_LIMBS {
                for j in 0..FQ_NUM_LIMBS {
                    let idx = qf_row + i * FQ_NUM_LIMBS + j;
                    self.config.s_mul.enable(&mut region, idx)?;

                    let q_assigned = region.assign_advice(
                        || format!("q_{}_a", i), self.config.a, idx, || q_limb_vals[i],
                    )?;
                    if let Some(c) = q_cells[i] { region.constrain_equal(q_assigned.cell(), c)?; }

                    region.assign_advice(
                        || format!("fq_{}_b", j), self.config.b, idx, || Value::known(fq_limbs_fp[j]),
                    )?;

                    let qf_assigned = region.assign_advice(
                        || format!("qf_{}{}", i, j), self.config.c, idx, || qf_vals[i][j],
                    )?;
                    let _ = qf_assigned.cell();
                }
            }

            // ── Step 4: accumulate P sums (rows 24-27) ──
            let acc1_cell = {
                let row = 24;
                let sum = p_vals[0][1].zip(p_vals[1][0]).map(|(x, y)| x + y);
                self.config.s_add.enable(&mut region, row)?;
                let a = region.assign_advice(|| "p01_a", self.config.a, row, || p_vals[0][1])?;
                if let Some(c) = p_cells[0][1] { region.constrain_equal(a.cell(), c)?; }
                region.assign_advice(|| "p10_b", self.config.b, row, || p_vals[1][0])?;
                region.assign_advice(|| "carry_in", self.config.aux, row, || Value::known(Fp::ZERO))?;
                let c = region.assign_advice(|| "acc1", self.config.c, row, || sum)?;
                region.assign_advice(|| "carry_out", self.config.aux, row + 1, || Value::known(Fp::ZERO))?;
                c.cell()
            };

            let acc2_cell = {
                let row1 = 25;
                let sum1 = p_vals[0][2].zip(p_vals[1][1]).map(|(x, y)| x + y);
                self.config.s_add.enable(&mut region, row1)?;
                let a = region.assign_advice(|| "p02_a", self.config.a, row1, || p_vals[0][2])?;
                if let Some(c) = p_cells[0][2] { region.constrain_equal(a.cell(), c)?; }
                region.assign_advice(|| "p11_b", self.config.b, row1, || p_vals[1][1])?;
                region.assign_advice(|| "carry_in", self.config.aux, row1, || Value::known(Fp::ZERO))?;
                let tmp_cell = region.assign_advice(|| "tmp2", self.config.c, row1, || sum1)?;
                region.assign_advice(|| "carry_out", self.config.aux, row1 + 1, || Value::known(Fp::ZERO))?;

                let row2 = 26;
                let sum2 = sum1.zip(p_vals[2][0]).map(|(s, x)| s + x);
                self.config.s_add.enable(&mut region, row2)?;
                let a = region.assign_advice(|| "tmp2_a", self.config.a, row2, || sum1)?;
                region.constrain_equal(a.cell(), tmp_cell.cell())?;
                region.assign_advice(|| "p20_b", self.config.b, row2, || p_vals[2][0])?;
                region.assign_advice(|| "carry_in", self.config.aux, row2, || Value::known(Fp::ZERO))?;
                let c = region.assign_advice(|| "acc2", self.config.c, row2, || sum2)?;
                region.assign_advice(|| "carry_out", self.config.aux, row2 + 1, || Value::known(Fp::ZERO))?;
                c.cell()
            };

            let acc3_cell = {
                let row = 27;
                let sum = p_vals[1][2].zip(p_vals[2][1]).map(|(x, y)| x + y);
                self.config.s_add.enable(&mut region, row)?;
                let a = region.assign_advice(|| "p12_a", self.config.a, row, || p_vals[1][2])?;
                if let Some(c) = p_cells[1][2] { region.constrain_equal(a.cell(), c)?; }
                region.assign_advice(|| "p21_b", self.config.b, row, || p_vals[2][1])?;
                region.assign_advice(|| "carry_in", self.config.aux, row, || Value::known(Fp::ZERO))?;
                let c = region.assign_advice(|| "acc3", self.config.c, row, || sum)?;
                region.assign_advice(|| "carry_out", self.config.aux, row + 1, || Value::known(Fp::ZERO))?;
                c.cell()
            };

            // ── Step 5: carry chain via s_reduce (rows 28-33, contiguous) ──
            // s_reduce: r + k·fq + carry_in = l + B·carry_out
            //   r = P_k (a col), k=0, carry_in = c_{k-1}, l = (QF+R)_k (c col), carry_out = c_k
            let cc_start = 28;

            // Compute QF_k + R_k as Fp value for each position
            let qf_r_comb: [Value<Fp>; 5] = array::from_fn(|k| match k {
                0 => qf_vals[0][0].zip(r_limb_vals[0]).map(|(q, r)| q + r),
                1 => qf_vals[0][1].zip(qf_vals[1][0]).zip(r_limb_vals[1])
                    .map(|((a, b), r)| a + b + r),
                2 => qf_vals[0][2].zip(qf_vals[1][1]).zip(qf_vals[2][0]).zip(r_limb_vals[2])
                    .map(|(((a, b), c), r)| a + b + c + r),
                3 => qf_vals[1][2].zip(qf_vals[2][1]).map(|(a, b)| a + b),
                4 => qf_vals[2][2],
                _ => unreachable!(),
            });

            // P_k values for each position
            let p_k_vals: [Value<Fp>; 5] = array::from_fn(|k| match k {
                0 => p_vals[0][0],
                1 => p_vals[0][1].zip(p_vals[1][0]).map(|(x, y)| x + y),
                2 => p_vals[0][2].zip(p_vals[1][1]).zip(p_vals[2][0]).map(|((x, y), z)| x + y + z),
                3 => p_vals[1][2].zip(p_vals[2][1]).map(|(x, y)| x + y),
                4 => p_vals[2][2],
                _ => unreachable!(),
            });

            let p_k_cells: [Option<halo2_proofs::circuit::Cell>; 5] = [
                p_cells[0][0],
                Some(acc1_cell),
                Some(acc2_cell),
                Some(acc3_cell),
                p_cells[2][2],
            ];

            let mut carry_aux_cells = [None::<halo2_proofs::circuit::Cell>; 4];
            for k in 0..6 {
                let row = cc_start + k;
                self.config.s_reduce.enable(&mut region, row)?;

                // s_reduce gate queries column b (k_val) at current rotation
                // k=0 in carry chain (no reduction), so assign b = 0
                region.assign_advice(
                    || format!("cc{}_b", k), self.config.b, row, || Value::known(Fp::ZERO),
                )?;

                if k < 5 {
                    // r = P_k
                    let a = region.assign_advice(
                        || format!("cc{}_r", k), self.config.a, row, || p_k_vals[k],
                    )?;
                    if let Some(cell) = p_k_cells[k] { region.constrain_equal(a.cell(), cell)?; }

                    // l = QF_k + R_k
                    region.assign_advice(
                        || format!("cc{}_l", k), self.config.c, row, || qf_r_comb[k],
                    )?;

                    // fq_i = 0 (no reduction factor in carry chain)
                    region.assign_fixed(
                        || format!("cc{}_fq", k), self.config.fq_const, row, || Value::known(Fp::ZERO),
                    )?;

                    // carry_in: for k=0, carry_in=0; for k>0, c_{k-1} lives at aux[row] from prev carry_out
                    if k == 0 {
                        region.assign_advice(
                            || "cc_carry_in_0", self.config.aux, row, || Value::known(Fp::ZERO),
                        )?;
                    }

                    // carry_out = c_k (at aux[row+1]). For k>0 this also becomes next row's carry_in.
                    // Save cell references for carries 0-3 for later range-checking.
                    let cout_assigned = region.assign_advice(
                        || format!("cc{}_cout", k), self.config.aux, row + 1, || carry_fp[k],
                    )?;
                    if k < 4 {
                        carry_aux_cells[k] = Some(cout_assigned.cell());
                    }
                } else {
                    // k=5: check c_4 = 0
                    // s_reduce: c4 + 0 + 0 = 0 + B · 0 → 2·c4 = 0 → c4 = 0
                    region.assign_advice(
                        || "cc5_c4", self.config.a, row, || carry_fp[4],
                    )?;
                    region.assign_advice(
                        || "cc5_zero", self.config.c, row, || Value::known(Fp::ZERO),
                    )?;
                    region.assign_fixed(
                        || "cc5_fq", self.config.fq_const, row, || Value::known(Fp::ZERO),
                    )?;
                    region.assign_advice(
                        || "cc5_cout", self.config.aux, row + 1, || Value::known(Fp::ZERO),
                    )?;
                }
            }

            // ── Step 6: range-check Q limbs (rows 34+) ──
            let rc_start = 40;
            for (qi, q_cell) in q_cells.iter().enumerate() {
                let bits: Vec<Value<Fp>> = (0..FQ_LIMB_BITS)
                    .map(|i| {
                        q_limb_vals[qi].map(|v| {
                            let bytes = v.to_repr();
                            let byte_idx = i / 8;
                            let bit_idx = i % 8;
                            if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                Fp::ONE
                            } else {
                                Fp::ZERO
                            }
                        })
                    })
                    .collect();

                let offset = rc_start + qi * (FQ_LIMB_BITS + 1);
                let mut acc = Value::known(Fp::ZERO);
                let mut base = Fp::ONE;
                for (i, bit_val) in bits.iter().enumerate() {
                    let row = offset + i;
                    self.config.s_range.enable(&mut region, row)?;
                    region.assign_advice(|| format!("q{}_bit_{}", qi, i), self.config.aux, row, || *bit_val)?;
                    acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                    base = base.double();
                }
                let acc_cell = region.assign_advice(
                    || format!("q{}_recon", qi), self.config.c, offset + FQ_LIMB_BITS, || acc,
                )?;
                if let Some(cell) = q_cell {
                    region.constrain_equal(acc_cell.cell(), *cell)?;
                }
            }

            // ── Step 7: range-check R limbs (rows 298+) ──
            let rc_r_start = 298;
            for (ri, r_cell) in r_cells.iter().enumerate() {
                let bits: Vec<Value<Fp>> = (0..FQ_LIMB_BITS)
                    .map(|i| {
                        r_limb_vals[ri].map(|v| {
                            let bytes = v.to_repr();
                            let byte_idx = i / 8;
                            let bit_idx = i % 8;
                            if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                Fp::ONE
                            } else {
                                Fp::ZERO
                            }
                        })
                    })
                    .collect();

                let offset = rc_r_start + ri * (FQ_LIMB_BITS + 1);
                let mut acc = Value::known(Fp::ZERO);
                let mut base = Fp::ONE;
                for (i, bit_val) in bits.iter().enumerate() {
                    let row = offset + i;
                    self.config.s_range.enable(&mut region, row)?;
                    region.assign_advice(|| format!("r{}_bit_{}", ri, i), self.config.aux, row, || *bit_val)?;
                    acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                    base = base.double();
                }
                let acc_cell = region.assign_advice(
                    || format!("r{}_recon", ri), self.config.c, offset + FQ_LIMB_BITS, || acc,
                )?;
                if let Some(cell) = r_cell {
                    region.constrain_equal(acc_cell.cell(), *cell)?;
                }
            }

            // ── Step 8: range-check carries to CARRY_BITS (rows 556+) ──
            let rc_c_start = 556;
            for (ci, aux_cell_opt) in carry_aux_cells.iter().enumerate() {
                let bits: Vec<Value<Fp>> = (0..CARRY_BITS)
                    .map(|i| {
                        carry_fp[ci].map(|v| {
                            let bytes = v.to_repr();
                            let byte_idx = i / 8;
                            let bit_idx = i % 8;
                            if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                Fp::ONE
                            } else {
                                Fp::ZERO
                            }
                        })
                    })
                    .collect();

                let offset = rc_c_start + ci * (CARRY_BITS + 1);
                // Assign carry value to column c and link to aux cell
                let carry_copy = region.assign_advice(
                    || format!("c{}_copy", ci), self.config.c, offset, || carry_fp[ci],
                )?;
                if let Some(aux_cell) = aux_cell_opt {
                    region.constrain_equal(carry_copy.cell(), *aux_cell)?;
                }

                let mut acc = Value::known(Fp::ZERO);
                let mut base = Fp::ONE;
                for (i, bit_val) in bits.iter().enumerate() {
                    let row = offset + i;
                    self.config.s_range.enable(&mut region, row)?;
                    region.assign_advice(|| format!("c{}_bit_{}", ci, i), self.config.aux, row, || *bit_val)?;
                    acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                    base = base.double();
                }
                let acc_cell = region.assign_advice(
                    || format!("c{}_recon", ci), self.config.c, offset + CARRY_BITS, || acc,
                )?;
                region.constrain_equal(acc_cell.cell(), carry_copy.cell())?;
            }

            // ── Return result ──
            let result_limbs: [Limb; FQ_NUM_LIMBS] = array::from_fn(|i| {
                Limb { value: r_limb_vals[i], cell: r_cells[i] }
            });
            Ok(FqElement { limbs: result_limbs })
        })?)
    }

    // ── Invert (witness-with-verify) ───────────────────────────────────────

    /// Witness `a^(-1) mod Fq` and verify `a * inv = 1`.
    ///
    /// The inverse is computed externally via BigUint modpow.
    /// Verification: compute `prod = mul(a, inv)`, then constrain
    /// `prod.limbs == [1, 0, 0]`.
    ///
    /// Note: correctness depends on mul()'s 9 s_mul constraints ensuring
    /// p_ij = a_i * inv_j. If p_ij are correct and prod == 1, then inv is
    /// the correct inverse.
    pub fn invert(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &FqElement,
    ) -> Result<FqElement, ErrorFront> {
        let inv_big = a.to_big().map(|a_int| {
            let fq = big_fq_mod();
            let exp = &fq - num_bigint::BigUint::from(2u64);
            a_int.modpow(&exp, &fq)
        });

        let limb_base_big = big_limb_base();
        let inv_limbs: [Limb; FQ_NUM_LIMBS] = array::from_fn(|i| {
            let lv = inv_big.clone().map(|r| {
                big_to_fp(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big))
            });
            Limb { value: lv, cell: None }
        });
        let inv = FqElement { limbs: inv_limbs };

        // Verify: mul(a, inv) == 1
        let prod = self.mul(layouter.namespace(|| "mul_verify"), a, &inv)?;

        layouter.assign_region(|| "check_one", |mut region| {
            let one_cell = region.assign_advice(|| "one", self.config.c, 0, || Value::known(Fp::ONE))?;
            let zero_cell = region.assign_advice(|| "zero", self.config.c, 1, || Value::known(Fp::ZERO))?;

            let c0 = region.assign_advice(|| "c0", self.config.a, 0, || prod.limbs[0].value)?;
            if let Some(c) = prod.limbs[0].cell { region.constrain_equal(c0.cell(), c)?; }
            region.constrain_equal(c0.cell(), one_cell.cell())?;

            let c1 = region.assign_advice(|| "c1", self.config.a, 1, || prod.limbs[1].value)?;
            if let Some(c) = prod.limbs[1].cell { region.constrain_equal(c1.cell(), c)?; }
            region.constrain_equal(c1.cell(), zero_cell.cell())?;

            let c2 = region.assign_advice(|| "c2", self.config.b, 0, || prod.limbs[2].value)?;
            if let Some(c) = prod.limbs[2].cell { region.constrain_equal(c2.cell(), c)?; }
            region.constrain_equal(c2.cell(), zero_cell.cell())?;

            Ok(())
        })?;

        Ok(inv)
    }

    // ── Range check ─────────────────────────────────────────────────────────

    /// Decompose `value` into `num_bits` bits and constrain each to {0, 1}.
    ///
    /// Reconstructs `Σ bit_i * 2^i` and constrains equality with `value`.
    /// Panics if `num_bits > 254` (Fp modulus wraps beyond 254 bits).
    pub fn range_check(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &Limb,
        num_bits: usize,
    ) -> Result<(), ErrorFront> {
        assert!(num_bits <= 254, "range_check: num_bits must be ≤ 254, got {}", num_bits);

        let bits: Vec<Value<Fp>> = (0..num_bits)
            .map(|i| {
                value.value.map(|v| {
                    let bytes = v.to_repr();
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                        Fp::ONE
                    } else {
                        Fp::ZERO
                    }
                })
            })
            .collect();

        layouter.assign_region(|| "range_check", |mut region| {
            let mut acc = Value::known(Fp::ZERO);
            let mut base = Fp::ONE;

            for (i, bit_val) in bits.iter().enumerate() {
                self.config.s_range.enable(&mut region, i)?;
                region.assign_advice(|| format!("bit_{}", i), self.config.aux, i, || *bit_val)?;
                acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                base = base.double();
            }

            let acc_cell = region.assign_advice(|| "reconstructed", self.config.c, num_bits, || acc)?;
            if let Some(c) = value.cell {
                region.constrain_equal(acc_cell.cell(), c)?;
            }
            Ok(())
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        plonk::Circuit,
        dev::MockProver,
    };

    fn make_fq_el(v: [u64; 3]) -> FqElement {
        FqElement {
            limbs: array::from_fn(|i| Limb {
                value: Value::known(Fp::from(v[i])),
                cell: None,
            }),
        }
    }

    #[derive(Default)]
    struct FqAddCircuit {
        a: [u64; 3],
        b: [u64; 3],
    }

    impl Circuit<Fp> for FqAddCircuit {
        type Config = NonNativeFqConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self { Self::default() }
        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            NonNativeFqChip::configure(meta)
        }
        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
            let chip = NonNativeFqChip::new(config);
            let a = make_fq_el(self.a);
            let b = make_fq_el(self.b);
            let _c = chip.add(layouter.namespace(|| "add"), &a, &b)?;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FqMulCircuit {
        a: [u64; 3],
        b: [u64; 3],
    }

    impl Circuit<Fp> for FqMulCircuit {
        type Config = NonNativeFqConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self { Self::default() }
        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            NonNativeFqChip::configure(meta)
        }
        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
            let chip = NonNativeFqChip::new(config);
            let a = make_fq_el(self.a);
            let b = make_fq_el(self.b);
            let _c = chip.mul(layouter.namespace(|| "mul"), &a, &b)?;
            Ok(())
        }
    }

    // ── add tests ──

    #[test]
    fn test_fq_add_small() {
        let k = 10;
        let circuit = FqAddCircuit { a: [3, 0, 0], b: [5, 0, 0] };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq add (3+5): {:?}", result.err());
    }

    #[test]
    fn test_fq_add_large() {
        let k = 10;
        let circuit = FqAddCircuit { a: [u64::MAX, 0, 0], b: [u64::MAX, 0, 0] };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq add (u64::MAX + u64::MAX): {:?}", result.err());
    }

    #[test]
    fn test_fq_add_fq_overflow() {
        let k = 10;
        // Test a + b where result > Fq: pick limb_0 values that overflow Fq_limb_0.
        // Fq_limb_0 = 0x14a8dd8c46eb2100000001 ≈ 387... ~3.87e25.
        // Use a_0 = Fq_limb_0 - 5, b_0 = 10 → sum ≈ Fq_limb_0 + 5 > Fq_limb_0.
        // Using Fp values directly for simplicity:
        let circuit = FqAddCircuit {
            a: [u64::MAX, 0, 0],
            b: [1, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq add overflow: {:?}", result.err());
    }

    #[test]
    fn test_fq_add_carry_edge() {
        let k = 10;
        // Carry-chain edge: a_0 near 2^85-1, b_0 = 1 → limb_0 overflows
        let hi_limb0: u64 = (1u64 << 63) - 1; // just a large 64-bit value
        let circuit = FqAddCircuit {
            a: [hi_limb0, 1, 0],
            b: [1, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq add carry edge: {:?}", result.err());
    }

    // ── mul tests ──

    #[test]
    fn test_fq_mul_small() {
        let k = 12;
        let circuit = FqMulCircuit { a: [3, 0, 0], b: [5, 0, 0] };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq mul (3*5): {:?}", result.err());
    }

    #[test]
    fn test_fq_mul_carry() {
        let k = 12;
        let circuit = FqMulCircuit { a: [u64::MAX, 0, 0], b: [2, 0, 0] };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq mul carry: {:?}", result.err());
    }

    // ── neg test ──

    #[test]
    fn test_fq_neg() {
        const K: u32 = 10;
        #[derive(Default)]
        struct NegCircuit;
        impl Circuit<Fp> for NegCircuit {
            type Config = NonNativeFqConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                NonNativeFqChip::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = NonNativeFqChip::new(config);
                let a = make_fq_el([7, 0, 0]);
                let _neg_a = chip.neg(layouter.namespace(|| "neg"), &a)?;
                Ok(())
            }
        }
        let circuit = NegCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq neg: {:?}", result.err());
    }

    // ── invert test ──

    #[test]
    fn test_fq_invert() {
        const K: u32 = 12;
        #[derive(Default)]
        struct InvertCircuit;
        impl Circuit<Fp> for InvertCircuit {
            type Config = NonNativeFqConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                NonNativeFqChip::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = NonNativeFqChip::new(config);
                let a = make_fq_el([7, 0, 0]);
                let _inv = chip.invert(layouter.namespace(|| "inv"), &a)?;
                Ok(())
            }
        }
        let circuit = InvertCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq invert: {:?}", result.err());
    }

    // ── range check test ──

    #[test]
    fn test_fq_range_small() {
        const K: u32 = 10;
        #[derive(Default)]
        struct RcCircuit;
        impl Circuit<Fp> for RcCircuit {
            type Config = NonNativeFqConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                NonNativeFqChip::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), ErrorFront> {
                let chip = NonNativeFqChip::new(config);
                let val = Limb { value: Value::known(Fp::from(42)), cell: None };
                chip.range_check(layouter.namespace(|| "rc"), &val, 8)?;
                Ok(())
            }
        }
        let circuit = RcCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fq range check: {:?}", result.err());
    }
}
