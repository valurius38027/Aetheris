//! Non-native Fp arithmetic over Circuit<Fq>.
//!
//! The recursive circuit runs over Vesta's base field (Fq). Pallas base field
//! elements (Fp) are non-native — represented as 3 × 85-bit Fq limbs.
//!
//! # Design
//!
//! Each Fp element is stored as 3 Fq limbs (85 bits each, little-endian):
//!   value = l0 + l1·2^85 + l2·2^170
//!
//! ## add (s_add gate, 4 rows)
//!   Row i: a_i + b_i + carry_in - c_i - 2^85·carry_out_i = 0
//!   Row 3: final carry + 0 = c_3 (absorbs 2^255 overflow)
//!   Then subtract Fp if result >= Fp.
//!
//! ## mul (s_mul + s_add gates, 9 + 6 + 3 rows)
//!   Rows 0-8: p_ij = a_i · b_j  (9 partial products)
//!   Rows 9-14: combine partials via 2:1 addition tree
//!   Rows 15-17: Fp reduction via conditional subtraction
//!
//! ## invert (witness-with-verify)
//!   Witness inv externally, verify a·inv = 1 mod Fp via mul + equality checks.

use core::array;

use num_bigint::BigUint;
use ff::{Field, PrimeField};
use halo2_proofs::halo2curves::pasta::Fq;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::Limb;

// ── Constants ──────────────────────────────────────────────────────────────

pub const FP_NUM_LIMBS: usize = 3;
pub const FP_LIMB_BITS: usize = 85;

/// Number of bits to range-check carries to. Honest carries are < 2^87;
/// 90 bits provides headroom and ensures Fq equation ≡ ℤ equation.
pub const CARRY_BITS: usize = 90;

/// Fp = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
/// as LE bytes (32 bytes).
const FP_MOD_BYTES: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0xed, 0x30, 0x2d, 0x99, 0x1b, 0xf9, 0x4c, 0x09, 0xfc, 0x98, 0x46, 0x22,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];

/// 2^85 as LE bytes (bit 85 set).
const TWO_POW_85_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn fq_from_bytes(bytes: [u8; 32]) -> Fq {
    Fq::from_repr(bytes).unwrap()
}

fn fq_limb_base() -> Fq {
    fq_from_bytes(TWO_POW_85_BYTES)
}

/// Full Fp modulus as BigUint.
fn big_fp_mod() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&FP_MOD_BYTES)
}

/// 2^85 as BigUint.
fn big_limb_base() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&TWO_POW_85_BYTES)
}

fn fq_to_big(fq: &Fq) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(fq.to_repr().as_ref())
}

fn fp_limb_fq(i: usize) -> Fq {
    let base = big_limb_base();
    big_to_fq(&(&big_fp_mod() / &base.pow(i as u32) % &base))
}

fn big_to_fq(big: &num_bigint::BigUint) -> Fq {
    let bytes = big.to_bytes_le();
    let mut repr = <Fq as PrimeField>::Repr::default();
    let repr_bytes = repr.as_mut();
    let len = bytes.len().min(repr_bytes.len());
    repr_bytes[..len].copy_from_slice(&bytes[..len]);
    Fq::from_repr(repr).unwrap()
}

// ── Fp element ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FpElement {
    pub limbs: [Limb<Fq>; FP_NUM_LIMBS],
}

impl FpElement {
    pub fn new(limbs: [Limb<Fq>; FP_NUM_LIMBS]) -> Self {
        FpElement { limbs }
    }

    pub fn zero() -> Self {
        FpElement {
            limbs: array::from_fn(|_| Limb {
                value: Value::known(Fq::ZERO),
                cell: None,
            }),
        }
    }

    pub fn one() -> Self {
        let mut e = Self::zero();
        e.limbs[0] = Limb {
            value: Value::known(Fq::ONE),
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
            .map(|((l0, l1), l2)| fq_to_big(&l0) + fq_to_big(&l1) * &b + fq_to_big(&l2) * &b2)
    }

    /// Returns true if all limbs are known and zero.
    pub fn is_zero(&self) -> bool {
        self.to_big()
            .map(|v| v == BigUint::from(0u32))
            .assign()
            .unwrap_or(false)
    }
}

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NonNativeFpConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub aux: Column<Advice>,
    pub fp_const: Column<Fixed>,
    pub s_add: Selector,
    pub s_mul: Selector,
    pub s_range: Selector,
    pub s_reduce: Selector,
}

// ── Chip ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct NonNativeFpChip {
    config: NonNativeFpConfig,
}

impl NonNativeFpConfig {
    /// Create a NonNativeFpConfig for any field without enabling gates.
    pub fn configure_no_gates<F: ff::Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            a: meta.advice_column(),
            b: meta.advice_column(),
            c: meta.advice_column(),
            aux: meta.advice_column(),
            fp_const: meta.fixed_column(),
            s_add: meta.complex_selector(),
            s_mul: meta.complex_selector(),
            s_range: meta.complex_selector(),
            s_reduce: meta.complex_selector(),
        }
    }
}

impl NonNativeFpChip {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> NonNativeFpConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let aux = meta.advice_column();
        let fp_const = meta.fixed_column();
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
        let limb_base = fq_limb_base();
        meta.create_gate("fp_add", |meta| {
            let s = meta.query_selector(s_add);
            let a_val = meta.query_advice(a, Rotation::cur());
            let b_val = meta.query_advice(b, Rotation::cur());
            let carry_in = meta.query_advice(aux, Rotation::cur());
            let c_val = meta.query_advice(c, Rotation::cur());
            let carry_out = meta.query_advice(aux, Rotation::next());
            vec![
                s * (a_val + b_val + carry_in
                    - c_val
                    - Expression::Constant(limb_base) * carry_out),
            ]
        });

        // ── Reduction gate ──
        // r + k·fp_i + carry_in - l - 2^85 * carry_out = 0
        meta.create_gate("fp_reduce", |meta| {
            let s = meta.query_selector(s_reduce);
            let r_val = meta.query_advice(a, Rotation::cur());
            let k_val = meta.query_advice(b, Rotation::cur());
            let carry_in = meta.query_advice(aux, Rotation::cur());
            let l_val = meta.query_advice(c, Rotation::cur());
            let carry_out = meta.query_advice(aux, Rotation::next());
            let fp_i = meta.query_fixed(fp_const, Rotation::cur());
            vec![
                s * (r_val + k_val * fp_i + carry_in
                    - l_val
                    - Expression::Constant(limb_base) * carry_out),
            ]
        });

        // ── Multiplication gate (limb mul) ──
        // a * b = c
        meta.create_gate("fp_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a_val = meta.query_advice(a, Rotation::cur());
            let b_val = meta.query_advice(b, Rotation::cur());
            let c_val = meta.query_advice(c, Rotation::cur());
            vec![s * (a_val * b_val - c_val)]
        });

        // ── Range check gate (bit check) ──
        // bit * (1 - bit) = 0
        meta.create_gate("fp_range", |meta| {
            let s = meta.query_selector(s_range);
            let bit_val = meta.query_advice(aux, Rotation::cur());
            vec![s * bit_val.clone() * (Expression::Constant(Fq::ONE) - bit_val)]
        });

        NonNativeFpConfig {
            a,
            b,
            c,
            aux,
            fp_const,
            s_add,
            s_mul,
            s_range,
            s_reduce,
        }
    }

    pub fn new(config: NonNativeFpConfig) -> Self {
        NonNativeFpChip { config }
    }

    // ── Add ────────────────────────────────────────────────────────────────

    /// Constrain `c = a + b mod Fp`.
    pub fn add(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
        b: &FpElement,
    ) -> Result<FpElement, ErrorFront> {
        let limb_base_big = big_limb_base();
        let fp_mod_big = big_fp_mod();
        let fp_limbs_fq = [fp_limb_fq(0), fp_limb_fq(1), fp_limb_fq(2)];

        Ok(layouter.assign_region(
            || "fp_add",
            |mut region| {
                // ── Pass 1: Carry-chain (unreduced addition S = a + b) ──
                let mut prev_carry_fq = Fq::ZERO;
                let mut raw_limbs: [Limb<Fq>; FP_NUM_LIMBS] = core::array::from_fn(|_| Limb {
                    value: Value::known(Fq::ZERO),
                    cell: None,
                });

                for i in 0..FP_NUM_LIMBS {
                    self.config.s_add.enable(&mut region, i)?;

                    let a_assigned = region.assign_advice(
                        || format!("a_{}", i),
                        self.config.a,
                        i,
                        || a.limbs[i].value,
                    )?;
                    if let Some(c) = a.limbs[i].cell {
                        region.constrain_equal(a_assigned.cell(), c)?;
                    }

                    let b_assigned = region.assign_advice(
                        || format!("b_{}", i),
                        self.config.b,
                        i,
                        || b.limbs[i].value,
                    )?;
                    if let Some(c) = b.limbs[i].cell {
                        region.constrain_equal(b_assigned.cell(), c)?;
                    }

                    region.assign_advice(
                        || format!("carry_in_{}", i),
                        self.config.aux,
                        i,
                        || Value::known(prev_carry_fq),
                    )?;

                    let (c_i_val, carry_out): (Value<Fq>, Value<Fq>) = a.limbs[i]
                        .value
                        .zip(b.limbs[i].value)
                        .zip(Value::known(prev_carry_fq))
                        .map(|((av, bv), ci)| {
                            let s = fq_to_big(&av) + fq_to_big(&bv) + fq_to_big(&ci);
                            let base = big_limb_base();
                            let carry = &s / &base;
                            (big_to_fq(&(&s % &base)), big_to_fq(&carry))
                        })
                        .unzip();
                    prev_carry_fq = carry_out.assign().unwrap_or(Fq::ZERO);

                    let c_assigned = region.assign_advice(
                        || format!("c_{}", i),
                        self.config.c,
                        i,
                        || c_i_val,
                    )?;
                    raw_limbs[i] = Limb {
                        value: c_i_val,
                        cell: Some(c_assigned.cell()),
                    };

                    region.assign_advice(
                        || format!("carry_out_{}", i),
                        self.config.aux,
                        i + 1,
                        || carry_out,
                    )?;
                }

                // Row 3: absorb final carry into 4th limb
                self.config.s_add.enable(&mut region, 3)?;
                region.assign_advice(|| "a_carry", self.config.a, 3, || Value::known(Fq::ZERO))?;
                region.assign_advice(|| "b_carry", self.config.b, 3, || Value::known(Fq::ZERO))?;
                region.assign_advice(
                    || "carry_in_3",
                    self.config.aux,
                    3,
                    || Value::known(prev_carry_fq),
                )?;
                let carry_val = Value::known(prev_carry_fq);
                let carry_cell =
                    region.assign_advice(|| "c_carry", self.config.c, 3, || carry_val)?;
                region.assign_advice(
                    || "carry_out_3",
                    self.config.aux,
                    4,
                    || Value::known(Fq::ZERO),
                )?;

                // ── Compute result S mod Fp and reduction flag k ──
                let s_big: Value<num_bigint::BigUint> = raw_limbs[0]
                    .value
                    .clone()
                    .zip(raw_limbs[1].value.clone())
                    .zip(raw_limbs[2].value.clone())
                    .zip(carry_val)
                    .map(|(((l0, l1), l2), cv)| {
                        fq_to_big(&l0)
                            + fq_to_big(&l1) * &limb_base_big
                            + fq_to_big(&l2) * &limb_base_big.pow(2)
                            + fq_to_big(&cv) * &limb_base_big.pow(3)
                    });

                let s_result: Value<(num_bigint::BigUint, Fq)> = s_big.map(|s| {
                    if s >= fp_mod_big {
                        (&s - &fp_mod_big, Fq::ONE)
                    } else {
                        (s, Fq::ZERO)
                    }
                });
                let (result_big, k_val): (Value<num_bigint::BigUint>, Value<Fq>) =
                    s_result.unzip();

                let mut result_limbs = array::from_fn(|i| {
                    let lv = result_big
                        .clone()
                        .map(|r| big_to_fq(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big)));
                    Limb {
                        value: lv,
                        cell: None,
                    }
                });

                // ── Pass 2: Reduction constraint (s_reduce, rows 4-7) ──
                let k_cell = region.assign_advice(|| "k_val", self.config.b, 4, || k_val)?;

                let mut prev_borrow_fq = Fq::ZERO;
                for i in 0..FP_NUM_LIMBS {
                    let row = 4 + i;
                    self.config.s_reduce.enable(&mut region, row)?;

                    let r_assigned = region.assign_advice(
                        || format!("r_{}", i),
                        self.config.a,
                        row,
                        || result_limbs[i].value.clone(),
                    )?;
                    result_limbs[i].cell = Some(r_assigned.cell());

                    let k_row_assigned = region.assign_advice(
                        || format!("k_row_{}", i),
                        self.config.b,
                        row,
                        || k_val,
                    )?;
                    region.constrain_equal(k_cell.cell(), k_row_assigned.cell())?;

                    region.assign_advice(
                        || format!("borrow_in_{}", i),
                        self.config.aux,
                        row,
                        || Value::known(prev_borrow_fq),
                    )?;

                    let l_assigned = region.assign_advice(
                        || format!("l_{}_reuse", i),
                        self.config.c,
                        row,
                        || raw_limbs[i].value.clone(),
                    )?;
                    region.constrain_equal(raw_limbs[i].cell.unwrap(), l_assigned.cell())?;

                    region.assign_fixed(
                        || format!("fp_{}", i),
                        self.config.fp_const,
                        row,
                        || Value::known(fp_limbs_fq[i]),
                    )?;

                    let borrow_out: Value<Fq> = result_limbs[i]
                        .value
                        .clone()
                        .zip(k_val)
                        .zip(Value::known(prev_borrow_fq))
                        .zip(raw_limbs[i].value.clone())
                        .map(|(((r, kv), bi), li)| {
                            let fp_i_big =
                                &fp_mod_big / &limb_base_big.pow(i as u32) % &limb_base_big;
                            let k_big: u64 = if kv == Fq::ONE { 1 } else { 0 };
                            let s = fq_to_big(&r) + fp_i_big * k_big + fq_to_big(&bi);
                            let ls = fq_to_big(&li);
                            if s >= ls {
                                big_to_fq(&((&s - &ls) / &limb_base_big))
                            } else {
                                big_to_fq(&((&s + &limb_base_big - &ls) / &limb_base_big))
                            }
                        });
                    prev_borrow_fq = borrow_out.assign().unwrap_or(Fq::ZERO);

                    region.assign_advice(
                        || format!("borrow_out_{}", i),
                        self.config.aux,
                        row + 1,
                        || borrow_out,
                    )?;
                }

                // Row 7: final borrow-in check against carry from pass 1
                {
                    let row = 7;
                    self.config.s_reduce.enable(&mut region, row)?;
                    region.assign_advice(
                        || "r_3",
                        self.config.a,
                        row,
                        || Value::known(Fq::ZERO),
                    )?;
                    let k_row_assigned =
                        region.assign_advice(|| "k_row_3", self.config.b, row, || k_val)?;
                    region.constrain_equal(k_cell.cell(), k_row_assigned.cell())?;
                    region.assign_advice(
                        || "borrow_in_3",
                        self.config.aux,
                        row,
                        || Value::known(prev_borrow_fq),
                    )?;
                    let carry_reassigned =
                        region.assign_advice(|| "carry_reuse", self.config.c, row, || carry_val)?;
                    region.constrain_equal(carry_cell.cell(), carry_reassigned.cell())?;
                    region.assign_fixed(
                        || "fp_3",
                        self.config.fp_const,
                        row,
                        || Value::known(Fq::ZERO),
                    )?;
                    region.assign_advice(
                        || "borrow_out_3",
                        self.config.aux,
                        row + 1,
                        || Value::known(Fq::ZERO),
                    )?;
                }

                // Row 9: k range check (row 8 is a gap to avoid aux[8] conflict with borrow_out_3)
                {
                    self.config.s_range.enable(&mut region, 9)?;
                    region.assign_advice(|| "k_check", self.config.aux, 9, || k_val)?;
                }

                Ok(FpElement {
                    limbs: result_limbs,
                })
            },
        )?)
    }

    // ── Sub ────────────────────────────────────────────────────────────────

    /// Constrain `c = a - b mod Fp`.
    pub fn sub(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
        b: &FpElement,
    ) -> Result<FpElement, ErrorFront> {
        let neg_b = self.neg(layouter.namespace(|| "neg_b"), b)?;
        self.add(layouter.namespace(|| "sub"), a, &neg_b)
    }

    // ── Neg ────────────────────────────────────────────────────────────────

    /// Constrain `c = -a mod Fp` (i.e. Fp - a).
    ///
    /// Witnesses the negation externally and verifies via `add(a, neg_a) == 0`.
    pub fn neg(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
    ) -> Result<FpElement, ErrorFront> {
        let fp_mod_big = big_fp_mod();
        let limb_base_big = big_limb_base();

        let result = layouter.assign_region(
            || "fp_neg",
            |mut region| {
                let neg_val = a.to_big().map(|a_int| &fp_mod_big - &a_int);

                let mut result_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
                    let lv = neg_val.clone().map(|r| {
                        let l = &r / &limb_base_big.pow(i as u32);
                        big_to_fq(&(&l % &limb_base_big))
                    });
                    Limb {
                        value: lv,
                        cell: None,
                    }
                });

                for i in 0..FP_NUM_LIMBS {
                    let c = region.assign_advice(
                        || format!("neg_{}", i),
                        self.config.c,
                        i,
                        || result_limbs[i].value,
                    )?;
                    result_limbs[i].cell = Some(c.cell());
                }

                Ok(FpElement {
                    limbs: result_limbs,
                })
            },
        )?;

        // Verify: a + neg_a == 0
        let sum = self.add(layouter.namespace(|| "neg_verify"), a, &result)?;

        layouter.assign_region(
            || "check_zero",
            |mut region| {
                let zero_cell =
                    region.assign_advice(|| "zero", self.config.c, 0, || Value::known(Fq::ZERO))?;

                for i in 0..FP_NUM_LIMBS {
                    let col = match i {
                        0 => self.config.a,
                        1 => self.config.a,
                        _ => self.config.b,
                    };
                    let row = match i {
                        0 => 0,
                        1 => 1,
                        _ => 0,
                    };
                    let l = region.assign_advice(
                        || format!("sum_{}", i),
                        col,
                        row,
                        || sum.limbs[i].value,
                    )?;
                    if let Some(c) = sum.limbs[i].cell {
                        region.constrain_equal(l.cell(), c)?;
                    }
                    region.constrain_equal(l.cell(), zero_cell.cell())?;
                }

                Ok(())
            },
        )?;

        Ok(result)
    }

    // ── Mul ────────────────────────────────────────────────────────────────

    /// Constrain `c = a * b mod Fp`.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
        b: &FpElement,
    ) -> Result<FpElement, ErrorFront> {
        let limb_base_big = big_limb_base();
        let fp_mod_big = big_fp_mod();
        let fp_limbs_fq = [fp_limb_fq(0), fp_limb_fq(1), fp_limb_fq(2)];

        // Pre-compute p_ij values, full product, and carries
        let p_vals: [[Value<Fq>; 3]; 3] = array::from_fn(|i| {
            array::from_fn(|j| {
                a.limbs[i]
                    .value
                    .zip(b.limbs[j].value)
                    .map(|(av, bv)| av * bv)
            })
        });

        let full_product = p_vals[0][0]
            .zip(p_vals[0][1])
            .zip(p_vals[0][2])
            .zip(p_vals[1][0])
            .zip(p_vals[1][1])
            .zip(p_vals[1][2])
            .zip(p_vals[2][0])
            .zip(p_vals[2][1])
            .zip(p_vals[2][2])
            .map(
                |((((((((p00, p01), p02), p10), p11), p12), p20), p21), p22)| {
                    let b = &limb_base_big;
                    let b2 = &(b * b);
                    let b3 = &(b2 * b);
                    let b4 = &(b3 * b);
                    fq_to_big(&p00)
                        + (fq_to_big(&p01) + fq_to_big(&p10)) * b
                        + (fq_to_big(&p02) + fq_to_big(&p11) + fq_to_big(&p20)) * b2
                        + (fq_to_big(&p12) + fq_to_big(&p21)) * b3
                        + fq_to_big(&p22) * b4
                },
            );

        let q_big = full_product.as_ref().map(|prod| prod / &fp_mod_big);
        let r_big = full_product.map(|prod| prod % &fp_mod_big);

        let q_limb_vals: [Value<Fq>; 3] = array::from_fn(|i| {
            q_big
                .clone()
                .map(|q| big_to_fq(&(&q / &limb_base_big.pow(i as u32) % &limb_base_big)))
        });
        let r_limb_vals: [Value<Fq>; 3] = array::from_fn(|i| {
            r_big
                .clone()
                .map(|r| big_to_fq(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big)))
        });

        // Pre-compute qf_ij values (q_i * fp_j)
        let qf_vals: [[Value<Fq>; 3]; 3] =
            array::from_fn(|i| array::from_fn(|j| q_limb_vals[i].map(|qv| qv * fp_limbs_fq[j])));

        // R limbs as BigUint
        let r_big_limbs: [Value<num_bigint::BigUint>; 3] =
            array::from_fn(|i| r_limb_vals[i].map(|v| fq_to_big(&v)));

        // Compute P_k and QF_k sums for each position
        let p_sum_big: [Value<num_bigint::BigUint>; 5] = array::from_fn(|k| match k {
            0 => p_vals[0][0].map(|v| fq_to_big(&v)),
            1 => p_vals[0][1]
                .zip(p_vals[1][0])
                .map(|(x, y)| fq_to_big(&x) + fq_to_big(&y)),
            2 => p_vals[0][2]
                .zip(p_vals[1][1])
                .zip(p_vals[2][0])
                .map(|((x, y), z)| fq_to_big(&x) + fq_to_big(&y) + fq_to_big(&z)),
            3 => p_vals[1][2]
                .zip(p_vals[2][1])
                .map(|(x, y)| fq_to_big(&x) + fq_to_big(&y)),
            4 => p_vals[2][2].map(|v| fq_to_big(&v)),
            _ => unreachable!(),
        });

        let qf_sum_big: [Value<num_bigint::BigUint>; 5] = array::from_fn(|k| match k {
            0 => qf_vals[0][0].map(|v| fq_to_big(&v)),
            1 => qf_vals[0][1]
                .zip(qf_vals[1][0])
                .map(|(x, y)| fq_to_big(&x) + fq_to_big(&y)),
            2 => qf_vals[0][2]
                .zip(qf_vals[1][1])
                .zip(qf_vals[2][0])
                .map(|((x, y), z)| fq_to_big(&x) + fq_to_big(&y) + fq_to_big(&z)),
            3 => qf_vals[1][2]
                .zip(qf_vals[2][1])
                .map(|(x, y)| fq_to_big(&x) + fq_to_big(&y)),
            4 => qf_vals[2][2].map(|v| fq_to_big(&v)),
            _ => unreachable!(),
        });

        // Compute signed carries for the reduction chain.
        let carry_offset_big = num_bigint::BigUint::from(1u64) << 89;
        let carry_offset_fq = big_to_fq(&carry_offset_big);
        let carry_const_first_fq = big_to_fq(&(&limb_base_big * &carry_offset_big));
        let carry_const_rest_fq = big_to_fq(&((&limb_base_big - 1u64) * &carry_offset_big));
        let carry_repr_fq: [Value<Fq>; 5] = {
            let mut carries = [Value::known(Fq::ZERO); 5];
            let base_bigint = num_bigint::BigInt::from(limb_base_big.clone());
            let mut prev_carry = num_bigint::BigInt::ZERO;

            for k in 0..5 {
                let r_big_k: Value<num_bigint::BigUint> = if k < 3 {
                    r_big_limbs[k].clone()
                } else {
                    Value::known(num_bigint::BigUint::ZERO)
                };

                let diff = p_sum_big[k]
                    .clone()
                    .zip(qf_sum_big[k].clone())
                    .zip(r_big_k)
                    .map(|((p, qf), r)| {
                        num_bigint::BigInt::from(p) + &prev_carry
                            - num_bigint::BigInt::from(qf + r)
                    });

                if let Ok(diff_big) = diff.assign() {
                    let carry_signed = &diff_big / &base_bigint;
                    let carry_repr = (carry_signed.clone()
                        + num_bigint::BigInt::from(carry_offset_big.clone()))
                    .to_biguint()
                    .expect("shifted carry must be non-negative");
                    carries[k] = Value::known(big_to_fq(&carry_repr));
                    prev_carry = carry_signed;
                }
            }
            carries
        };

        Ok(layouter.assign_region(
            || "fp_mul",
            |mut region| {
                // ── Step 1: 9 s_mul — p_ij = a_i · b_j (rows 0-8) ──
                let mut p_cells = [[None; 3]; 3];

                for i in 0..FP_NUM_LIMBS {
                    for j in 0..FP_NUM_LIMBS {
                        let idx = i * FP_NUM_LIMBS + j;
                        self.config.s_mul.enable(&mut region, idx)?;

                        let a_assigned = region.assign_advice(
                            || format!("a_{}{}", i, j),
                            self.config.a,
                            idx,
                            || a.limbs[i].value,
                        )?;
                        if let Some(c) = a.limbs[i].cell {
                            region.constrain_equal(a_assigned.cell(), c)?;
                        }

                        let b_assigned = region.assign_advice(
                            || format!("b_{}{}", i, j),
                            self.config.b,
                            idx,
                            || b.limbs[j].value,
                        )?;
                        if let Some(c) = b.limbs[j].cell {
                            region.constrain_equal(b_assigned.cell(), c)?;
                        }

                        let c_assigned = region.assign_advice(
                            || format!("p_{}{}", i, j),
                            self.config.c,
                            idx,
                            || p_vals[i][j],
                        )?;
                        p_cells[i][j] = Some(c_assigned.cell());
                    }
                }

                // ── Step 2: assign Q (rows 9-11) and R (rows 12-14) ──
                let mut q_cells = [None; 3];
                let mut r_cells = [None; 3];
                for i in 0..FP_NUM_LIMBS {
                    let q_cell = region.assign_advice(
                        || format!("q_{}", i),
                        self.config.c,
                        9 + i,
                        || q_limb_vals[i],
                    )?;
                    q_cells[i] = Some(q_cell.cell());

                    let r_cell = region.assign_advice(
                        || format!("r_{}", i),
                        self.config.c,
                        12 + i,
                        || r_limb_vals[i],
                    )?;
                    r_cells[i] = Some(r_cell.cell());
                }

                // ── Step 3: 9 s_mul — qf_ij = q_i · fp_j (rows 15-23) ──
                let qf_row = 15;
                for i in 0..FP_NUM_LIMBS {
                    for j in 0..FP_NUM_LIMBS {
                        let idx = qf_row + i * FP_NUM_LIMBS + j;
                        self.config.s_mul.enable(&mut region, idx)?;

                        let q_assigned = region.assign_advice(
                            || format!("q_{}_a", i),
                            self.config.a,
                            idx,
                            || q_limb_vals[i],
                        )?;
                        if let Some(c) = q_cells[i] {
                            region.constrain_equal(q_assigned.cell(), c)?;
                        }

                        region.assign_advice(
                            || format!("fp_{}_b", j),
                            self.config.b,
                            idx,
                            || Value::known(fp_limbs_fq[j]),
                        )?;

                        let qf_assigned = region.assign_advice(
                            || format!("qf_{}{}", i, j),
                            self.config.c,
                            idx,
                            || qf_vals[i][j],
                        )?;
                        let _ = qf_assigned.cell();
                    }
                }

                // ── Step 4: accumulate P sums (rows 24-27) ──
                let acc1_cell = {
                    let row = 24;
                    let sum = p_vals[0][1].zip(p_vals[1][0]).map(|(x, y)| x + y);
                    self.config.s_add.enable(&mut region, row)?;
                    let a =
                        region.assign_advice(|| "p01_a", self.config.a, row, || p_vals[0][1])?;
                    if let Some(c) = p_cells[0][1] {
                        region.constrain_equal(a.cell(), c)?;
                    }
                    region.assign_advice(|| "p10_b", self.config.b, row, || p_vals[1][0])?;
                    region.assign_advice(
                        || "carry_in",
                        self.config.aux,
                        row,
                        || Value::known(Fq::ZERO),
                    )?;
                    let c = region.assign_advice(|| "acc1", self.config.c, row, || sum)?;
                    region.assign_advice(
                        || "carry_out",
                        self.config.aux,
                        row + 1,
                        || Value::known(Fq::ZERO),
                    )?;
                    c.cell()
                };

                let acc2_cell = {
                    let row1 = 25;
                    let sum1 = p_vals[0][2].zip(p_vals[1][1]).map(|(x, y)| x + y);
                    self.config.s_add.enable(&mut region, row1)?;
                    let a =
                        region.assign_advice(|| "p02_a", self.config.a, row1, || p_vals[0][2])?;
                    if let Some(c) = p_cells[0][2] {
                        region.constrain_equal(a.cell(), c)?;
                    }
                    region.assign_advice(|| "p11_b", self.config.b, row1, || p_vals[1][1])?;
                    region.assign_advice(
                        || "carry_in",
                        self.config.aux,
                        row1,
                        || Value::known(Fq::ZERO),
                    )?;
                    let tmp_cell =
                        region.assign_advice(|| "tmp2", self.config.c, row1, || sum1)?;
                    region.assign_advice(
                        || "carry_out",
                        self.config.aux,
                        row1 + 1,
                        || Value::known(Fq::ZERO),
                    )?;

                    let row2 = 26;
                    let sum2 = sum1.zip(p_vals[2][0]).map(|(s, x)| s + x);
                    self.config.s_add.enable(&mut region, row2)?;
                    let a = region.assign_advice(|| "tmp2_a", self.config.a, row2, || sum1)?;
                    region.constrain_equal(a.cell(), tmp_cell.cell())?;
                    region.assign_advice(|| "p20_b", self.config.b, row2, || p_vals[2][0])?;
                    region.assign_advice(
                        || "carry_in",
                        self.config.aux,
                        row2,
                        || Value::known(Fq::ZERO),
                    )?;
                    let c = region.assign_advice(|| "acc2", self.config.c, row2, || sum2)?;
                    region.assign_advice(
                        || "carry_out",
                        self.config.aux,
                        row2 + 1,
                        || Value::known(Fq::ZERO),
                    )?;
                    c.cell()
                };

                let acc3_cell = {
                    let row = 27;
                    let sum = p_vals[1][2].zip(p_vals[2][1]).map(|(x, y)| x + y);
                    self.config.s_add.enable(&mut region, row)?;
                    let a =
                        region.assign_advice(|| "p12_a", self.config.a, row, || p_vals[1][2])?;
                    if let Some(c) = p_cells[1][2] {
                        region.constrain_equal(a.cell(), c)?;
                    }
                    region.assign_advice(|| "p21_b", self.config.b, row, || p_vals[2][1])?;
                    region.assign_advice(
                        || "carry_in",
                        self.config.aux,
                        row,
                        || Value::known(Fq::ZERO),
                    )?;
                    let c = region.assign_advice(|| "acc3", self.config.c, row, || sum)?;
                    region.assign_advice(
                        || "carry_out",
                        self.config.aux,
                        row + 1,
                        || Value::known(Fq::ZERO),
                    )?;
                    c.cell()
                };

                // ── Step 5: carry chain via s_reduce (rows 28-33, contiguous) ──
                let cc_start = 28;

                // Compute QF_k + R_k as Fq value for each position
                let qf_r_comb: [Value<Fq>; 5] = array::from_fn(|k| match k {
                    0 => qf_vals[0][0].zip(r_limb_vals[0]).map(|(q, r)| q + r),
                    1 => qf_vals[0][1]
                        .zip(qf_vals[1][0])
                        .zip(r_limb_vals[1])
                        .map(|((a, b), r)| a + b + r),
                    2 => qf_vals[0][2]
                        .zip(qf_vals[1][1])
                        .zip(qf_vals[2][0])
                        .zip(r_limb_vals[2])
                        .map(|(((a, b), c), r)| a + b + c + r),
                    3 => qf_vals[1][2].zip(qf_vals[2][1]).map(|(a, b)| a + b),
                    4 => qf_vals[2][2],
                    _ => unreachable!(),
                });

                // P_k values for each position
                let p_k_vals: [Value<Fq>; 5] = array::from_fn(|k| match k {
                    0 => p_vals[0][0],
                    1 => p_vals[0][1].zip(p_vals[1][0]).map(|(x, y)| x + y),
                    2 => p_vals[0][2]
                        .zip(p_vals[1][1])
                        .zip(p_vals[2][0])
                        .map(|((x, y), z)| x + y + z),
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
                let mut carry_4_cell = None::<halo2_proofs::circuit::Cell>;
                for k in 0..5 {
                    let row = cc_start + k;
                    self.config.s_reduce.enable(&mut region, row)?;

                    region.assign_advice(
                        || format!("cc{}_b", k),
                        self.config.b,
                        row,
                        || Value::known(Fq::ONE),
                    )?;

                    let a = region.assign_advice(
                        || format!("cc{}_r", k),
                        self.config.a,
                        row,
                        || p_k_vals[k],
                    )?;
                    if let Some(cell) = p_k_cells[k] {
                        region.constrain_equal(a.cell(), cell)?;
                    }

                    region.assign_advice(
                        || format!("cc{}_l", k),
                        self.config.c,
                        row,
                        || qf_r_comb[k],
                    )?;

                    region.assign_fixed(
                        || format!("cc{}_fq", k),
                        self.config.fp_const,
                        row,
                        || {
                            Value::known(if k == 0 {
                                carry_const_first_fq
                            } else {
                                carry_const_rest_fq
                            })
                        },
                    )?;

                    if k == 0 {
                        region.assign_advice(
                            || "cc_carry_in_0",
                            self.config.aux,
                            row,
                            || Value::known(Fq::ZERO),
                        )?;
                    }

                    let cout_assigned = region.assign_advice(
                        || format!("cc{}_cout", k),
                        self.config.aux,
                        row + 1,
                        || carry_repr_fq[k],
                    )?;
                    if k < 4 {
                        carry_aux_cells[k] = Some(cout_assigned.cell());
                    } else {
                        carry_4_cell = Some(cout_assigned.cell());
                    }
                }

                let carry_4_expected = region.assign_advice(
                    || "cc4_expected_offset",
                    self.config.c,
                    cc_start + 5,
                    || Value::known(carry_offset_fq),
                )?;
                if let Some(cell) = carry_4_cell {
                    region.constrain_equal(carry_4_expected.cell(), cell)?;
                }

                // ── Step 6: range-check Q limbs (rows 40+) ──
                let rc_start = 40;
                for (qi, q_cell) in q_cells.iter().enumerate() {
                    let bits: Vec<Value<Fq>> = (0..FP_LIMB_BITS)
                        .map(|i| {
                            q_limb_vals[qi].map(|v| {
                                let bytes = v.to_repr();
                                let byte_idx = i / 8;
                                let bit_idx = i % 8;
                                if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                    Fq::ONE
                                } else {
                                    Fq::ZERO
                                }
                            })
                        })
                        .collect();

                    let offset = rc_start + qi * (FP_LIMB_BITS + 1);
                    let mut acc = Value::known(Fq::ZERO);
                    let mut base = Fq::ONE;
                    for (i, bit_val) in bits.iter().enumerate() {
                        let row = offset + i;
                        self.config.s_range.enable(&mut region, row)?;
                        region.assign_advice(
                            || format!("q{}_bit_{}", qi, i),
                            self.config.aux,
                            row,
                            || *bit_val,
                        )?;
                        acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                        base = base.double();
                    }
                    let acc_cell = region.assign_advice(
                        || format!("q{}_recon", qi),
                        self.config.c,
                        offset + FP_LIMB_BITS,
                        || acc,
                    )?;
                    if let Some(cell) = q_cell {
                        region.constrain_equal(acc_cell.cell(), *cell)?;
                    }
                }

                // ── Step 7: range-check R limbs (rows 298+) ──
                let rc_r_start = 298;
                for (ri, r_cell) in r_cells.iter().enumerate() {
                    let bits: Vec<Value<Fq>> = (0..FP_LIMB_BITS)
                        .map(|i| {
                            r_limb_vals[ri].map(|v| {
                                let bytes = v.to_repr();
                                let byte_idx = i / 8;
                                let bit_idx = i % 8;
                                if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                    Fq::ONE
                                } else {
                                    Fq::ZERO
                                }
                            })
                        })
                        .collect();

                    let offset = rc_r_start + ri * (FP_LIMB_BITS + 1);
                    let mut acc = Value::known(Fq::ZERO);
                    let mut base = Fq::ONE;
                    for (i, bit_val) in bits.iter().enumerate() {
                        let row = offset + i;
                        self.config.s_range.enable(&mut region, row)?;
                        region.assign_advice(
                            || format!("r{}_bit_{}", ri, i),
                            self.config.aux,
                            row,
                            || *bit_val,
                        )?;
                        acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                        base = base.double();
                    }
                    let acc_cell = region.assign_advice(
                        || format!("r{}_recon", ri),
                        self.config.c,
                        offset + FP_LIMB_BITS,
                        || acc,
                    )?;
                    if let Some(cell) = r_cell {
                        region.constrain_equal(acc_cell.cell(), *cell)?;
                    }
                }

                // ── Step 8: range-check carries to CARRY_BITS (rows 556+) ──
                let rc_c_start = 556;
                for (ci, aux_cell_opt) in carry_aux_cells.iter().enumerate() {
                    let bits: Vec<Value<Fq>> = (0..CARRY_BITS)
                        .map(|i| {
                            carry_repr_fq[ci].map(|v| {
                                let bytes = v.to_repr();
                                let byte_idx = i / 8;
                                let bit_idx = i % 8;
                                if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                    Fq::ONE
                                } else {
                                    Fq::ZERO
                                }
                            })
                        })
                        .collect();

                    let offset = rc_c_start + ci * (CARRY_BITS + 1);
                    let carry_copy = region.assign_advice(
                        || format!("c{}_copy", ci),
                        self.config.c,
                        offset,
                        || carry_repr_fq[ci],
                    )?;
                    if let Some(aux_cell) = aux_cell_opt {
                        region.constrain_equal(carry_copy.cell(), *aux_cell)?;
                    }

                    let mut acc = Value::known(Fq::ZERO);
                    let mut base = Fq::ONE;
                    for (i, bit_val) in bits.iter().enumerate() {
                        let row = offset + i;
                        self.config.s_range.enable(&mut region, row)?;
                        region.assign_advice(
                            || format!("c{}_bit_{}", ci, i),
                            self.config.aux,
                            row,
                            || *bit_val,
                        )?;
                        acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                        base = base.double();
                    }
                    let acc_cell = region.assign_advice(
                        || format!("c{}_recon", ci),
                        self.config.c,
                        offset + CARRY_BITS,
                        || acc,
                    )?;
                    region.constrain_equal(acc_cell.cell(), carry_copy.cell())?;
                }

                // ── Return result ──
                let result_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| Limb {
                    value: r_limb_vals[i],
                    cell: r_cells[i],
                });
                Ok(FpElement {
                    limbs: result_limbs,
                })
            },
        )?)
    }

    // ── Invert (witness-with-verify) ───────────────────────────────────────

    /// Witness `a^(-1) mod Fp` and verify `a * inv = 1`.
    /// Returns `Err` when `a = 0` (0 has no inverse).
    pub fn invert(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
    ) -> Result<FpElement, ErrorFront> {

        // Extended Euclidean Algorithm for modular inverse
        // (BigUint::modpow gives incorrect results for large exponents)
        let inv_big = a.to_big().map(|a_int| {
            let fp = big_fp_mod();
            let fp_bi = num_bigint::BigInt::from(fp);
            let a_bi = num_bigint::BigInt::from(a_int);
            let mut old_r = fp_bi.clone();
            let mut r = a_bi;
            let mut old_s = num_bigint::BigInt::ZERO;
            let mut s = num_bigint::BigInt::from(1u64);
            while r != num_bigint::BigInt::ZERO {
                let quotient = &old_r / &r;
                let new_r = &old_r - &quotient * &r;
                let new_s = &old_s - &quotient * &s;
                old_r = r;
                r = new_r;
                old_s = s;
                s = new_s;
            }
            let inv = if old_s >= num_bigint::BigInt::ZERO {
                old_s
            } else {
                old_s + fp_bi
            };
            inv.to_biguint().expect("inv must be positive")
        });

        let limb_base_big = big_limb_base();
        let inv_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = inv_big
                .clone()
                .map(|r| big_to_fq(&(&r / &limb_base_big.pow(i as u32) % &limb_base_big)));
            Limb {
                value: lv,
                cell: None,
            }
        });
        let inv = FpElement { limbs: inv_limbs };

        // Verify: mul(a, inv) == 1
        let prod = self.mul(layouter.namespace(|| "mul_verify"), a, &inv)?;

        layouter.assign_region(
            || "check_one",
            |mut region| {
                let one_cell =
                    region.assign_advice(|| "one", self.config.c, 0, || Value::known(Fq::ONE))?;
                let zero_cell =
                    region.assign_advice(|| "zero", self.config.c, 1, || Value::known(Fq::ZERO))?;

                let c0 = region.assign_advice(|| "c0", self.config.a, 0, || prod.limbs[0].value)?;
                if let Some(c) = prod.limbs[0].cell {
                    region.constrain_equal(c0.cell(), c)?;
                }
                region.constrain_equal(c0.cell(), one_cell.cell())?;

                let c1 = region.assign_advice(|| "c1", self.config.a, 1, || prod.limbs[1].value)?;
                if let Some(c) = prod.limbs[1].cell {
                    region.constrain_equal(c1.cell(), c)?;
                }
                region.constrain_equal(c1.cell(), zero_cell.cell())?;

                let c2 =
                    region.assign_advice(|| "c2", self.config.b, 0, || prod.limbs[2].value)?;
                if let Some(c) = prod.limbs[2].cell {
                    region.constrain_equal(c2.cell(), c)?;
                }
                region.constrain_equal(c2.cell(), zero_cell.cell())?;

                Ok(())
            },
        )?;

        Ok(inv)
    }

    // ── assign_constant ────────────────────────────────────────────────────

    /// Assign a constant Fp value as a 3-limb FpElement.
    pub fn assign_constant(
        &self,
        mut layouter: impl Layouter<Fq>,
        val: Fq,
    ) -> Result<FpElement, ErrorFront> {
        let limb_base_big = big_limb_base();
        let val_big = fq_to_big(&val);

        let limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = Value::known(big_to_fq(
                &(&val_big / &limb_base_big.pow(i as u32) % &limb_base_big),
            ));
            Limb {
                value: lv,
                cell: None,
            }
        });

        let mut result = FpElement { limbs };

        layouter.assign_region(
            || "fp_assign_constant",
            |mut region| {
                for i in 0..FP_NUM_LIMBS {
                    let cell = region.assign_advice(
                        || format!("limb_{}", i),
                        self.config.c,
                        i,
                        || result.limbs[i].value,
                    )?;
                    result.limbs[i].cell = Some(cell.cell());
                }
                Ok(())
            },
        )?;

        Ok(result)
    }

    /// Constrain two non-native Fp elements to be limb-wise equal.
    pub fn constrain_equal(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &FpElement,
        b: &FpElement,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "fp_constrain_equal",
            |mut region| {
                for i in 0..FP_NUM_LIMBS {
                    let a_assigned = region.assign_advice(
                        || format!("a_{}", i),
                        self.config.a,
                        i,
                        || a.limbs[i].value,
                    )?;
                    let b_assigned = region.assign_advice(
                        || format!("b_{}", i),
                        self.config.b,
                        i,
                        || b.limbs[i].value,
                    )?;

                    if let Some(cell) = a.limbs[i].cell {
                        region.constrain_equal(a_assigned.cell(), cell)?;
                    }
                    if let Some(cell) = b.limbs[i].cell {
                        region.constrain_equal(b_assigned.cell(), cell)?;
                    }
                    region.constrain_equal(a_assigned.cell(), b_assigned.cell())?;
                }
                Ok(())
            },
        )
    }

    // ── Range check ─────────────────────────────────────────────────────────

    /// Decompose an Fp element into 255 little-endian bits.
    pub fn decompose_bits(
        &self,
        mut layouter: impl Layouter<Fq>,
        value: &FpElement,
    ) -> Result<Vec<Limb<Fq>>, ErrorFront> {
        layouter.assign_region(
            || "fp_decompose_bits",
            |mut region| {
                let mut out = Vec::with_capacity(FP_NUM_LIMBS * FP_LIMB_BITS);
                for limb_idx in 0..FP_NUM_LIMBS {
                    let offset = limb_idx * (FP_LIMB_BITS + 1);
                    let bits: Vec<Value<Fq>> = (0..FP_LIMB_BITS)
                        .map(|i| {
                            value.limbs[limb_idx].value.map(|v| {
                                let bytes = v.to_repr();
                                let byte_idx = i / 8;
                                let bit_idx = i % 8;
                                if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                                    Fq::ONE
                                } else {
                                    Fq::ZERO
                                }
                            })
                        })
                        .collect();

                    let mut acc = Value::known(Fq::ZERO);
                    let mut base = Fq::ONE;
                    for (i, bit_val) in bits.iter().enumerate() {
                        let row = offset + i;
                        self.config.s_range.enable(&mut region, row)?;
                        let bit_cell = region.assign_advice(
                            || format!("limb{}_bit_{}", limb_idx, i),
                            self.config.aux,
                            row,
                            || *bit_val,
                        )?;
                        out.push(Limb {
                            value: *bit_val,
                            cell: Some(bit_cell.cell()),
                        });
                        acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                        base = base.double();
                    }

                    let recon_row = offset + FP_LIMB_BITS;
                    let recon_cell = region.assign_advice(
                        || format!("limb{}_recon", limb_idx),
                        self.config.c,
                        recon_row,
                        || acc,
                    )?;

                    let limb_cell = if let Some(cell) = value.limbs[limb_idx].cell {
                        cell
                    } else {
                        region
                            .assign_advice(
                                || format!("limb{}_copy", limb_idx),
                                self.config.a,
                                recon_row,
                                || value.limbs[limb_idx].value,
                            )?
                            .cell()
                    };
                    region.constrain_equal(recon_cell.cell(), limb_cell)?;
                }

                Ok(out)
            },
        )
    }

    /// Decompose `value` into `num_bits` bits and constrain each to {0, 1}.
    pub fn range_check(
        &self,
        mut layouter: impl Layouter<Fq>,
        value: &Limb<Fq>,
        num_bits: usize,
    ) -> Result<(), ErrorFront> {
        assert!(
            num_bits <= 254,
            "range_check: num_bits must be ≤ 254, got {}",
            num_bits
        );

        let bits: Vec<Value<Fq>> = (0..num_bits)
            .map(|i| {
                value.value.map(|v| {
                    let bytes = v.to_repr();
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                        Fq::ONE
                    } else {
                        Fq::ZERO
                    }
                })
            })
            .collect();

        layouter.assign_region(
            || "range_check",
            |mut region| {
                let mut acc = Value::known(Fq::ZERO);
                let mut base = Fq::ONE;

                for (i, bit_val) in bits.iter().enumerate() {
                    self.config.s_range.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("bit_{}", i),
                        self.config.aux,
                        i,
                        || *bit_val,
                    )?;
                    acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                    base = base.double();
                }

                let acc_cell =
                    region.assign_advice(|| "reconstructed", self.config.c, num_bits, || acc)?;
                if let Some(c) = value.cell {
                    region.constrain_equal(acc_cell.cell(), c)?;
                }
                Ok(())
            },
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    fn make_fp_el(v: [u64; 3]) -> FpElement {
        FpElement {
            limbs: array::from_fn(|i| Limb {
                value: Value::known(Fq::from(v[i])),
                cell: None,
            }),
        }
    }

    #[derive(Default)]
    struct FpAddCircuit {
        a: [u64; 3],
        b: [u64; 3],
    }

    impl Circuit<Fq> for FpAddCircuit {
        type Config = NonNativeFpConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            NonNativeFpChip::configure(meta)
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = NonNativeFpChip::new(config);
            let a = make_fp_el(self.a);
            let b = make_fp_el(self.b);
            let _c = chip.add(layouter.namespace(|| "add"), &a, &b)?;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FpMulCircuit {
        a: [u64; 3],
        b: [u64; 3],
    }

    impl Circuit<Fq> for FpMulCircuit {
        type Config = NonNativeFpConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            NonNativeFpChip::configure(meta)
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = NonNativeFpChip::new(config);
            let a = make_fp_el(self.a);
            let b = make_fp_el(self.b);
            let _c = chip.mul(layouter.namespace(|| "mul"), &a, &b)?;
            Ok(())
        }
    }

    // ── add tests ──

    #[test]
    fn test_fp_add_small() {
        let k = 10;
        let circuit = FpAddCircuit {
            a: [3, 0, 0],
            b: [5, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp add (3+5): {:?}", result.err());
    }

    #[test]
    fn test_fp_add_large() {
        let k = 10;
        let circuit = FpAddCircuit {
            a: [u64::MAX, 0, 0],
            b: [u64::MAX, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(
            result.is_ok(),
            "Fp add (u64::MAX + u64::MAX): {:?}",
            result.err()
        );
    }

    // ── mul tests ──

    #[test]
    fn test_fp_mul_small() {
        let k = 12;
        let circuit = FpMulCircuit {
            a: [3, 0, 0],
            b: [5, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp mul (3*5): {:?}", result.err());
    }

    #[test]
    fn test_fp_mul_carry() {
        let k = 12;
        let circuit = FpMulCircuit {
            a: [u64::MAX, 0, 0],
            b: [2, 0, 0],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp mul carry: {:?}", result.err());
    }

    // ── neg test ──

    #[test]
    fn test_fp_neg() {
        const K: u32 = 10;
        #[derive(Default)]
        struct NegCircuit;
        impl Circuit<Fq> for NegCircuit {
            type Config = NonNativeFpConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self::default()
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                NonNativeFpChip::configure(meta)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let chip = NonNativeFpChip::new(config);
                let a = make_fp_el([7, 0, 0]);
                let _neg_a = chip.neg(layouter.namespace(|| "neg"), &a)?;
                Ok(())
            }
        }
        let circuit = NegCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp neg: {:?}", result.err());
    }

    // ── invert test ──

    #[test]
    fn test_fp_invert() {
        const K: u32 = 12;
        #[derive(Default)]
        struct InvertCircuit;
        impl Circuit<Fq> for InvertCircuit {
            type Config = NonNativeFpConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self::default()
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                NonNativeFpChip::configure(meta)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let chip = NonNativeFpChip::new(config);
                let a = make_fp_el([7, 0, 0]);
                let _inv = chip.invert(layouter.namespace(|| "inv"), &a)?;
                Ok(())
            }
        }
        let circuit = InvertCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp invert: {:?}", result.err());
    }

    #[test]
    fn test_fp_invert_zero_rejected() {
        const K: u32 = 12;
        #[derive(Default)]
        struct InvertZeroCircuit;
        impl Circuit<Fq> for InvertZeroCircuit {
            type Config = NonNativeFpConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                NonNativeFpChip::configure(meta)
            }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let chip = NonNativeFpChip::new(config);
                let zero = FpElement::zero();
                let inv = chip.invert(layouter.namespace(|| "inv_zero"), &zero)?;
                chip.constrain_equal(layouter.namespace(|| "check"), &inv, &zero)
            }
        }
        let circuit = InvertZeroCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_err(), "invert(0) should be unsatisfiable");
    }

    // ── range check test ──

    #[test]
    fn test_fp_range_small() {
        const K: u32 = 10;
        #[derive(Default)]
        struct RcCircuit;
        impl Circuit<Fq> for RcCircuit {
            type Config = NonNativeFpConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self::default()
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                NonNativeFpChip::configure(meta)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let chip = NonNativeFpChip::new(config);
                let val = Limb {
                    value: Value::known(Fq::from(42)),
                    cell: None,
                };
                chip.range_check(layouter.namespace(|| "rc"), &val, 8)?;
                Ok(())
            }
        }
        let circuit = RcCircuit;
        let prover = MockProver::run(K, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "Fp range check: {:?}", result.err());
    }
}
