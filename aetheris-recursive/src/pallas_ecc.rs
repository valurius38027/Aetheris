//! Pallas EC point operations using NonNativeFpChip.
//!
//! Pallas curve: y² = x³ + 5 over base field Fp.
//! Since the recursive circuit runs over Fq, Fp coordinates are non-native —
//! all arithmetic goes through NonNativeFpChip (3 × 85-bit limbs).
//!
//! # Design
//!
//! PallasEccChip does NOT own its own gate selectors. Instead it orchestrates
//! sequences of NonNativeFpChip operations to verify point equations. Each
//! point operation is witness-and-verify: the host computes the expected
//! result (λ, x₃, y₃) natively using Fp arithmetic, and the circuit verifies
//! the constraints using NonNativeFpChip add/sub/mul calls.
//!
//! This is more expensive than VestaEccChip's 1-row gates, but it avoids
//! building custom Fp-arithmetic gates over Circuit<Fq>.

use core::array;

use ff::Field;
use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::ErrorFront,
};

use crate::non_native_fp::{FpElement, NonNativeFpChip, FP_NUM_LIMBS};
use crate::vesta_fq::VestaFqChip;
use crate::Limb;

/// A Pallas point in affine coordinates represented via non-native Fp limbs.
#[derive(Clone, Debug)]
pub struct PallasPoint {
    pub x: FpElement,
    pub y: FpElement,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
}

/// Pallas ECC chip — wraps NonNativeFpChip and VestaFqChip.
#[derive(Clone)]
pub struct PallasEccChip {
    pub fp: NonNativeFpChip,
    pub fq: VestaFqChip,
}

impl std::fmt::Debug for PallasEccChip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PallasEccChip").finish()
    }
}

impl PallasEccChip {
    pub fn new(fp: NonNativeFpChip, fq: VestaFqChip) -> Self {
        Self { fp, fq }
    }

    /// Verify that `point` lies on the Pallas curve: y² - x³ - 5 = 0 mod Fp.
    pub fn assert_on_curve(
        &self,
        mut layouter: impl Layouter<Fq>,
        point: &PallasPoint,
    ) -> Result<PallasPoint, ErrorFront> {
        let y_sq = self.fp.mul(layouter.namespace(|| "on_curve_y_sq"), &point.y, &point.y)?;
        let x_sq = self
            .fp
            .mul(layouter.namespace(|| "on_curve_x_sq"), &point.x, &point.x)?;
        let x_cu = self
            .fp
            .mul(layouter.namespace(|| "on_curve_x_cu"), &x_sq, &point.x)?;
        let y_sq_minus_x_cu = self
            .fp
            .sub(layouter.namespace(|| "on_curve_sub_1"), &y_sq, &x_cu)?;
        let five = self.fp_element_from_u64(5);
        let tmp = self
            .fp
            .sub(layouter.namespace(|| "on_curve_sub_5"), &y_sq_minus_x_cu, &five)?;
        self.constrain_zero(layouter.namespace(|| "on_curve_check"), &tmp)?;

        Ok(PallasPoint {
            x: point.x.clone(),
            y: point.y.clone(),
            x_cell: point.x_cell,
            y_cell: point.y_cell,
        })
    }

    /// Verify R = P + Q.
    ///
    /// `lam`, `rx`, `ry` are host-precomputed FpElement witnesses.
    pub fn point_add(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &PallasPoint,
        q: &PallasPoint,
        lam: &FpElement,
        rx: &FpElement,
        ry: &FpElement,
    ) -> Result<PallasPoint, ErrorFront> {
        let dx = self
            .fp
            .sub(layouter.namespace(|| "pa_dx"), &q.x, &p.x)?;
        let dy = self
            .fp
            .sub(layouter.namespace(|| "pa_dy"), &q.y, &p.y)?;
        let lam_dx = self
            .fp
            .mul(layouter.namespace(|| "pa_lam_dx"), lam, &dx)?;
        self.constrain_equal(
            layouter.namespace(|| "pa_check_lam_dx_eq_dy"),
            &lam_dx,
            &dy,
        )?;

        let lam_sq = self
            .fp
            .mul(layouter.namespace(|| "pa_lam_sq"), lam, lam)?;
        let lam_sq_minus_px = self
            .fp
            .sub(layouter.namespace(|| "pa_lam_sq_minus_px"), &lam_sq, &p.x)?;
        let check_rx = self
            .fp
            .sub(layouter.namespace(|| "pa_lam_sq_minus_px_minus_qx"), &lam_sq_minus_px, &q.x)?;
        self.constrain_equal(layouter.namespace(|| "pa_check_rx"), &check_rx, rx)?;

        let px_minus_rx = self
            .fp
            .sub(layouter.namespace(|| "pa_px_minus_rx"), &p.x, rx)?;
        let lam_px_minus_rx = self
            .fp
            .mul(layouter.namespace(|| "pa_lam_px_minus_rx"), lam, &px_minus_rx)?;
        let check_ry = self
            .fp
            .sub(layouter.namespace(|| "pa_check_ry"), &lam_px_minus_rx, &p.y)?;
        self.constrain_equal(layouter.namespace(|| "pa_check_ry_eq"), &check_ry, ry)?;

        Ok(PallasPoint {
            x: rx.clone(),
            y: ry.clone(),
            x_cell: None,
            y_cell: None,
        })
    }

    /// Verify R = 2P.
    ///
    /// Host computes λ = 3·px² / (2·py), rx = λ² - 2·px, ry = λ·(px - rx) - py.
    pub fn point_double(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &PallasPoint,
        lam: &FpElement,
        rx: &FpElement,
        ry: &FpElement,
    ) -> Result<PallasPoint, ErrorFront> {
        let px_sq = self
            .fp
            .mul(layouter.namespace(|| "pd_px_sq"), &p.x, &p.x)?;
        let three_px_sq = {
            let two_px_sq = self
                .fp
                .add(layouter.namespace(|| "pd_px_sq_double"), &px_sq, &px_sq)?;
            self.fp.add(layouter.namespace(|| "pd_3px_sq"), &two_px_sq, &px_sq)
        }?;
        let two = self.fp_element_from_u64(2);
        let two_py = self
            .fp
            .mul(layouter.namespace(|| "pd_two_py"), &p.y, &two)?;
        let lam_two_py = self
            .fp
            .mul(layouter.namespace(|| "pd_lam_two_py"), lam, &two_py)?;
        self.constrain_equal(
            layouter.namespace(|| "pd_check_lam_2py_eq_3px2"),
            &lam_two_py,
            &three_px_sq,
        )?;

        let lam_sq = self
            .fp
            .mul(layouter.namespace(|| "pd_lam_sq"), lam, lam)?;
        let two_px = self
            .fp
            .mul(layouter.namespace(|| "pd_two_px"), &p.x, &two)?;
        let check_rx = self
            .fp
            .sub(layouter.namespace(|| "pd_check_rx"), &lam_sq, &two_px)?;
        self.constrain_equal(layouter.namespace(|| "pd_check_rx_eq"), &check_rx, rx)?;

        let px_minus_rx = self
            .fp
            .sub(layouter.namespace(|| "pd_px_minus_rx"), &p.x, rx)?;
        let lam_px_minus_rx = self
            .fp
            .mul(layouter.namespace(|| "pd_lam_px_minus_rx"), lam, &px_minus_rx)?;
        let check_ry = self
            .fp
            .sub(layouter.namespace(|| "pd_check_ry"), &lam_px_minus_rx, &p.y)?;
        self.constrain_equal(layouter.namespace(|| "pd_check_ry_eq"), &check_ry, ry)?;

        Ok(PallasPoint {
            x: rx.clone(),
            y: ry.clone(),
            x_cell: None,
            y_cell: None,
        })
    }

    /// Conditionally select between two Pallas points.
    ///
    /// For each of the 6 limbs (3 per coordinate):
    ///   result_limb = bit * b_limb + (1-bit) * a_limb
    pub fn select(
        &self,
        mut layouter: impl Layouter<Fq>,
        bit: Value<Fq>,
        a: &PallasPoint,
        b: &PallasPoint,
    ) -> Result<PallasPoint, ErrorFront> {
        let bit_limb = Limb { value: bit, cell: None };
        let one_minus_bit_val = bit.map(|b| Fq::ONE - b);
        let one_minus_bit_limb = Limb { value: one_minus_bit_val, cell: None };

        macro_rules! select_limb {
            ($label:expr, $a_limb:expr, $b_limb:expr) => {{
                let t1 = self.fq.mul(
                    layouter.namespace(|| format!("{}_t1", $label)),
                    &bit_limb, $b_limb,
                    &format!("{}_t1", $label),
                )?;
                let t2 = self.fq.mul(
                    layouter.namespace(|| format!("{}_t2", $label)),
                    &one_minus_bit_limb, $a_limb,
                    &format!("{}_t2", $label),
                )?;
                self.fq.add(
                    layouter.namespace(|| format!("{}_sum", $label)),
                    &t1, &t2,
                    &format!("{}_sum", $label),
                )?
            }};
        }

        let x0 = select_limb!("select_x_0", &a.x.limbs[0], &b.x.limbs[0]);
        let x1 = select_limb!("select_x_1", &a.x.limbs[1], &b.x.limbs[1]);
        let x2 = select_limb!("select_x_2", &a.x.limbs[2], &b.x.limbs[2]);
        let y0 = select_limb!("select_y_0", &a.y.limbs[0], &b.y.limbs[0]);
        let y1 = select_limb!("select_y_1", &a.y.limbs[1], &b.y.limbs[1]);
        let y2 = select_limb!("select_y_2", &a.y.limbs[2], &b.y.limbs[2]);

        Ok(PallasPoint {
            x: FpElement { limbs: [x0, x1, x2] },
            y: FpElement { limbs: [y0, y1, y2] },
            x_cell: None,
            y_cell: None,
        })
    }

    /// Negate a Pallas point: -P = (x, -y mod Fp).
    pub fn point_negate(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &PallasPoint,
    ) -> Result<PallasPoint, ErrorFront> {
        let zero = FpElement::zero();
        let neg_y = self.fp.sub(layouter.namespace(|| "neg_y"), &zero, &p.y)?;

        Ok(PallasPoint {
            x: p.x.clone(),
            y: neg_y,
            x_cell: p.x_cell,
            y_cell: None,
        })
    }

    /// Constrain two PallasPoints to be limb-wise equal (both coordinates).
    pub fn constrain_equal_points(
        &self,
        mut layouter: impl Layouter<Fq>,
        a: &PallasPoint,
        b: &PallasPoint,
    ) -> Result<(), ErrorFront> {
        self.fp.constrain_equal(layouter.namespace(|| "eq_x"), &a.x, &b.x)?;
        self.fp.constrain_equal(layouter.namespace(|| "eq_y"), &a.y, &b.y)
    }

    /// Constrain two FpElements to be limb-wise equal.
    pub fn constrain_equal(
        &self,
        layouter: impl Layouter<Fq>,
        a: &FpElement,
        b: &FpElement,
    ) -> Result<(), ErrorFront> {
        self.fp.constrain_equal(layouter, a, b)
    }

    /// Constrain all 3 limbs of an FpElement to be zero.
    pub fn constrain_zero(
        &self,
        layouter: impl Layouter<Fq>,
        a: &FpElement,
    ) -> Result<(), ErrorFront> {
        let zero_el = FpElement::zero();
        self.constrain_equal(layouter, a, &zero_el)
    }

    // ── Helpers ──

    fn fp_element_from_u64(&self, v: u64) -> FpElement {
        let limb_base_big = num_bigint::BigUint::from_bytes_le(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let val_big = num_bigint::BigUint::from(v);
        let limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = (&val_big / &limb_base_big.pow(i as u32)) % &limb_base_big;
            let mut repr = <Fq as ff::PrimeField>::Repr::default();
            let le = lv.to_bytes_le();
            repr.as_mut()[..le.len()].copy_from_slice(&le);
            Limb {
                value: Value::known(<Fq as ff::PrimeField>::from_repr(repr).unwrap()),
                cell: None,
            }
        });
        FpElement { limbs }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::pasta::Fp,
        plonk::{Circuit, ConstraintSystem},
    };
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
    use halo2curves::CurveAffine;

    use crate::non_native_fp::NonNativeFpConfig;
    use crate::vesta_fq::VestaFqConfig;

    fn big_limb_base() -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_le(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    fn big_to_fq(big: &num_bigint::BigUint) -> Fq {
        let bytes = big.to_bytes_le();
        let mut repr = <Fq as ff::PrimeField>::Repr::default();
        let len = bytes.len().min(repr.as_ref().len());
        repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
        <Fq as ff::PrimeField>::from_repr(repr).unwrap()
    }

    fn ep_to_pallas_point(p: &halo2curves::pasta::EpAffine) -> PallasPoint {
        let coords = p.coordinates().unwrap();
        let x_fp = *coords.x();
        let y_fp = *coords.y();
        let limb_base_big = big_limb_base();
        let x_repr = x_fp.to_repr();
        let x_big = num_bigint::BigUint::from_bytes_le(x_repr.as_ref());
        let y_repr = y_fp.to_repr();
        let y_big = num_bigint::BigUint::from_bytes_le(y_repr.as_ref());
        let lbb = limb_base_big.clone();
        let x_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = (&x_big / &lbb.pow(i as u32)) % &lbb;
            Limb {
                value: Value::known(big_to_fq(&lv)),
                cell: None,
            }
        });
        let y_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = (&y_big / &limb_base_big.pow(i as u32)) % &limb_base_big;
            Limb {
                value: Value::known(big_to_fq(&lv)),
                cell: None,
            }
        });
        PallasPoint {
            x: FpElement { limbs: x_limbs },
            y: FpElement { limbs: y_limbs },
            x_cell: None,
            y_cell: None,
        }
    }

    #[derive(Clone, Debug)]
    struct EccTestConfig {
        fp: NonNativeFpConfig,
        fq: VestaFqConfig,
    }

    impl EccTestConfig {
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
            Self {
                fp: NonNativeFpChip::configure(meta),
                fq: VestaFqConfig::configure(meta),
            }
        }
    }

    fn make_fp_el_from_fp(v: halo2curves::pasta::Fp, limb_base_big: &num_bigint::BigUint) -> FpElement {
        let repr = v.to_repr();
        let big = num_bigint::BigUint::from_bytes_le(repr.as_ref());
        let limbs = array::from_fn(|i| {
            let lv = (&big / &limb_base_big.pow(i as u32)) % limb_base_big.clone();
            Limb {
                value: Value::known(big_to_fq(&lv)),
                cell: None,
            }
        });
        FpElement { limbs }
    }

    // ── On-curve test ──

    #[test]
    fn test_pallas_generator_is_on_curve() {
        #[derive(Default)]
        struct TestOnCurve;

        impl Circuit<Fq> for TestOnCurve {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let fp = NonNativeFpChip::new(config.fp);
                let fq = VestaFqChip::new(config.fq);
                let ecc = PallasEccChip::new(fp, fq);

                let gen = halo2curves::pasta::EpAffine::generator();
                let p = ep_to_pallas_point(&gen);
                ecc.assert_on_curve(layouter.namespace(|| "oc"), &p)?;
                Ok(())
            }
        }

        let circuit = TestOnCurve;
        let prover = MockProver::run(14, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "on_curve test: {:?}", result.err());
    }

    // ── Point add test ──

    #[test]
    fn test_pallas_add_g_plus_g_eq_2g() {
        #[derive(Default)]
        struct TestAdd;

        impl Circuit<Fq> for TestAdd {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let fp = NonNativeFpChip::new(config.fp);
                let fq = VestaFqChip::new(config.fq);
                let ecc = PallasEccChip::new(fp, fq);

                let gen = halo2curves::pasta::EpAffine::generator();
                let p = ep_to_pallas_point(&gen);

                let coords = gen.coordinates().unwrap();
                let px_fp = *coords.x();
                let py_fp = *coords.y();

                let lam_fp = {
                    let num = Fp::from(3) * px_fp.square();
                    let den = Fp::from(2) * py_fp;
                    num * den.invert().unwrap()
                };

                let double_aff = (gen.to_curve() + gen.to_curve()).to_affine();
                let double_coords = double_aff.coordinates().unwrap();

                let limb_base_big = big_limb_base();
                let lam_el = make_fp_el_from_fp(lam_fp, &limb_base_big);
                let rx_el = make_fp_el_from_fp(*double_coords.x(), &limb_base_big);
                let ry_el = make_fp_el_from_fp(*double_coords.y(), &limb_base_big);

                let result = ecc.point_add(
                    layouter.namespace(|| "add"),
                    &p, &p, &lam_el, &rx_el, &ry_el,
                )?;
                ecc.assert_on_curve(layouter.namespace(|| "result_oc"), &result)?;
                Ok(())
            }
        }

        let circuit = TestAdd;
        let prover = MockProver::run(14, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "add G+G: {:?}", result.err());
    }

    // ── Point double test ──

    #[test]
    fn test_pallas_double_g_eq_2g() {
        #[derive(Default)]
        struct TestDouble;

        impl Circuit<Fq> for TestDouble {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let fp = NonNativeFpChip::new(config.fp);
                let fq = VestaFqChip::new(config.fq);
                let ecc = PallasEccChip::new(fp, fq);

                let gen = halo2curves::pasta::EpAffine::generator();
                let p = ep_to_pallas_point(&gen);
                let coords = gen.coordinates().unwrap();
                let px_fp = *coords.x();
                let py_fp = *coords.y();

                let lam_fp = {
                    let num = Fp::from(3) * px_fp.square();
                    let den = Fp::from(2) * py_fp;
                    num * den.invert().unwrap()
                };

                let double_aff = (gen.to_curve() + gen.to_curve()).to_affine();
                let dcoords = double_aff.coordinates().unwrap();

                let limb_base_big = big_limb_base();
                let lam_el = make_fp_el_from_fp(lam_fp, &limb_base_big);
                let rx_el = make_fp_el_from_fp(*dcoords.x(), &limb_base_big);
                let ry_el = make_fp_el_from_fp(*dcoords.y(), &limb_base_big);

                let result = ecc.point_double(
                    layouter.namespace(|| "double"),
                    &p, &lam_el, &rx_el, &ry_el,
                )?;
                ecc.assert_on_curve(layouter.namespace(|| "result_oc"), &result)?;
                Ok(())
            }
        }

        let circuit = TestDouble;
        let prover = MockProver::run(14, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "double G: {:?}", result.err());
    }

    // ── Select test ──

    #[test]
    fn test_pallas_select_bit_0_returns_a() {
        #[derive(Default)]
        struct TestSelect;

        impl Circuit<Fq> for TestSelect {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let fp = NonNativeFpChip::new(config.fp);
                let fq = VestaFqChip::new(config.fq);
                let ecc = PallasEccChip::new(fp, fq);

                let gen = halo2curves::pasta::EpAffine::generator();
                let p = ep_to_pallas_point(&gen);

                let two_el = FpElement {
                    limbs: array::from_fn(|i| Limb {
                        value: Value::known(if i == 0 { Fq::from(2) } else { Fq::ZERO }),
                        cell: None,
                    }),
                };
                let q = PallasPoint { x: two_el.clone(), y: two_el, x_cell: None, y_cell: None };

                let result = ecc.select(layouter.namespace(|| "sel"), Value::known(Fq::ZERO), &p, &q)?;
                ecc.assert_on_curve(layouter.namespace(|| "result_oc"), &result)?;
                Ok(())
            }
        }

        let circuit = TestSelect;
        let prover = MockProver::run(14, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "select bit=0: {:?}", result.err());
    }

    // ── Negate test ──

    #[test]
    fn test_pallas_negate() {
        #[derive(Default)]
        struct TestNegate;

        impl Circuit<Fq> for TestNegate {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self { Self::default() }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(
                &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
            ) -> Result<(), ErrorFront> {
                let fp = NonNativeFpChip::new(config.fp);
                let fq = VestaFqChip::new(config.fq);
                let ecc = PallasEccChip::new(fp.clone(), fq);

                let gen = halo2curves::pasta::EpAffine::generator();
                let p = ep_to_pallas_point(&gen);
                let neg_p = ecc.point_negate(layouter.namespace(|| "neg"), &p)?;

                let y_plus_neg_y = ecc.fp.add(layouter.namespace(|| "y_plus_neg_y"), &p.y, &neg_p.y)?;
                ecc.constrain_zero(layouter.namespace(|| "check_zero"), &y_plus_neg_y)?;
                ecc.fp.constrain_equal(layouter.namespace(|| "x_unchanged"), &p.x, &neg_p.x)?;
                Ok(())
            }
        }

        let circuit = TestNegate;
        let prover = MockProver::run(14, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "negate: {:?}", result.err());
    }
}
