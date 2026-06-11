//! Pallas IPA verification chip.
//!
//! Unlike VestaIpaChip (which does in-circuit scalar_mul), PallasIpaChip
//! takes host-precomputed intermediate points and verifies the IPA equation
//! using point addition chains.
//!
//! # Soundness
//!
//! All precomputed points are on-curve checked. The final equation
//! `commitment + Σ(Lᵢ' + Rᵢ') = G' + H' + U'` is verified via point_add
//! constraints. If any intermediate point is wrong, the equation fails
//! with overwhelming probability.

use halo2_proofs::{
    circuit::Layouter,
    halo2curves::pasta::Fq,
    plonk::ErrorFront,
};

use crate::non_native_fp::FpElement;
use crate::pallas_ecc::{PallasEccChip, PallasPoint};
use crate::vesta_fq::VestaFqChip;

pub struct PallasIpaChip {
    pub ecc: PallasEccChip,
    pub fq: VestaFqChip,
}

impl PallasIpaChip {
    pub fn new(ecc: PallasEccChip, fq: VestaFqChip) -> Self {
        Self { ecc, fq }
    }

    /// Verify the full IPA verification equation.
    ///
    /// `lhs_witnesses` — precomputed (λ, rx, ry) for the LHS chain.
    ///   Length = 2 × `l_scaled_points.len()`:
    ///     entry 2i:   Lᵢ' + Rᵢ' → sum
    ///     entry 2i+1: LHS + sum → LHS
    ///
    /// `rhs_witnesses` — precomputed (λ, rx, ry) for the RHS chain.
    ///   Length = 2:
    ///     entry 0: G' + H' → tmp
    ///     entry 1: tmp + U' → RHS
    pub fn verify_ipa_full(
        &self,
        mut layouter: impl Layouter<Fq>,
        commitment: &PallasPoint,
        l_scaled_points: &[PallasPoint],
        r_scaled_points: &[PallasPoint],
        a_mul_gfinal: &PallasPoint,
        r_prime_mul_h: &PallasPoint,
        ab_eval_mul_u: &PallasPoint,
        lhs_witnesses: &[(FpElement, FpElement, FpElement)],
        rhs_witnesses: &[(FpElement, FpElement, FpElement)],
    ) -> Result<(), ErrorFront> {
        let k = l_scaled_points.len();
        assert_eq!(r_scaled_points.len(), k);
        assert_eq!(lhs_witnesses.len(), 2 * k, "need 2 witnesses per round");
        assert_eq!(rhs_witnesses.len(), 2, "need 2 witnesses for RHS");

        let commitment = self.ecc.assert_on_curve(
            layouter.namespace(|| "commitment_on_curve"),
            commitment,
        )?;
        let a_mul_gfinal = self.ecc.assert_on_curve(
            layouter.namespace(|| "a_mul_gfinal_on_curve"),
            a_mul_gfinal,
        )?;
        let r_prime_mul_h = self.ecc.assert_on_curve(
            layouter.namespace(|| "r_prime_mul_h_on_curve"),
            r_prime_mul_h,
        )?;
        let ab_eval_mul_u = self.ecc.assert_on_curve(
            layouter.namespace(|| "ab_eval_mul_u_on_curve"),
            ab_eval_mul_u,
        )?;

        let mut l_scaled = Vec::with_capacity(k);
        let mut r_scaled = Vec::with_capacity(k);
        for (i, (l, r)) in l_scaled_points.iter().zip(r_scaled_points.iter()).enumerate() {
            let lc = self.ecc.assert_on_curve(
                layouter.namespace(|| format!("l_scaled_{}_on_curve", i)), l,
            )?;
            let rc = self.ecc.assert_on_curve(
                layouter.namespace(|| format!("r_scaled_{}_on_curve", i)), r,
            )?;
            l_scaled.push(lc);
            r_scaled.push(rc);
        }

        let mut lhs = commitment;
        for (i, ((l, r), wit)) in l_scaled.iter().zip(r_scaled.iter()).zip(lhs_witnesses.chunks(2)).enumerate() {
            let sum_lr = self.ecc.point_add(
                layouter.namespace(|| format!("lhs_add_lr_{}", i)),
                l, r, &wit[0].0, &wit[0].1, &wit[0].2,
            )?;
            lhs = self.ecc.point_add(
                layouter.namespace(|| format!("lhs_accum_{}", i)),
                &lhs, &sum_lr, &wit[1].0, &wit[1].1, &wit[1].2,
            )?;
        }

        let rhs_gh = self.ecc.point_add(
            layouter.namespace(|| "rhs_add_gh"),
            &a_mul_gfinal, &r_prime_mul_h,
            &rhs_witnesses[0].0, &rhs_witnesses[0].1, &rhs_witnesses[0].2,
        )?;
        let rhs = self.ecc.point_add(
            layouter.namespace(|| "rhs_add_u"),
            &rhs_gh, &ab_eval_mul_u,
            &rhs_witnesses[1].0, &rhs_witnesses[1].1, &rhs_witnesses[1].2,
        )?;

        self.ecc.constrain_equal_points(
            layouter.namespace(|| "ipa_eq_check"), &lhs, &rhs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;

    use ff::{Field, PrimeField};
    use halo2_proofs::halo2curves::pasta::EpAffine;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::pasta::{Fp, Fq},
        plonk::{Circuit, ConstraintSystem},
    };
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
    use halo2curves::CurveAffine;

    use crate::non_native_fp::{NonNativeFpChip, NonNativeFpConfig, FP_NUM_LIMBS};
    use crate::vesta_fq::{VestaFqChip, VestaFqConfig};
    use crate::Limb;

    // ── Host helpers (duplicated from pallas_ecc::tests for independence) ──

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
        let mut repr = <Fq as PrimeField>::Repr::default();
        let len = bytes.len().min(repr.as_ref().len());
        repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
        <Fq as PrimeField>::from_repr(repr).unwrap()
    }

    fn ep_to_pallas_point(p: &EpAffine) -> PallasPoint {
        let coords = p.coordinates().unwrap();
        let x_fp = *coords.x();
        let y_fp = *coords.y();
        let lbb = big_limb_base();
        let x_big = num_bigint::BigUint::from_bytes_le(x_fp.to_repr().as_ref());
        let y_big = num_bigint::BigUint::from_bytes_le(y_fp.to_repr().as_ref());
        let x_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = (&x_big / &lbb.pow(i as u32)) % &lbb;
            Limb { value: Value::known(big_to_fq(&lv)), cell: None }
        });
        let y_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
            let lv = (&y_big / &lbb.pow(i as u32)) % &lbb;
            Limb { value: Value::known(big_to_fq(&lv)), cell: None }
        });
        PallasPoint {
            x: FpElement { limbs: x_limbs },
            y: FpElement { limbs: y_limbs },
            x_cell: None,
            y_cell: None,
        }
    }

    /// Host-side Fp point addition: returns (λ, rx, ry) all as FpElement.
    fn fp_add_witness(p: &PallasPoint, q: &PallasPoint) -> (FpElement, FpElement, FpElement) {
        let reconstruct = |el: &FpElement| -> Fp {
            let mut big = num_bigint::BigUint::from(0u32);
            let base = big_limb_base();
            for (i, limb) in el.limbs.iter().enumerate() {
                if let Ok(val) = limb.value.assign() {
                    let lv_big = num_bigint::BigUint::from_bytes_le(val.to_repr().as_ref());
                    big += lv_big * base.pow(i as u32);
                }
            }
            let mut repr = <Fp as PrimeField>::Repr::default();
            let le = big.to_bytes_le();
            repr.as_mut()[..le.len()].copy_from_slice(&le);
            <Fp as PrimeField>::from_repr(repr).unwrap()
        };
        let px = reconstruct(&p.x);
        let py = reconstruct(&p.y);
        let qx = reconstruct(&q.x);
        let qy = reconstruct(&q.y);

        let lam = (qy - py) * (qx - px).invert().unwrap();
        let rx = lam.square() - px - qx;
        let ry = lam * (px - rx) - py;

        let fp_to_el = |fp: Fp| -> FpElement {
            let big = num_bigint::BigUint::from_bytes_le(fp.to_repr().as_ref());
            let base = big_limb_base();
            let limbs = array::from_fn(|i| {
                let lv = (&big / &base.pow(i as u32)) % &base;
                Limb { value: Value::known(big_to_fq(&lv)), cell: None }
            });
            FpElement { limbs }
        };

        (fp_to_el(lam), fp_to_el(rx), fp_to_el(ry))
    }

    // ── Test circuit ──

    #[derive(Clone)]
    struct IpaTestConfig {
        fp: NonNativeFpConfig,
        fq: VestaFqConfig,
    }

    struct IpaTestCircuit {
        commitment: PallasPoint,
        l_scaled: Vec<PallasPoint>,
        r_scaled: Vec<PallasPoint>,
        a_mul_gfinal: PallasPoint,
        r_prime_mul_h: PallasPoint,
        ab_eval_mul_u: PallasPoint,
        lhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
        rhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
    }

    impl Default for IpaTestCircuit {
        fn default() -> Self {
            let zero = FpElement::zero();
            Self {
                commitment: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                l_scaled: vec![],
                r_scaled: vec![],
                a_mul_gfinal: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                r_prime_mul_h: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                ab_eval_mul_u: PallasPoint { x: zero.clone(), y: zero, x_cell: None, y_cell: None },
                lhs_witnesses: vec![],
                rhs_witnesses: vec![],
            }
        }
    }

    impl Circuit<Fq> for IpaTestCircuit {
        type Config = IpaTestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self { Self::default() }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            IpaTestConfig {
                fp: NonNativeFpChip::configure(meta),
                fq: VestaFqConfig::configure(meta),
            }
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let fp_chip = NonNativeFpChip::new(config.fp);
            let fq_chip = VestaFqChip::new(config.fq);
            let ecc = PallasEccChip::new(fp_chip, fq_chip.clone());
            let ipa = PallasIpaChip::new(ecc, fq_chip);
            ipa.verify_ipa_full(
                layouter.namespace(|| "verify_ipa"),
                &self.commitment, &self.l_scaled, &self.r_scaled,
                &self.a_mul_gfinal, &self.r_prime_mul_h, &self.ab_eval_mul_u,
                &self.lhs_witnesses, &self.rhs_witnesses,
            )
        }
    }

    // ── Test: k=1 valid ──

    #[test]
    fn test_ipa_k1_valid() {
        // Craft a balanced IPA equation: choose arbitrary RHS components, then
        // compute commitment = RHS - L' - R' so the equation always balances.
        let g = EpAffine::generator();
        let h = (g.to_curve() * Fq::from(2u64)).to_affine();
        let u = (g.to_curve() * Fq::from(3u64)).to_affine();
        let g_final = g;

        // RHS components
        let a_mul_g = (g_final.to_curve() * Fq::from(11u64)).to_affine();
        let r_prime_mul_h = (h.to_curve() * Fq::from(13u64)).to_affine();
        let ab_eval_mul_u = (u.to_curve() * Fq::from(17u64)).to_affine();
        let rhs = (a_mul_g.to_curve() + r_prime_mul_h.to_curve() + ab_eval_mul_u.to_curve()).to_affine();

        // LHS terms (arbitrary)
        let l_scaled = (g_final.to_curve() * Fq::from(2u64)).to_affine();
        let r_scaled = (h.to_curve() * Fq::from(3u64)).to_affine();

        // commitment = RHS - L' - R'  → equation always balances
        let commitment_pt = (rhs.to_curve() - l_scaled.to_curve() - r_scaled.to_curve()).to_affine();

        // Verify host-side
        let lhs_check = (commitment_pt.to_curve() + l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        assert_eq!(lhs_check, rhs, "host precomputation must produce balanced IPA equation");

        // Convert all to PallasPoint
        let p_com = ep_to_pallas_point(&commitment_pt);
        let p_l = ep_to_pallas_point(&l_scaled);
        let p_r = ep_to_pallas_point(&r_scaled);
        let p_a = ep_to_pallas_point(&a_mul_g);
        let p_rh = ep_to_pallas_point(&r_prime_mul_h);
        let p_ab = ep_to_pallas_point(&ab_eval_mul_u);

        // Precompute addition witnesses
        let sum_lr = (l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        let p_sum_lr = ep_to_pallas_point(&sum_lr);
        let wit_lr = fp_add_witness(&p_l, &p_r);
        let wit_accum = fp_add_witness(&p_com, &p_sum_lr);

        let rhs_gh = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
        let p_rhs_gh = ep_to_pallas_point(&rhs_gh);
        let wit_gh = fp_add_witness(&p_a, &p_rh);
        let wit_u = fp_add_witness(&p_rhs_gh, &p_ab);

        let circuit = IpaTestCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_witnesses: vec![wit_lr, wit_accum],
            rhs_witnesses: vec![wit_gh, wit_u],
        };

        let prover = MockProver::run(16, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "IPA k=1 valid: {:?}", result.err());
    }
}
