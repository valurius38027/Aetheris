//! Recursive proof circuit — wraps PallasAccumulateChip in a Halo2 circuit.
//!
//! Takes host-precomputed intermediate Pallas points and witnesses, assigns
//! commitment + eval as public inputs, then calls `verify_ipa_pallas`.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::pasta::Fq,
    plonk::{Circuit, ConstraintSystem, ErrorFront},
};

use crate::non_native_fp::FpElement;
use crate::pallas_accumulate::{PallasAccumulateChip, PallasAccumulateConfig};
use crate::pallas_ecc::PallasPoint;

/// Config for the recursive proof circuit.
#[derive(Clone, Debug)]
pub struct RecursiveProofConfig {
    pub acc: PallasAccumulateConfig,
}

/// Recursive proof circuit that verifies an inner IPA proof.
pub struct RecursiveProofCircuit {
    pub commitment: PallasPoint,
    pub l_scaled: Vec<PallasPoint>,
    pub r_scaled: Vec<PallasPoint>,
    pub a_mul_gfinal: PallasPoint,
    pub r_prime_mul_h: PallasPoint,
    pub ab_eval_mul_u: PallasPoint,
    pub lhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
    pub rhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
}

impl Default for RecursiveProofCircuit {
    fn default() -> Self {
        let zero = FpElement::zero();
        Self {
            commitment: PallasPoint {
                x: zero.clone(), y: zero.clone(),
                x_cell: None, y_cell: None,
            },
            l_scaled: vec![], r_scaled: vec![],
            a_mul_gfinal: PallasPoint {
                x: zero.clone(), y: zero.clone(),
                x_cell: None, y_cell: None,
            },
            r_prime_mul_h: PallasPoint {
                x: zero.clone(), y: zero.clone(),
                x_cell: None, y_cell: None,
            },
            ab_eval_mul_u: PallasPoint {
                x: FpElement::zero(), y: FpElement::zero(),
                x_cell: None, y_cell: None,
            },
            lhs_witnesses: vec![],
            rhs_witnesses: vec![],
        }
    }
}

impl Circuit<Fq> for RecursiveProofCircuit {
    type Config = RecursiveProofConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        RecursiveProofConfig {
            acc: PallasAccumulateConfig::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let acc = PallasAccumulateChip::new(&config.acc);
        acc.verify_ipa_pallas(
            layouter.namespace(|| "verify"),
            &self.commitment,
            &self.l_scaled,
            &self.r_scaled,
            &self.a_mul_gfinal,
            &self.r_prime_mul_h,
            &self.ab_eval_mul_u,
            &self.lhs_witnesses,
            &self.rhs_witnesses,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;

    use ff::{Field, PrimeField};
    use halo2_proofs::halo2curves::pasta::{EpAffine, Fp};
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
    };
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
    use halo2curves::CurveAffine;

    use crate::{Limb, non_native_fp::FP_NUM_LIMBS};

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
            x_cell: None, y_cell: None,
        }
    }

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

    #[test]
    fn test_recursive_proof_k1_valid() {
        let g = EpAffine::generator();
        let h = (g.to_curve() * Fq::from(2u64)).to_affine();
        let u = (g.to_curve() * Fq::from(3u64)).to_affine();
        let g_final = g;

        let a_mul_g = (g_final.to_curve() * Fq::from(11u64)).to_affine();
        let r_prime_mul_h = (h.to_curve() * Fq::from(13u64)).to_affine();
        let ab_eval_mul_u = (u.to_curve() * Fq::from(17u64)).to_affine();
        let rhs = (a_mul_g.to_curve() + r_prime_mul_h.to_curve() + ab_eval_mul_u.to_curve()).to_affine();

        let l_scaled = (g_final.to_curve() * Fq::from(2u64)).to_affine();
        let r_scaled = (h.to_curve() * Fq::from(3u64)).to_affine();
        let commitment = (rhs.to_curve() - l_scaled.to_curve() - r_scaled.to_curve()).to_affine();

        let p_com = ep_to_pallas_point(&commitment);
        let p_l = ep_to_pallas_point(&l_scaled);
        let p_r = ep_to_pallas_point(&r_scaled);
        let p_a = ep_to_pallas_point(&a_mul_g);
        let p_rh = ep_to_pallas_point(&r_prime_mul_h);
        let p_ab = ep_to_pallas_point(&ab_eval_mul_u);

        let sum_lr = (l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        let p_sum_lr = ep_to_pallas_point(&sum_lr);
        let wit_lr = fp_add_witness(&p_l, &p_r);
        let wit_accum = fp_add_witness(&p_com, &p_sum_lr);

        let rhs_gh = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
        let p_rhs_gh = ep_to_pallas_point(&rhs_gh);
        let wit_gh = fp_add_witness(&p_a, &p_rh);
        let wit_u = fp_add_witness(&p_rhs_gh, &p_ab);

        let circuit = RecursiveProofCircuit {
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
        assert!(result.is_ok(), "recursive proof k=1: {:?}", result.err());
    }
}
