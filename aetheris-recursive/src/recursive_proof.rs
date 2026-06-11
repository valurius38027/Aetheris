//! Recursive proof circuit — wraps PallasAccumulateChip in a Halo2 circuit.
//!
//! Takes host-precomputed intermediate Pallas points and witnesses, assigns
//! commitment + state_root as public inputs, then calls `verify_ipa_pallas`.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};

use crate::non_native_fp::{FpElement, FP_NUM_LIMBS};
use crate::pallas_accumulate::{PallasAccumulateChip, PallasAccumulateConfig};
use crate::pallas_ecc::PallasPoint;

/// Config for the recursive proof circuit.
#[derive(Clone, Debug)]
pub struct RecursiveProofConfig {
    pub acc: PallasAccumulateConfig,
    /// Advice column for assigning public-input limb values.
    pub adv: Column<Advice>,
    /// Instance column — commitment coordinates (6 Fq limbs) + state_root (1 Fq).
    pub instance: Column<Instance>,
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
    /// 32-byte state root bound as public instance.
    pub state_root: [u8; 32],
}

impl Default for RecursiveProofCircuit {
    fn default() -> Self {
        let zero = FpElement::zero();
        let zero_point = PallasPoint {
            x: zero.clone(), y: zero.clone(),
            x_cell: None, y_cell: None,
        };
        Self {
            commitment: zero_point.clone(),
            l_scaled: vec![zero_point.clone()],
            r_scaled: vec![zero_point.clone()],
            a_mul_gfinal: zero_point.clone(),
            r_prime_mul_h: zero_point.clone(),
            ab_eval_mul_u: zero_point.clone(),
            lhs_witnesses: vec![
                (zero.clone(), zero.clone(), zero.clone()),
                (zero.clone(), zero.clone(), zero.clone()),
            ],
            rhs_witnesses: vec![
                (zero.clone(), zero.clone(), zero.clone()),
                (zero.clone(), zero.clone(), zero.clone()),
            ],
            state_root: [0u8; 32],
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
        let adv = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(adv);
        meta.enable_equality(instance);
        RecursiveProofConfig {
            acc: PallasAccumulateConfig::configure(meta),
            adv,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let num_limbs = FP_NUM_LIMBS;
        let num_commit_cells = 2 * num_limbs;

        // Assign commitment coordinate limbs as public instance inputs.
        let cells = layouter.assign_region(|| "pub_commitment", |mut region| {
            let mut cells = Vec::with_capacity(num_commit_cells + 1);
            for (i, limb) in self.commitment.x.limbs.iter().enumerate() {
                let cell = region.assign_advice(
                    || format!("com_x_{}", i), config.adv, i, || limb.value,
                )?;
                cells.push(cell.cell());
            }
            for (i, limb) in self.commitment.y.limbs.iter().enumerate() {
                let cell = region.assign_advice(
                    || format!("com_y_{}", i), config.adv, num_limbs + i, || limb.value,
                )?;
                cells.push(cell.cell());
            }

            // Assign state_root as 7th instance cell.
            let mut repr = <Fq as ff::PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&self.state_root);
            let sr_fq = <Fq as ff::PrimeField>::from_repr(repr).unwrap();
            let sr_cell = region.assign_advice(
                || "state_root",
                config.adv,
                num_commit_cells,
                || Value::known(sr_fq),
            )?;
            cells.push(sr_cell.cell());

            Ok(cells)
        })?;
        for (row, cell) in cells.iter().enumerate() {
            layouter.constrain_instance(*cell, config.instance, row)?;
        }

        // Verify the IPA proof.
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

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallas_accumulate::{commitment_limbs, ep_to_pallas_point, fp_add_witness};
    use ff::{Field, PrimeField};
    use halo2_proofs::halo2curves::pasta::EpAffine;
    use halo2_proofs::dev::MockProver;
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;

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

        let mut pub_limbs = commitment_limbs(&p_com);
        // state_root must be < Fq modulus; use a small value.
        let sr_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0xab;
            b
        };
        let sr_fq = {
            let mut repr = <Fq as PrimeField>::Repr::default();
            repr.as_mut()[..1].copy_from_slice(&sr_bytes[..1]);
            <Fq as PrimeField>::from_repr(repr).unwrap()
        };
        pub_limbs.push(sr_fq);
        let circuit = RecursiveProofCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_witnesses: vec![wit_lr, wit_accum],
            rhs_witnesses: vec![wit_gh, wit_u],
            state_root: sr_bytes,
        };

        let prover = MockProver::run(16, &circuit, vec![pub_limbs]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "recursive proof k=1: {:?}", result.err());
    }

    #[test]
    fn test_recursive_proof_rejects_wrong_commitment() {
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

        let mut wrong_limbs = commitment_limbs(&p_com);
        wrong_limbs[0] += Fq::ONE;
        // state_root must be < Fq modulus.
        let sr_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0xab;
            b
        };
        let sr_fq = {
            let mut repr = <Fq as PrimeField>::Repr::default();
            repr.as_mut()[..1].copy_from_slice(&sr_bytes[..1]);
            <Fq as PrimeField>::from_repr(repr).unwrap()
        };
        wrong_limbs.push(sr_fq);
        let circuit = RecursiveProofCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_witnesses: vec![wit_lr, wit_accum],
            rhs_witnesses: vec![wit_gh, wit_u],
            state_root: sr_bytes,
        };

        let prover = MockProver::run(16, &circuit, vec![wrong_limbs]).unwrap();
        let result = prover.verify();
        assert!(result.is_err(), "wrong public input should be rejected");
    }
}
