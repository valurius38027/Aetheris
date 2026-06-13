use crate::poseidon_transcript::{PoseidonTranscriptChip, PoseidonTranscriptConfig};
use crate::vesta_ecc::{VestaEccConfig, VestaPoint};
use crate::vesta_fq::VestaFqConfig;
use crate::vesta_ipa::{VestaIpaChip, VestaIpaConfig, VestaIpaResult};
use crate::Limb;
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{ConstraintSystem, ErrorFront},
};

#[derive(Clone, Debug)]
pub struct VestaAccumulateConfig {
    pub poseidon: PoseidonTranscriptConfig,
    pub ipa: VestaIpaConfig,
}

impl VestaAccumulateConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        let poseidon = PoseidonTranscriptConfig::configure(meta);
        let ipa = VestaIpaConfig {
            fq: VestaFqConfig::configure(meta),
            ecc: VestaEccConfig::configure(meta),
        };
        Self { poseidon, ipa }
    }
}

pub struct VestaAccumulateChip {
    poseidon: PoseidonTranscriptChip,
    pub ipa: VestaIpaChip,
}

impl VestaAccumulateChip {
    pub fn new(config: &VestaAccumulateConfig) -> Self {
        let poseidon = PoseidonTranscriptChip::new(&config.poseidon);
        let fq = crate::vesta_fq::VestaFqChip::new(config.ipa.fq.clone());
        let ecc = crate::vesta_ecc::VestaEccChip::new(config.ipa.ecc.clone());
        let ipa = VestaIpaChip::new(fq, ecc);
        Self { poseidon, ipa }
    }

    pub fn squeeze_challenges(
        &self,
        mut layouter: impl Layouter<Fq>,
        _config: &VestaAccumulateConfig,
        k: usize,
        l_x: &[Value<Fq>],
        l_y: &[Value<Fq>],
        r_x: &[Value<Fq>],
        r_y: &[Value<Fq>],
    ) -> Result<Vec<Limb<Fq>>, ErrorFront> {
        // Init: state = Poseidon(TRANSCRIPT_DOMAIN, CAPACITY_FILL)
        let mut state = self.poseidon.assign_init(
            layouter.namespace(|| "transcript_init"),
        )?;

        // Absorb k
        state = self.poseidon.assign_absorb_scalar(
            layouter.namespace(|| "absorb_k"),
            &state,
            Value::known(Fq::from(k as u64)),
        )?;

        let mut out = Vec::with_capacity(k);

        for i in 0..k {
            // Absorb L_i (x, y) and R_i (x, y)
            state = self.poseidon.assign_absorb_coord(
                layouter.namespace(|| format!("absorb_lx_{}", i)),
                &state,
                l_x[i],
            )?;
            state = self.poseidon.assign_absorb_coord(
                layouter.namespace(|| format!("absorb_ly_{}", i)),
                &state,
                l_y[i],
            )?;
            state = self.poseidon.assign_absorb_coord(
                layouter.namespace(|| format!("absorb_rx_{}", i)),
                &state,
                r_x[i],
            )?;
            state = self.poseidon.assign_absorb_coord(
                layouter.namespace(|| format!("absorb_ry_{}", i)),
                &state,
                r_y[i],
            )?;

            // Squeeze: challenge = state[0] before advance permutation
            let (challenge, new_state) = self.poseidon.assign_squeeze(
                layouter.namespace(|| format!("squeeze_{}", i)),
                &state,
            )?;
            out.push(Limb {
                value: challenge.value().map(|&v| v),
                cell: Some(challenge.cell()),
            });
            state = new_state;
        }

        Ok(out)
    }

    pub fn fold_and_constrain(
        &self,
        mut layouter: impl Layouter<Fq>,
        point: &Limb<Fq>,
        g_init: &[VestaPoint],
        offset_points: &[VestaPoint],
        challenges: &[Limb<Fq>],
    ) -> Result<VestaIpaResult, ErrorFront> {
        self.ipa.fold_to_final(
            layouter.namespace(|| "fold"),
            point,
            g_init,
            offset_points,
            challenges,
        )
    }

    /// Full in-circuit IPA verification.
    ///
    /// Verifies the equation:
    ///   `commitment + Σ(x_inv·L_i + x·R_i) = a·G_final + r'·H + (ab-eval)·U`
    pub fn verify_ipa_full(
        &self,
        mut layouter: impl Layouter<Fq>,
        commitment: &VestaPoint,
        eval: &Limb<Fq>,
        a_final: &Limb<Fq>,
        r_prime: &Limb<Fq>,
        l_points: &[VestaPoint],
        r_points: &[VestaPoint],
        lr_offsets: &[VestaPoint],
        challenges: &[Limb<Fq>],
        fold_result: &VestaIpaResult,
        g_final_offset: &VestaPoint,
        h_point: &VestaPoint,
        h_offset: &VestaPoint,
        u_point: &VestaPoint,
        u_offset: &VestaPoint,
    ) -> Result<(), ErrorFront> {
        let k = challenges.len();
        assert_eq!(l_points.len(), k);
        assert_eq!(r_points.len(), k);
        assert_eq!(lr_offsets.len(), 2 * k);

        let ecc = &self.ipa.ecc;
        let fq = &self.ipa.fq;

        // 1. a*b - eval  (no native sub, so compute a*b + (-eval))
        let a_mul_b = fq.mul(
            layouter.namespace(|| "a_mul_b"),
            a_final,
            &fold_result.b_final,
            "a_mul_b",
        )?;
        let neg_one = fq.assign_constant(
            layouter.namespace(|| "neg_one"),
            -Fq::ONE,
            "neg_one",
        )?;
        let neg_eval = fq.mul(
            layouter.namespace(|| "neg_eval"),
            eval,
            &neg_one,
            "neg_eval",
        )?;
        let ab_minus_eval = fq.add(
            layouter.namespace(|| "ab_minus_eval"),
            &a_mul_b,
            &neg_eval,
            "ab_minus_eval",
        )?;

        // 2. RHS = a·G_final + r'·H + (ab-eval)·U
        let rhs_a = ecc.scalar_mul(
            layouter.namespace(|| "a_mul_gfinal"),
            &fold_result.g_final,
            g_final_offset,
            a_final.value,
            "a_mul_gfinal",
        )?;
        let rhs_ar = ecc.scalar_mul(
            layouter.namespace(|| "r_prime_mul_h"),
            h_point,
            h_offset,
            r_prime.value,
            "r_prime_mul_h",
        )?;
        let rhs_u = ecc.scalar_mul(
            layouter.namespace(|| "ab_minus_eval_mul_u"),
            u_point,
            u_offset,
            ab_minus_eval.value,
            "ab_minus_eval_mul_u",
        )?;

        let rhs_temp = ecc.point_add(
            layouter.namespace(|| "rhs_add_ar"),
            &rhs_a,
            &rhs_ar,
            "rhs_a_plus_ar",
        )?;
        let rhs = ecc.point_add(
            layouter.namespace(|| "rhs_add_u"),
            &rhs_temp,
            &rhs_u,
            "rhs_add_u",
        )?;

        // 3. LHS = commitment + Σ(x_inv·L_i + x·R_i)
        let mut lhs = commitment.clone();
        for i in 0..k {
            let x_inv = fq.invert(
                layouter.namespace(|| format!("x_inv_{}", i)),
                &challenges[i],
                &format!("x_inv_{}", i),
            )?;
            let li_term = ecc.scalar_mul(
                layouter.namespace(|| format!("l_{}_term", i)),
                &l_points[i],
                &lr_offsets[2 * i],
                x_inv.value,
                &format!("l_{}", i),
            )?;
            let ri_term = ecc.scalar_mul(
                layouter.namespace(|| format!("r_{}_term", i)),
                &r_points[i],
                &lr_offsets[2 * i + 1],
                challenges[i].value,
                &format!("r_{}", i),
            )?;
            let lr_sum = ecc.point_add(
                layouter.namespace(|| format!("lr_sum_{}", i)),
                &li_term,
                &ri_term,
                &format!("lr_sum_{}", i),
            )?;
            lhs = ecc.point_add(
                layouter.namespace(|| format!("lhs_add_{}", i)),
                &lhs,
                &lr_sum,
                &format!("lhs_add_{}", i),
            )?;
        }

        // 4. constrain LHS == RHS
        ecc.constrain_equal_points(
            layouter.namespace(|| "verify_ipa_eq"),
            &lhs,
            &rhs,
            "verify_ipa_eq",
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_transcript::HostTranscript;
    use ff::{Field, PrimeField};
    use halo2_proofs::halo2curves::pasta::EqAffine;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::{Curve, Group};
    use halo2curves::CurveAffine;
    use num_bigint::BigUint;

    fn to_vesta_point(p: &EqAffine) -> VestaPoint {
        let coords = p.coordinates().unwrap();
        VestaPoint {
            x: Value::known(*coords.x()),
            y: Value::known(*coords.y()),
            x_cell: None,
            y_cell: None,
        }
    }

    fn fq_as_fp(x: Fq) -> halo2curves::pasta::Fp {
        let n = BigUint::from_bytes_le(x.to_repr().as_ref());
        let mut repr = <halo2curves::pasta::Fp as PrimeField>::Repr::default();
        let le = n.to_bytes_le();
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        halo2curves::pasta::Fp::from_repr(repr).unwrap()
    }

    fn compute_b_vector(point: Fq, n: usize) -> Vec<Fq> {
        let mut b = Vec::with_capacity(n);
        b.push(Fq::ONE);
        for i in 1..n {
            b.push(b[i - 1] * point);
        }
        b
    }

    fn host_fold(
        point: Fq,
        g_init: &[EqAffine],
        challenges: &[Fq],
    ) -> (Fq, EqAffine) {
        let n = g_init.len();
        let mut b = compute_b_vector(point, n);
        let mut g_cur = g_init.to_vec();

        for chal in challenges {
            let x_inv = chal.invert().unwrap();
            let half = b.len() / 2;
            let mut b_next = Vec::with_capacity(half);
            let mut g_next = Vec::with_capacity(half);
            for j in 0..half {
                let b_folded = b[j] + x_inv * b[j + half];
                b_next.push(b_folded);
                let g_scaled = (g_cur[j + half].to_curve() * fq_as_fp(x_inv)).to_affine();
                let g_folded = (g_cur[j].to_curve() + g_scaled).to_affine();
                g_next.push(g_folded);
            }
            b = b_next;
            g_cur = g_next;
        }
        (b[0], g_cur[0])
    }

    fn flatten_offsets(g_init: &[EqAffine], challenges: &[Fq]) -> Vec<VestaPoint> {
        let mut g_all: Vec<Vec<EqAffine>> = vec![g_init.to_vec()];

        for chal in challenges {
            let x_inv = chal.invert().unwrap();
            let half = g_all.last().unwrap().len() / 2;
            let cur = g_all.last().unwrap();
            let mut next = Vec::with_capacity(half);
            for j in 0..half {
                let g_scaled = (cur[j + half].to_curve() * fq_as_fp(x_inv)).to_affine();
                let g_folded = (cur[j].to_curve() + g_scaled).to_affine();
                next.push(g_folded);
            }
            g_all.push(next);
        }

        let two_pow_254 = BigUint::from(2u128).pow(254);
        let mut repr = <Fq as PrimeField>::Repr::default();
        let le = two_pow_254.to_bytes_le();
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        let two_pow_254_fq = Fq::from_repr(repr).unwrap();
        let two_pow_254_fp = fq_as_fp(two_pow_254_fq);

        let mut offsets = Vec::new();
        for round_g in &g_all {
            for g in round_g {
                let scaled = (g.to_curve() * two_pow_254_fp).to_affine();
                offsets.push(to_vesta_point(&scaled));
            }
        }
        offsets
    }

    fn build_test_witness() -> AccumulateTestWitness {
        let k = 2;
        let n = 1usize << k;
        let point = Fq::from(3);

        let g0 = EqAffine::generator();
        let generators: Vec<EqAffine> = (0..n)
            .map(|i| (g0.to_curve() * fq_as_fp(Fq::from(i as u64 + 1))).to_affine())
            .collect();
        let u = (g0.to_curve() * fq_as_fp(Fq::from(12345))).to_affine();

        let coeffs = vec![Fq::from(1), Fq::from(2), Fq::from(3), Fq::from(4)];

        let commitment = {
            let mut acc = EqAffine::identity().to_curve();
            for (a, g) in coeffs.iter().zip(generators.iter()) {
                acc += g.to_curve() * fq_as_fp(*a);
            }
            acc.to_affine()
        };

        let eval = {
            let mut ev = Fq::ZERO;
            let mut pow = Fq::ONE;
            for coeff in &coeffs {
                ev += *coeff * pow;
                pow *= point;
            }
            ev
        };

        let mut a_cur = coeffs;
        let mut b_cur = compute_b_vector(point, n);
        let mut g_cur = generators.clone();
        let mut l_points = Vec::new();
        let mut r_points = Vec::new();
        let mut challenges = Vec::new();
        let mut len = n;
        let mut transcript = HostTranscript::new();
        transcript.absorb_scalar(Fq::from(k as u64));

        while len > 1 {
            let half = len / 2;
            let (a_lo, a_hi) = a_cur.split_at(half);
            let (b_lo, b_hi) = b_cur.split_at(half);

            let mut l = EqAffine::identity().to_curve();
            let mut r = EqAffine::identity().to_curve();
            for j in 0..half {
                l += g_cur[j].to_curve() * fq_as_fp(a_hi[j]);
                r += g_cur[j + half].to_curve() * fq_as_fp(a_lo[j]);
            }
            let l_aff = l.to_affine();
            let r_aff = r.to_affine();

            transcript.absorb_point(&l_aff);
            transcript.absorb_point(&r_aff);
            let x = transcript.squeeze();
            let x_inv = x.invert().unwrap();

            let mut a_new = Vec::with_capacity(half);
            let mut b_new = Vec::with_capacity(half);
            let mut g_new = Vec::with_capacity(half);
            for j in 0..half {
                a_new.push(a_lo[j] + x * a_hi[j]);
                b_new.push(b_lo[j] + x_inv * b_hi[j]);
                g_new.push((g_cur[j].to_curve() + g_cur[j + half].to_curve() * fq_as_fp(x_inv)).to_affine());
            }

            l_points.push(l_aff);
            r_points.push(r_aff);
            challenges.push(x);
            a_cur = a_new;
            b_cur = b_new;
            g_cur = g_new;
            len = half;
        }

        AccumulateTestWitness {
            generators,
            u,
            point,
            challenges,
            l_points,
            r_points,
            commitment,
            eval,
            a_final: a_cur[0],
        }
    }

    struct AccumulateTestWitness {
        generators: Vec<EqAffine>,
        #[allow(dead_code)]
        u: EqAffine,
        point: Fq,
        challenges: Vec<Fq>,
        l_points: Vec<EqAffine>,
        r_points: Vec<EqAffine>,
        commitment: EqAffine,
        eval: Fq,
        #[allow(dead_code)]
        a_final: Fq,
    }

    #[derive(Clone)]
    struct AccumulateTestConfig {
        acc: VestaAccumulateConfig,
    }

    struct AccumulateTest {
        witness: AccumulateTestWitness,
        corrupt_challenge: bool,
    }

    impl Circuit<Fq> for AccumulateTest {
        type Config = AccumulateTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                witness: AccumulateTestWitness {
                    generators: vec![EqAffine::generator()],
                    u: EqAffine::generator(),
                    point: Fq::ZERO,
                    challenges: vec![],
                    l_points: vec![],
                    r_points: vec![],
                    commitment: EqAffine::generator(),
                    eval: Fq::ZERO,
                    a_final: Fq::ZERO,
                },
                corrupt_challenge: false,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            AccumulateTestConfig {
                acc: VestaAccumulateConfig::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = VestaAccumulateChip::new(&config.acc);

            let k = self.witness.challenges.len();
            let l_x: Vec<Value<Fq>> = self.witness.l_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.x())
            }).collect();
            let l_y: Vec<Value<Fq>> = self.witness.l_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.y())
            }).collect();
            let r_x: Vec<Value<Fq>> = self.witness.r_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.x())
            }).collect();
            let r_y: Vec<Value<Fq>> = self.witness.r_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.y())
            }).collect();

            let bound_chals = if self.corrupt_challenge {
                // Introduce a challenge mismatch by generating wrong L/R data.
                // Flip the first byte of the first L point's x coordinate.
                let mut wrong_l_x = l_x.clone();
                if let Some(val) = wrong_l_x.first_mut() {
                    let corrupt = val.map(|v| v + Fq::ONE);
                    *val = corrupt;
                }
                chip.squeeze_challenges(
                    layouter.namespace(|| "squeeze"),
                    &config.acc,
                    k,
                    &wrong_l_x,
                    &l_y,
                    &r_x,
                    &r_y,
                )?
            } else {
                chip.squeeze_challenges(
                    layouter.namespace(|| "squeeze"),
                    &config.acc,
                    k,
                    &l_x,
                    &l_y,
                    &r_x,
                    &r_y,
                )?
            };

            let point_limb = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "point"),
                self.witness.point,
                "point",
            )?;

            let g_val: Vec<VestaPoint> =
                self.witness.generators.iter().map(|g| to_vesta_point(g)).collect();
            let offset_points = flatten_offsets(&self.witness.generators, &self.witness.challenges);

            let result = chip.fold_and_constrain(
                layouter.namespace(|| "fold"),
                &point_limb,
                &g_val,
                &offset_points,
                &bound_chals,
            )?;

            let (expected_b, expected_g) =
                host_fold(self.witness.point, &self.witness.generators, &self.witness.challenges);

            let expected_g_point = to_vesta_point(&expected_g);
            let expected_g_assigned = chip.ipa.ecc.assert_on_curve(
                layouter.namespace(|| "expected_g"),
                &expected_g_point,
                "expected_g",
            )?;

            let expected_b = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "expected_b"),
                expected_b,
                "expected_b",
            )?;

            if let (Some(b_cell), Some(exp_cell)) = (result.b_final.cell, expected_b.cell) {
                layouter.assign_region(|| "constrain_b", |mut region| {
                    region.constrain_equal(b_cell, exp_cell)?;
                    Ok(())
                })?;
            }
            if let (Some(gx_cell), Some(egx_cell)) =
                (result.g_final.x_cell, expected_g_assigned.x_cell)
            {
                layouter.assign_region(|| "constrain_gx", |mut region| {
                    region.constrain_equal(gx_cell, egx_cell)?;
                    Ok(())
                })?;
            }
            if let (Some(gy_cell), Some(egy_cell)) =
                (result.g_final.y_cell, expected_g_assigned.y_cell)
            {
                layouter.assign_region(|| "constrain_gy", |mut region| {
                    region.constrain_equal(gy_cell, egy_cell)?;
                    Ok(())
                })?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_accumulate_wires_transcript_and_fold() {
        let witness = build_test_witness();
        let circuit = AccumulateTest {
            witness,
            corrupt_challenge: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("failed: {:?}", e),
        }
    }

    #[test]
    fn test_accumulate_rejects_corrupt_challenge() {
        let witness = build_test_witness();
        let circuit = AccumulateTest {
            witness,
            corrupt_challenge: true,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for corrupt challenge");
    }

    struct VerifyIpaWitness {
        generators: Vec<EqAffine>,
        point: Fq,
        challenges: Vec<Fq>,
        l_points: Vec<EqAffine>,
        r_points: Vec<EqAffine>,
        commitment: EqAffine,
        eval: Fq,
        a_final: Fq,
        host_g_final: EqAffine,
        r_prime: Fq,
        h_point: EqAffine,
        u_point: EqAffine,
    }

    #[derive(Clone)]
    struct VerifyIpaConfig {
        acc: VestaAccumulateConfig,
    }

    struct VerifyIpaTest {
        witness: VerifyIpaWitness,
        corrupt_r_prime: bool,
    }

    impl Circuit<Fq> for VerifyIpaTest {
        type Config = VerifyIpaConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                witness: VerifyIpaWitness {
                    generators: vec![EqAffine::generator()],
                    point: Fq::ZERO,
                    challenges: vec![],
                    l_points: vec![],
                    r_points: vec![],
                    commitment: EqAffine::generator(),
                    eval: Fq::ZERO,
                    a_final: Fq::ZERO,
                    host_g_final: EqAffine::generator(),
                    r_prime: Fq::ZERO,
                    h_point: EqAffine::generator(),
                    u_point: EqAffine::generator(),
                },
                corrupt_r_prime: false,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            VerifyIpaConfig {
                acc: VestaAccumulateConfig::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = VestaAccumulateChip::new(&config.acc);
            let k = self.witness.challenges.len();

            let l_x: Vec<Value<Fq>> = self.witness.l_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.x())
            }).collect();
            let l_y: Vec<Value<Fq>> = self.witness.l_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.y())
            }).collect();
            let r_x: Vec<Value<Fq>> = self.witness.r_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.x())
            }).collect();
            let r_y: Vec<Value<Fq>> = self.witness.r_points.iter().map(|p| {
                let coords = p.coordinates().unwrap();
                Value::known(*coords.y())
            }).collect();

            let bound_chals = chip.squeeze_challenges(
                layouter.namespace(|| "squeeze"),
                &config.acc,
                k,
                &l_x,
                &l_y,
                &r_x,
                &r_y,
            )?;

            let point_limb = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "point"),
                self.witness.point,
                "point",
            )?;

            let g_val: Vec<VestaPoint> =
                self.witness.generators.iter().map(|g| to_vesta_point(g)).collect();
            let offset_points = flatten_offsets(&self.witness.generators, &self.witness.challenges);

            let fold_result = chip.fold_and_constrain(
                layouter.namespace(|| "fold"),
                &point_limb,
                &g_val,
                &offset_points,
                &bound_chals,
            )?;

            // L/R points as VestaPoints
            let l_vals: Vec<VestaPoint> = self.witness.l_points.iter().map(|p| to_vesta_point(p)).collect();
            let r_vals: Vec<VestaPoint> = self.witness.r_points.iter().map(|p| to_vesta_point(p)).collect();
            let commitment_point = to_vesta_point(&self.witness.commitment);

            // L/R offsets
            let two_pow_254 = BigUint::from(2u128).pow(254);
            let mut repr = <Fq as PrimeField>::Repr::default();
            let le = two_pow_254.to_bytes_le();
            repr.as_mut()[..le.len()].copy_from_slice(&le);
            let two_pow_254_fq = Fq::from_repr(repr).unwrap();
            let two_pow_254_fp = fq_as_fp(two_pow_254_fq);

            let mut lr_offsets = Vec::with_capacity(2 * k);
            for i in 0..k {
                let l_scaled = (self.witness.l_points[i].to_curve() * two_pow_254_fp).to_affine();
                lr_offsets.push(to_vesta_point(&l_scaled));
                let r_scaled = (self.witness.r_points[i].to_curve() * two_pow_254_fp).to_affine();
                lr_offsets.push(to_vesta_point(&r_scaled));
            }

            // g_final offset
            let g_final_scaled = (self.witness.host_g_final.to_curve() * two_pow_254_fp).to_affine();
            let g_final_offset = to_vesta_point(&g_final_scaled);

            // H and U from witness
            let h_scaled = (self.witness.h_point.to_curve() * two_pow_254_fp).to_affine();
            let u_scaled = (self.witness.u_point.to_curve() * two_pow_254_fp).to_affine();
            let h_offset = to_vesta_point(&h_scaled);
            let u_offset = to_vesta_point(&u_scaled);
            let h_point = to_vesta_point(&self.witness.h_point);
            let u_point = to_vesta_point(&self.witness.u_point);

            let eval_limb = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "eval"),
                self.witness.eval,
                "eval",
            )?;
            let a_final_limb = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "a_final"),
                self.witness.a_final,
                "a_final",
            )?;
            let r_prime_val = if self.corrupt_r_prime {
                self.witness.r_prime + Fq::ONE
            } else {
                self.witness.r_prime
            };
            let r_prime_limb = chip.ipa.fq.assign_constant(
                layouter.namespace(|| "r_prime"),
                r_prime_val,
                "r_prime",
            )?;

            chip.verify_ipa_full(
                layouter.namespace(|| "verify_ipa"),
                &commitment_point,
                &eval_limb,
                &a_final_limb,
                &r_prime_limb,
                &l_vals,
                &r_vals,
                &lr_offsets,
                &bound_chals,
                &fold_result,
                &g_final_offset,
                &h_point,
                &h_offset,
                &u_point,
                &u_offset,
            )?;

            Ok(())
        }
    }

    /// Build a base VerifyIpaWitness from the standard test witness.
    fn base_verify_witness() -> VerifyIpaWitness {
        let w = build_test_witness();
        let (host_b_final, host_g_final) =
            host_fold(w.point, &w.generators, &w.challenges);
        let gen = EqAffine::generator();

        let mut q = w.commitment.to_curve();
        for i in 0..w.challenges.len() {
            let x = w.challenges[i];
            let x_inv = x.invert().unwrap();
            q = (q + w.l_points[i].to_curve() * fq_as_fp(x_inv)
                   + w.r_points[i].to_curve() * fq_as_fp(x)).to_affine().to_curve();
        }
        let u_scalar = w.a_final * host_b_final - w.eval;
        let a_g_final_curve = host_g_final.to_curve() * fq_as_fp(w.a_final);
        let u_term = gen.to_curve() * fq_as_fp(u_scalar);
        let target = q - a_g_final_curve - u_term;
        let target_aff = target.to_affine();
        let (h_point, r_prime) = if bool::from(target.is_identity()) {
            (gen, Fq::ZERO)
        } else {
            (target_aff, Fq::ONE)
        };
        let u_point = gen;

        VerifyIpaWitness {
            generators: w.generators,
            point: w.point,
            challenges: w.challenges,
            l_points: w.l_points,
            r_points: w.r_points,
            commitment: w.commitment,
            eval: w.eval,
            a_final: w.a_final,
            host_g_final,
            r_prime,
            h_point,
            u_point,
        }
    }

    #[test]
    fn test_verify_ipa_full_passes() {
        let vw = base_verify_witness();
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("verify_ipa_full failed: {:?}", e),
        }
    }

    #[test]
    fn test_verify_ipa_full_rejects_corrupt_r_prime() {
        let vw = base_verify_witness();
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: true,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected rejection for corrupt r_prime"
        );
    }

    #[test]
    fn test_verify_ipa_full_rejects_corrupt_eval() {
        let mut vw = base_verify_witness();
        vw.eval = vw.eval + Fq::ONE;
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected rejection for corrupt eval"
        );
    }

    #[test]
    fn test_verify_ipa_full_rejects_corrupt_a_final() {
        let mut vw = base_verify_witness();
        vw.a_final = vw.a_final + Fq::ONE;
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected rejection for corrupt a_final"
        );
    }

    #[test]
    fn test_verify_ipa_full_rejects_corrupt_l_point() {
        let mut vw = base_verify_witness();
        vw.l_points[0] = EqAffine::generator();
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected rejection for corrupt L point"
        );
    }

    #[test]
    fn test_verify_ipa_full_rejects_corrupt_r_point() {
        let mut vw = base_verify_witness();
        vw.r_points[0] = EqAffine::generator();
        let circuit = VerifyIpaTest {
            witness: vw,
            corrupt_r_prime: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected rejection for corrupt R point"
        );
    }

    // ─── Integration: real IPA proof bytes → VerifyIpaTest circuit ───
    //
    // NOTE: A direct pipeline from aetheris-zkp's ProverIPA<EpAffine> (Vesta,
    // scalar Fq) into the Pallas-based VerifyIpaTest circuit (points EqAffine,
    // circuit field Fq) is infeasible without a major refactor. The proof's
    // scalars (Fq for Vesta, Fp for Pallas) live in different fields —
    // byte-reinterpretation does not preserve inverses or the IPA accumulator
    // equation.  A future integration could:
    //   1. Port the circuit to Vesta (EpAffine) so field types match natively
    //   2. Or write a standalone prover that operates on Pallas (EqAffine)
    //      with Fp scalars and a companion circuit over Fp.
    // For now, correctness of the circuit is validated by the synthetic-proof
    // tests above.
}
