use ff::Field;
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::pasta::Fq,
    plonk::ErrorFront,
};

use crate::vesta_ecc::{VestaEccChip, VestaEccConfig, VestaPoint};
use crate::vesta_fq::{VestaFqChip, VestaFqConfig};
use crate::Limb;

#[derive(Clone, Debug)]
pub struct VestaIpaConfig {
    pub fq: VestaFqConfig,
    pub ecc: VestaEccConfig,
}

pub struct VestaIpaResult {
    pub b_final: Limb<Fq>,
    pub g_final: VestaPoint,
}

pub struct VestaIpaChip {
    pub fq: VestaFqChip,
    pub ecc: VestaEccChip,
}

impl VestaIpaChip {
    pub fn new(fq: VestaFqChip, ecc: VestaEccChip) -> Self {
        Self { fq, ecc }
    }

    pub fn compute_b_vector(
        &self,
        mut layouter: impl Layouter<Fq>,
        point: &Limb<Fq>,
        n: usize,
    ) -> Result<Vec<Limb<Fq>>, ErrorFront> {
        assert!(n > 0, "IPA fold requires n > 0");
        let mut b = Vec::with_capacity(n);
        let one = self.fq.assign_constant(
            layouter.namespace(|| "b_one"),
            Fq::ONE, "b_one",
        )?;
        b.push(one);
        for i in 1..n {
            let next = self.fq.mul(
                layouter.namespace(|| format!("b_pow_{}", i)),
                &b[i - 1], point,
                &format!("b_pow_{}", i),
            )?;
            b.push(next);
        }
        Ok(b)
    }

    /// Fold generators and b-vector through k = challenges.len() rounds.
    ///
    /// `offset_points` are host-precomputed 2^254 · g for every generator that
    /// exists at the start of each round.  Flattened as:
    ///   round 0: generators 0..n
    ///   round 1: generators 0..n/2
    ///   ...
    /// Layout: offset_points[0..n] = round 0 offsets,
    ///         offset_points[n..n+n/2] = round 1 offsets, etc.
    /// Total length = n + n/2 + n/4 + ... = 2n - 1 (n = initial len).
    pub fn fold_to_final(
        &self,
        mut layouter: impl Layouter<Fq>,
        point: &Limb<Fq>,
        g_init: &[VestaPoint],
        offset_points: &[VestaPoint],
        challenges: &[Limb<Fq>],
    ) -> Result<VestaIpaResult, ErrorFront> {
        assert!(!g_init.is_empty(), "IPA fold requires at least one generator");
        assert!(g_init.len().is_power_of_two(), "generator length must be a power of two");
        assert_eq!(g_init.len(), 1usize << challenges.len(), "generator length must equal 2^k");
        let expected_offsets = 2usize * g_init.len() - 1;
        assert_eq!(offset_points.len(), expected_offsets,
            "offset_points must have length 2n-1 (got {}, expected {})",
            offset_points.len(), expected_offsets);

        let mut b_cur = self.compute_b_vector(
            layouter.namespace(|| "compute_b_vector"),
            point,
            g_init.len(),
        )?;
        for (i, g) in g_init.iter().enumerate() {
            self.ecc.assert_on_curve(
                layouter.namespace(|| format!("g_init_on_curve_{}", i)),
                g, &format!("g_init_{}", i),
            )?;
        }
        let mut g_cur = g_init.to_vec();
        let mut off_idx = 0usize;

        for (round, challenge) in challenges.iter().enumerate() {
            let x_inv = self.fq.invert(
                layouter.namespace(|| format!("inv_challenge_{}", round)),
                challenge,
                &format!("inv_{}", round),
            )?;

            let half = b_cur.len() / 2;
            let mut b_next = Vec::with_capacity(half);
            let mut g_next = Vec::with_capacity(half);

            for j in 0..half {
                let b_hi_scaled = self.fq.mul(
                    layouter.namespace(|| format!("round_{}_b_mul_{}", round, j)),
                    &x_inv, &b_cur[j + half],
                    &format!("b_mul_{}_{}", round, j),
                )?;
                let b_folded = self.fq.add(
                    layouter.namespace(|| format!("round_{}_b_add_{}", round, j)),
                    &b_cur[j], &b_hi_scaled,
                    &format!("b_add_{}_{}", round, j),
                )?;
                b_next.push(b_folded);

                let off = &offset_points[off_idx + j + half];
                let x_inv_val = x_inv.value;
                let g_hi_scaled = self.ecc.scalar_mul(
                    layouter.namespace(|| format!("round_{}_g_smul_{}", round, j)),
                    &g_cur[j + half],
                    off,
                    x_inv_val,
                    &format!("g_smul_{}_{}", round, j),
                )?;
                let g_folded = self.ecc.point_add(
                    layouter.namespace(|| format!("round_{}_g_add_{}", round, j)),
                    &g_cur[j],
                    &g_hi_scaled,
                    &format!("g_add_{}_{}", round, j),
                )?;
                self.ecc.assert_on_curve(
                    layouter.namespace(|| format!("round_{}_g_folded_on_curve_{}", round, j)),
                    &g_folded,
                    &format!("g_folded_{}_{}", round, j),
                )?;
                g_next.push(g_folded);
            }

            off_idx += g_cur.len();
            b_cur = b_next;
            g_cur = g_next;
        }

        assert_eq!(b_cur.len(), 1);
        assert_eq!(g_cur.len(), 1);
        Ok(VestaIpaResult {
            b_final: b_cur.pop().unwrap(),
            g_final: g_cur.pop().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    };
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
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

    fn fq_as_fp(x: Fq) -> Fp {
        let n = BigUint::from_bytes_le(x.to_repr().as_ref());
        let mut repr = <Fp as PrimeField>::Repr::default();
        let le = n.to_bytes_le();
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        Fp::from_repr(repr).unwrap()
    }

    fn generator_chain(len: usize) -> Vec<EqAffine> {
        let g = EqAffine::generator();
        let mut chain = Vec::with_capacity(len);
        for i in 0..len {
            let p = (g * Fp::from(i as u64 + 1)).to_affine();
            chain.push(p);
        }
        chain
    }

    fn host_fold(
        point: Fq,
        g_init: &[EqAffine],
        challenges: &[Fq],
    ) -> (Fq, EqAffine) {
        let n = g_init.len();
        let mut b: Vec<Fq> = Vec::with_capacity(n);
        b.push(Fq::ONE);
        for i in 1..n {
            b.push(b[i - 1] * point);
        }
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

    #[derive(Clone)]
    struct VestaFoldTestConfig {
        ipa: VestaIpaConfig,
    }

    struct VestaFoldTest {
        point: Fq,
        generators: Vec<EqAffine>,
        challenges: Vec<Fq>,
        corrupt_challenge: bool,
    }

    impl VestaFoldTest {
        fn generators_val(&self) -> Vec<VestaPoint> {
            self.generators.iter().map(|g| to_vesta_point(g)).collect()
        }
    }

    impl Circuit<Fq> for VestaFoldTest {
        type Config = VestaFoldTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                point: Fq::ZERO,
                generators: vec![],
                challenges: vec![],
                corrupt_challenge: false,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let fq = VestaFqConfig::configure(meta);
            let ecc = VestaEccConfig::configure(meta);
            VestaFoldTestConfig { ipa: VestaIpaConfig { fq, ecc } }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let fq_chip = VestaFqChip::new(config.ipa.fq);
            let ecc_chip = VestaEccChip::new(config.ipa.ecc);
            let ipa = VestaIpaChip::new(fq_chip, ecc_chip);

            let point_limb = ipa.fq.assign_constant(
                layouter.namespace(|| "point"),
                self.point, "point",
            )?;

            let chal_limbs: Vec<Limb<Fq>> = if self.corrupt_challenge {
                self.challenges.iter().enumerate().map(|(i, c)| {
                    let corrupted = *c + Fq::from(i as u64 + 1);
                    ipa.fq.assign_constant(
                        layouter.namespace(|| format!("chal_{}", i)),
                        corrupted, &format!("chal_{}", i),
                    ).unwrap()
                }).collect()
            } else {
                self.challenges.iter().enumerate().map(|(i, c)| {
                    ipa.fq.assign_constant(
                        layouter.namespace(|| format!("chal_{}", i)),
                        *c, &format!("chal_{}", i),
                    ).unwrap()
                }).collect()
            };

            let g_val = self.generators_val();
            let offset_points = flatten_offsets(&self.generators, &self.challenges);

            let result = ipa.fold_to_final(
                layouter.namespace(|| "fold"),
                &point_limb,
                &g_val,
                &offset_points,
                &chal_limbs,
            )?;

            let (expected_b, expected_g) = host_fold(
                self.point, &self.generators, &self.challenges,
            );

            let expected_g_point = to_vesta_point(&expected_g);
            let expected_g_assigned = ipa.ecc.assert_on_curve(
                layouter.namespace(|| "expected_g"),
                &expected_g_point,
                "expected_g",
            )?;

            let expected_b = ipa.fq.assign_constant(
                layouter.namespace(|| "expected_b"),
                expected_b, "expected_b",
            )?;

            if let (Some(b_cell), Some(exp_cell)) = (result.b_final.cell, expected_b.cell) {
                layouter.assign_region(
                    || "constrain_b",
                    |mut region| region.constrain_equal(b_cell, exp_cell),
                )?;
            }
            if let (Some(gx_cell), Some(egx_cell)) = (result.g_final.x_cell, expected_g_assigned.x_cell) {
                layouter.assign_region(
                    || "constrain_gx",
                    |mut region| region.constrain_equal(gx_cell, egx_cell),
                )?;
            }
            if let (Some(gy_cell), Some(egy_cell)) = (result.g_final.y_cell, expected_g_assigned.y_cell) {
                layouter.assign_region(
                    || "constrain_gy",
                    |mut region| region.constrain_equal(gy_cell, egy_cell),
                )?;
            }

            Ok(())
        }
    }

    #[test]
    #[ignore = "heavy K>=17 recursive circuit test; run explicitly with --ignored and a name filter"]
    fn test_vesta_fold_k1() {
        let g = generator_chain(2);
        let challenges = vec![Fq::from(7)];
        let circuit = VestaFoldTest {
            point: Fq::from(3),
            generators: g,
            challenges,
            corrupt_challenge: false,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("failed: {:?}", e),
        }
    }

    #[test]
    #[ignore = "heavy K>=17 recursive circuit test; run explicitly with --ignored and a name filter"]
    fn test_vesta_fold_k1_corrupt_rejected() {
        let g = generator_chain(2);
        let challenges = vec![Fq::from(7)];
        let circuit = VestaFoldTest {
            point: Fq::from(3),
            generators: g,
            challenges,
            corrupt_challenge: true,
        };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for corrupt challenge");
    }
}
