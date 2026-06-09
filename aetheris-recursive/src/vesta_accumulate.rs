use crate::non_native_fq::NonNativeFqConfig;
use crate::transcript_blake2b_circuit::{
    Blake2bCompressionCircuitChip, Blake2bCompressionCircuitConfig,
};
use crate::transcript_words::TranscriptWordConfig;
use crate::vesta_ecc::{VestaEccConfig, VestaPoint};
use crate::vesta_fq::VestaFqConfig;
use crate::vesta_ipa::{VestaIpaChip, VestaIpaConfig, VestaIpaResult};
use crate::Limb;
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Selector},
};

#[derive(Clone, Debug)]
pub struct VestaAccumulateConfig {
    pub compression: Blake2bCompressionCircuitConfig,
    pub word_config: TranscriptWordConfig,
    pub fq_dummy: NonNativeFqConfig,
    pub challenge_col: Column<Advice>,
    pub s_witness: Selector,
    pub ipa: VestaIpaConfig,
}

impl VestaAccumulateConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        let compression = Blake2bCompressionCircuitChip::configure(meta);
        let word_config = crate::transcript_words::TranscriptWordChip::configure(meta);
        let fq_dummy = NonNativeFqConfig::configure_no_gates(meta);
        let challenge_col = meta.advice_column();
        meta.enable_equality(challenge_col);
        let s_witness = meta.complex_selector();
        let ipa = VestaIpaConfig {
            fq: VestaFqConfig::configure(meta),
            ecc: VestaEccConfig::configure(meta),
        };
        Self {
            compression,
            word_config,
            fq_dummy,
            challenge_col,
            s_witness,
            ipa,
        }
    }
}

pub struct VestaAccumulateChip {
    blake2b: Blake2bCompressionCircuitChip,
    pub ipa: VestaIpaChip,
}

impl VestaAccumulateChip {
    pub fn new(config: &VestaAccumulateConfig) -> Self {
        let blake2b = Blake2bCompressionCircuitChip::new(
            config.compression.clone(),
            config.word_config.clone(),
            config.fq_dummy.clone(),
        );
        let fq = crate::vesta_fq::VestaFqChip::new(config.ipa.fq.clone());
        let ecc = crate::vesta_ecc::VestaEccChip::new(config.ipa.ecc.clone());
        let ipa = VestaIpaChip::new(fq, ecc);
        Self { blake2b, ipa }
    }

    pub fn squeeze_challenges(
        &self,
        mut layouter: impl Layouter<Fq>,
        config: &VestaAccumulateConfig,
        prefixes: &[Vec<u8>],
        chal_witness: &[Limb<Fq>],
    ) -> Result<Vec<Limb<Fq>>, ErrorFront> {
        use crate::transcript_blake2b::BLAKE2B_STATE_WORDS;
        use crate::transcript_blake2b_circuit::{AssignedBlake2bStateRow};
        use crate::transcript_blake2b_compression::{
            blake2b_compression_trace_skeleton, halo2_blake2b_transcript_initial_state,
        };
        use crate::transcript_bytes::TranscriptByteStream;
        use crate::vesta_transcript::constrain_challenge_scalar_native;

        let mut out = Vec::with_capacity(prefixes.len());

        for (i, prefix) in prefixes.iter().enumerate() {
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(prefix);
            let ref_trace = blake2b_compression_trace_skeleton(&stream);
            let iv = halo2_blake2b_transcript_initial_state();

            let mut prev_cells: [Limb<Fq>; BLAKE2B_STATE_WORDS] = std::array::from_fn(|_| Limb {
                value: Value::known(Fq::ZERO),
                cell: None,
            });
            let mut last_assigned: Option<AssignedBlake2bStateRow<Fq>> = None;

            for (bi, row) in ref_trace.rows.iter().enumerate() {
                let state_in = if bi == 0 {
                    iv
                } else {
                    ref_trace.rows[bi - 1].state_out
                };
                let this_row = self.blake2b.assign_and_constrain_squeeze_block(
                    layouter.namespace(|| format!("squeeze_{}_{}", i, bi)),
                    &state_in,
                    &row.block,
                    &prev_cells,
                    &format!("squeeze_{}_{}", i, bi),
                )?;
                prev_cells = std::array::from_fn(|j| this_row.state_out[j].clone());
                last_assigned = Some(this_row);
            }

            let last_row = last_assigned.expect("trace must have rows");
            let digest = ref_trace.rows.last().expect("trace must have rows").state_out;
            let digest_limbs: [Limb<Fq>; BLAKE2B_STATE_WORDS] =
                std::array::from_fn(|j| last_row.state_out[j].clone());

            let _bound = constrain_challenge_scalar_native(
                &config.compression,
                layouter.namespace(|| format!("bind_{}", i)),
                &digest_limbs,
                &digest,
                &chal_witness[i],
            )?;

            out.push(chal_witness[i].clone());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipa_transcript::{challenge_prefix_bytes, point_transcript_bytes, scalar_transcript_bytes};
    use ff::{Field, FromUniformBytes, PrimeField};
    use halo2_proofs::halo2curves::pasta::EqAffine;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::Circuit,
    };
    use halo2curves::group::prime::PrimeCurveAffine;
    use halo2curves::group::Curve;
    use halo2curves::CurveAffine;
    use num_bigint::BigUint;

    /// Split a byte stream into challenge-specific prefixes by 0x00 markers.
    fn squeeze_prefixes(stream: &[u8], k: usize) -> Vec<Vec<u8>> {
        let mut prefixes = Vec::with_capacity(k);
        let mut chal_count = 0usize;
        for i in 0..stream.len() {
            if stream[i] == 0x00 {
                chal_count += 1;
                if chal_count <= k {
                    prefixes.push(stream[..=i].to_vec());
                }
                if chal_count >= k {
                    break;
                }
            }
        }
        prefixes
    }

    /// Hash a byte prefix through Blake2b and produce an Fq challenge.
    fn blake2b_prefix_challenge(prefix: &[u8]) -> Fq {
        let mut stream = crate::transcript_bytes::TranscriptByteStream::new();
        stream.extend_bytes(prefix);
        let trace =
            crate::transcript_blake2b_compression::blake2b_compression_trace_skeleton(&stream);
        let digest = trace.rows.last().expect("trace must have rows").state_out;
        let mut bytes = [0u8; 64];
        for (i, w) in digest.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
        }
        Fq::from_uniform_bytes(&bytes)
    }

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

            let mut byte_stream = Vec::new();
            byte_stream.extend_from_slice(&scalar_transcript_bytes(Fq::from(n as u64)));
            byte_stream.extend_from_slice(&scalar_transcript_bytes(point));
            byte_stream.extend_from_slice(&point_transcript_bytes(commitment).unwrap());
            byte_stream.extend_from_slice(&scalar_transcript_bytes(eval));
            for idx in 0..l_points.len() {
                byte_stream.extend_from_slice(&point_transcript_bytes(l_points[idx]).unwrap());
                byte_stream.extend_from_slice(&point_transcript_bytes(r_points[idx]).unwrap());
                byte_stream.extend_from_slice(&challenge_prefix_bytes());
            }
            byte_stream.extend_from_slice(&point_transcript_bytes(l_aff).unwrap());
            byte_stream.extend_from_slice(&point_transcript_bytes(r_aff).unwrap());
            byte_stream.extend_from_slice(&challenge_prefix_bytes());

            let prefixes = squeeze_prefixes(&byte_stream, k);
            let chal_idx = l_points.len();
            let x = blake2b_prefix_challenge(&prefixes[chal_idx]);
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

            let mut byte_stream = Vec::new();
            byte_stream.extend_from_slice(&scalar_transcript_bytes(Fq::from(self.witness.generators.len() as u64)));
            byte_stream.extend_from_slice(&scalar_transcript_bytes(self.witness.point));
            byte_stream.extend_from_slice(&point_transcript_bytes(self.witness.commitment).unwrap());
            byte_stream.extend_from_slice(&scalar_transcript_bytes(self.witness.eval));
            for i in 0..k {
                byte_stream.extend_from_slice(&point_transcript_bytes(self.witness.l_points[i]).unwrap());
                byte_stream.extend_from_slice(&point_transcript_bytes(self.witness.r_points[i]).unwrap());
                byte_stream.extend_from_slice(&challenge_prefix_bytes());
            }

            let prefixes = squeeze_prefixes(&byte_stream, k);

            let chal_limbs: Vec<Limb<Fq>> = self
                .witness
                .challenges
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let val = if self.corrupt_challenge {
                        *c + Fq::from(i as u64 + 1)
                    } else {
                        *c
                    };
                    chip.ipa
                        .fq
                        .assign_constant(
                            layouter.namespace(|| format!("chal_{}", i)),
                            val,
                            &format!("chal_{}", i),
                        )
                        .unwrap()
                })
                .collect();

            let bound_chals = chip.squeeze_challenges(
                layouter.namespace(|| "squeeze"),
                &config.acc,
                &prefixes,
                &chal_limbs,
            )?;

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
}
