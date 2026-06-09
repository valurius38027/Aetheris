use ff::Field;
use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Column, ErrorFront},
};

use crate::transcript_blake2b::BLAKE2B_STATE_WORDS;
use crate::transcript_blake2b_circuit::Blake2bCompressionCircuitConfig;
use crate::transcript_words::TranscriptWordConfig;
use crate::vesta_range::FqRangeCheckChip;
use crate::Limb;

fn compute_shift_constants() -> [Fq; BLAKE2B_STATE_WORDS] {
    let two_pow_64 = Fq::from(1u64 << 32).square();
    let mut acc = Fq::ONE;
    [Fq::ZERO; BLAKE2B_STATE_WORDS].map(|_| {
        acc = acc * two_pow_64;
        acc
    })
}

fn accumulate(words: &[u64; BLAKE2B_STATE_WORDS], up_to: usize) -> Fq {
    let shifts = compute_shift_constants();
    let mut sum = Fq::from(words[0]);
    for j in 1..=up_to {
        sum = sum + Fq::from(words[j]) * shifts[j - 1];
    }
    sum
}

pub fn constrain_challenge_scalar_native(
    compression: &Blake2bCompressionCircuitConfig,
    mut layouter: impl Layouter<Fq>,
    state_out_cells: &[Limb<Fq>; BLAKE2B_STATE_WORDS],
    words: &[u64; BLAKE2B_STATE_WORDS],
    challenge: &Limb<Fq>,
) -> Result<(), ErrorFront> {
    let shifts = compute_shift_constants();
    let mut prev_cell: Option<Cell> = state_out_cells[0].cell;

    for i in 1..BLAKE2B_STATE_WORDS {
        let target_val = accumulate(words, i);
        let term1_val = accumulate(words, i - 1);
        let term2_val = Fq::from(words[i]);
        let shift_val = shifts[i - 1];

        let target_cell = layouter.assign_region(
            || format!("decompose_challenge_{}", i),
            |mut region| {
                compression.s_decompose.enable(&mut region, 0)?;

                let target = region.assign_advice(
                    || "target",
                    compression.step_expected[0],
                    0,
                    || Value::known(target_val),
                )?;

                let t1 = region.assign_advice(
                    || "t1",
                    compression.challenge_limbs[0],
                    0,
                    || Value::known(term1_val),
                )?;
                if let Some(c) = prev_cell {
                    region.constrain_equal(t1.cell(), c)?;
                }

                let t2 = region.assign_advice(
                    || "t2",
                    compression.challenge_limbs[1],
                    0,
                    || Value::known(term2_val),
                )?;
                if let Some(c) = state_out_cells[i].cell {
                    region.constrain_equal(t2.cell(), c)?;
                }

                region.assign_fixed(
                    || "shift",
                    compression.decompose_shift,
                    0,
                    || Value::known(shift_val),
                )?;

                Ok(target.cell())
            },
        )?;

        prev_cell = Some(target_cell);
    }

    if let (Some(acc_cell), Some(challenge_cell)) = (prev_cell, challenge.cell) {
        layouter.assign_region(
            || "constrain_challenge_equal",
            |mut region| region.constrain_equal(acc_cell, challenge_cell),
        )?;
    }

    Ok(())
}

pub fn assign_byte(
    mut layouter: impl Layouter<Fq>,
    range_chip: &FqRangeCheckChip,
    byte_col: Column<Advice>,
    value: Value<u8>,
    label: &str,
) -> Result<Limb<Fq>, ErrorFront> {
    let limb = layouter.assign_region(
        || format!("assign_byte_{}", label),
        |mut region| {
            let cell = region.assign_advice(
                || format!("byte_{}", label),
                byte_col,
                0,
                || value.map(|v| Fq::from(u64::from(v))),
            )?;
            Ok(Limb { value: value.map(|v| Fq::from(u64::from(v))), cell: Some(cell.cell()) })
        },
    )?;
    range_chip.range_check(
        layouter.namespace(|| format!("range_byte_{}", label)),
        &limb,
        8,
    )?;
    Ok(limb)
}

pub fn assign_word_from_bytes(
    mut layouter: impl Layouter<Fq>,
    word_config: &TranscriptWordConfig,
    byte_limbs: &[Limb<Fq>],
    word_u64: u64,
    label: &str,
) -> Result<Limb<Fq>, ErrorFront> {
    assert_eq!(byte_limbs.len(), 8, "word must have 8 byte limbs");
    layouter.assign_region(
        || format!("word_decode_{}", label),
        |mut region| {
            word_config.s_decode.enable(&mut region, 0)?;
            let word_val = Fq::from(word_u64);
            let word = region.assign_advice(
                || "word",
                word_config.word,
                0,
                || Value::known(word_val),
            )?;
            for i in 0..8 {
                let byte = region.assign_advice(
                    || format!("byte_{}", i),
                    word_config.byte_cols[i],
                    0,
                    || byte_limbs[i].value,
                )?;
                if let Some(cell) = byte_limbs[i].cell {
                    region.constrain_equal(byte.cell(), cell)?;
                }
            }
            Ok(Limb { value: Value::known(word_val), cell: Some(word.cell()) })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_words::TranscriptWordChip;
    use crate::vesta_range::FqRangeCheckConfig;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Selector},
    };
    use ff::PrimeField;

    #[derive(Clone)]
    struct FqChallengeTestConfig {
        compression: Blake2bCompressionCircuitConfig,
        state_words: [Column<Advice>; BLAKE2B_STATE_WORDS],
        challenge_col: Column<Advice>,
        s_witness: Selector,
    }

    struct FqChallengeTest {
        words: [u64; BLAKE2B_STATE_WORDS],
        corrupt: bool,
    }

    impl Circuit<Fq> for FqChallengeTest {
        type Config = FqChallengeTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { words: [0u64; BLAKE2B_STATE_WORDS], corrupt: self.corrupt }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            use crate::transcript_blake2b_circuit::Blake2bCompressionCircuitChip;
            let compression = Blake2bCompressionCircuitChip::configure(meta);
            let state_words = [0; BLAKE2B_STATE_WORDS].map(|_| meta.advice_column());
            for c in &state_words {
                meta.enable_equality(*c);
            }
            let challenge_col = meta.advice_column();
            meta.enable_equality(challenge_col);
            let s_witness = meta.complex_selector();
            FqChallengeTestConfig { compression, state_words, challenge_col, s_witness }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let challenge_val = host_challenge(&self.words);
            let witness_val = if self.corrupt {
                challenge_val + Fq::ONE
            } else {
                challenge_val
            };

            let state_cells: [Limb<Fq>; BLAKE2B_STATE_WORDS] = layouter.assign_region(
                || "state_words",
                |mut region| {
                    let mut limbs = Vec::with_capacity(BLAKE2B_STATE_WORDS);
                    for i in 0..BLAKE2B_STATE_WORDS {
                        let cell = region.assign_advice(
                            || format!("word_{}", i),
                            config.state_words[i],
                            0,
                            || Value::known(Fq::from(self.words[i])),
                        )?;
                        limbs.push(Limb { value: Value::known(Fq::from(self.words[i])), cell: Some(cell.cell()) });
                    }
                    Ok(limbs.try_into().unwrap())
                },
            )?;

            let challenge_limb = layouter.assign_region(
                || "challenge_witness",
                |mut region| {
                    config.s_witness.enable(&mut region, 0)?;
                    let cell = region.assign_advice(
                        || "challenge",
                        config.challenge_col,
                        0,
                        || Value::known(witness_val),
                    )?;
                    Ok(Limb { value: Value::known(witness_val), cell: Some(cell.cell()) })
                },
            )?;

            constrain_challenge_scalar_native(
                &config.compression,
                layouter.namespace(|| "challenge_derivation"),
                &state_cells,
                &self.words,
                &challenge_limb,
            )
        }
    }

    fn host_challenge(words: &[u64; BLAKE2B_STATE_WORDS]) -> Fq {
        use num_bigint::BigUint;
        let mut full = BigUint::from(0u32);
        for (i, w) in words.iter().copied().enumerate() {
            full += BigUint::from(w) << (64 * i);
        }
        let fq_bytes: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0x21, 0xEB, 0x46, 0x8C,
            0xDD, 0xA8, 0x94, 0x09, 0xFC, 0x98, 0x46, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
        ];
        let modulus = BigUint::from_bytes_le(&fq_bytes);
        let val = full % modulus;
        let bytes = val.to_bytes_le();
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
        Fq::from_repr(repr).unwrap()
    }

    fn known_digest() -> [u64; BLAKE2B_STATE_WORDS] {
        let msg = b"hello world";
        use blake2b_simd::Params;
        let hash = Params::new().hash_length(64).hash(msg);
        let bytes = hash.as_bytes();
        let mut words = [0u64; BLAKE2B_STATE_WORDS];
        for i in 0..BLAKE2B_STATE_WORDS {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            words[i] = u64::from_le_bytes(word_bytes);
        }
        words
    }

    #[test]
    fn test_native_challenge_from_digest() {
        let words = known_digest();
        let circuit = FqChallengeTest { words, corrupt: false };
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_native_challenge_wrong_rejected() {
        let words = known_digest();
        let circuit = FqChallengeTest { words, corrupt: true };
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for corrupt challenge");
    }

    // ── S1 + S2: byte assign + word decode ──

    #[derive(Clone)]
    struct ByteDecodeTestConfig {
        word_config: TranscriptWordConfig,
        range_config: FqRangeCheckConfig,
        byte_col: Column<Advice>,
        word_witness: Column<Advice>,
        s_word_witness: Selector,
    }

    struct ByteDecodeTest {
        bytes: [u8; 8],
        corrupt_word: bool,
    }

    impl Circuit<Fq> for ByteDecodeTest {
        type Config = ByteDecodeTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { bytes: [0u8; 8], corrupt_word: self.corrupt_word }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let word_config = TranscriptWordChip::configure(meta);
            let range_config = FqRangeCheckConfig::configure(meta);
            let byte_col = meta.advice_column();
            meta.enable_equality(byte_col);
            let word_witness = meta.advice_column();
            meta.enable_equality(word_witness);
            let s_word_witness = meta.complex_selector();
            ByteDecodeTestConfig { word_config, range_config, byte_col, word_witness, s_word_witness }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let range_chip = FqRangeCheckChip::new(config.range_config.clone());

            let mut byte_limbs = Vec::new();
            for i in 0..8 {
                let limb = assign_byte(
                    layouter.namespace(|| format!("byte_{}", i)),
                    &range_chip,
                    config.byte_col,
                    Value::known(self.bytes[i]),
                    &format!("byte_{}", i),
                )?;
                byte_limbs.push(limb);
            }

            let expected_word = u64::from_le_bytes(self.bytes);
            let word_limb = assign_word_from_bytes(
                layouter.namespace(|| "word"),
                &config.word_config,
                &byte_limbs,
                expected_word,
                "word",
            )?;

            let witness_val = if self.corrupt_word {
                expected_word.wrapping_add(1)
            } else {
                expected_word
            };
            let witness_limb = layouter.assign_region(
                || "word_witness",
                |mut region| {
                    config.s_word_witness.enable(&mut region, 0)?;
                    let cell = region.assign_advice(
                        || "witness",
                        config.word_witness,
                        0,
                        || Value::known(Fq::from(witness_val)),
                    )?;
                    Ok(Limb { value: Value::known(Fq::from(witness_val)), cell: Some(cell.cell()) })
                },
            )?;

            if let (Some(word_cell), Some(witness_cell)) = (word_limb.cell, witness_limb.cell) {
                layouter.assign_region(
                    || "constrain_word_equal",
                    |mut region| region.constrain_equal(word_cell, witness_cell),
                )?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_byte_decode_roundtrip() {
        let circuit = ByteDecodeTest { bytes: *b"hello   ", corrupt_word: false };
        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_byte_decode_wrong_word_rejected() {
        let circuit = ByteDecodeTest { bytes: *b"hello   ", corrupt_word: true };
        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for corrupt word");
    }

    // ── S3: Fq Compress Block ──

    use crate::transcript_bytes::TranscriptByteStream;
    use crate::transcript_blake2b_compression::{blake2b_compression_trace_skeleton, halo2_blake2b_transcript_initial_state};
    use crate::transcript_blake2b_circuit::{AssignedBlake2bStateRow, Blake2bCompressionCircuitChip};
    use crate::non_native_fq::NonNativeFqConfig;

    #[derive(Clone)]
    struct FqCompressTestConfig {
        compression: Blake2bCompressionCircuitConfig,
        word_config: TranscriptWordConfig,
        fq_config: crate::non_native_fq::NonNativeFqConfig,
    }

    struct FqCompressTest {
        stream: TranscriptByteStream,
        corrupt_feed_forward: bool,
    }

    impl Circuit<Fq> for FqCompressTest {
        type Config = FqCompressTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { stream: TranscriptByteStream::new(), corrupt_feed_forward: self.corrupt_feed_forward }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let compression = Blake2bCompressionCircuitChip::configure(meta);
            let word_config = TranscriptWordChip::configure(meta);
            let fq_config = NonNativeFqConfig::configure_no_gates(meta);
            FqCompressTestConfig { compression, word_config, fq_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = Blake2bCompressionCircuitChip::new(
                config.compression.clone(),
                config.word_config.clone(),
                config.fq_config.clone(),
            );

            let trace = blake2b_compression_trace_skeleton(&self.stream);

            let trace = if self.corrupt_feed_forward {
                let mut t = trace;
                t.rows[0].state_out[0] = t.rows[0].state_out[0].wrapping_add(1);
                t
            } else {
                trace
            };

            let mut assigned_rounds = Vec::new();
            let mut first_state_row = None;
            for (i, row) in trace.rows.iter().enumerate() {
                let assigned = chip.assign_state_row(
                    layouter.namespace(|| format!("state_row_{}", i)),
                    &row.block,
                    &row.state_in,
                    &row.state_out,
                    &format!("state_row_{}", i),
                )?;
                if i == 0 {
                    first_state_row = Some(assigned.clone());
                }

                chip.assign_round_placeholder(
                    layouter.namespace(|| format!("placeholder_{}", i)),
                    i,
                    &format!("placeholder_{}", i),
                )?;

                for round in &row.rounds {
                    let assigned_round = chip.assign_round_trace_row(
                        layouter.namespace(|| format!("round_{}_{}", i, round.round_index)),
                        &row.block,
                        round,
                        &format!("round_{}_{}", i, round.round_index),
                    )?;

                    chip.constrain_round_message_pair(
                        layouter.namespace(|| format!("round_msg_{}_{}", i, round.round_index)),
                        &assigned,
                        &assigned_round,
                        round,
                    )?;

                    let mut assigned_mixes = Vec::new();
                    for mix in &round.mixes {
                        let assigned_mix = chip.assign_mix_trace_row(
                            layouter.namespace(|| format!("mix_{}_{}_{}", i, round.round_index, mix.mix_index)),
                            mix,
                            &format!("mix_{}_{}_{}", i, round.round_index, mix.mix_index),
                        )?;

                        chip.constrain_mix_message_pair(
                            layouter.namespace(|| format!("mix_msg_{}_{}_{}", i, round.round_index, mix.mix_index)),
                            &assigned,
                            &assigned_mix,
                            mix,
                            round.round_index,
                        )?;

                        assigned_mixes.push(assigned_mix);
                    }

                    chip.constrain_mix_to_round_boundary(
                        layouter.namespace(|| format!("mix_bound_in_{}_{}", i, round.round_index)),
                        &assigned_round,
                        &assigned_mixes[0],
                        true,
                    )?;
                    chip.constrain_mix_to_round_boundary(
                        layouter.namespace(|| format!("mix_bound_out_{}_{}", i, round.round_index)),
                        &assigned_round,
                        assigned_mixes.last().unwrap(),
                        false,
                    )?;
                    chip.constrain_mix_chaining(
                        layouter.namespace(|| format!("mix_chain_{}_{}", i, round.round_index)),
                        &assigned_mixes,
                    )?;

                    for (mix, assigned_mix) in round.mixes.iter().zip(&assigned_mixes) {
                        let mut assigned_steps = Vec::new();
                        for step in &mix.steps {
                            let assigned_step = chip.assign_mix_step_row(
                                layouter.namespace(|| {
                                    format!("step_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)
                                }),
                                step,
                                &format!("step_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index),
                            )?;
                            assigned_steps.push(assigned_step);
                        }
                        chip.constrain_mix_boundary(
                            layouter.namespace(|| format!("step_bound_in_{}_{}_{}", i, round.round_index, mix.mix_index)),
                            assigned_mix,
                            &assigned_steps[0],
                            true,
                        )?;
                        chip.constrain_mix_boundary(
                            layouter.namespace(|| format!("step_bound_out_{}_{}_{}", i, round.round_index, mix.mix_index)),
                            assigned_mix,
                            assigned_steps.last().unwrap(),
                            false,
                        )?;
                        chip.constrain_mix_step_chaining(
                            layouter.namespace(|| format!("step_chain_{}_{}_{}", i, round.round_index, mix.mix_index)),
                            &assigned_steps,
                        )?;

                        for (assigned_step, step) in assigned_steps.iter().zip(&mix.steps) {
                            chip.constrain_mix_step_unchanged_lanes(
                                layouter.namespace(|| format!("unchanged_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)),
                                assigned_step,
                                step,
                                mix.mix_index,
                            )?;
                            chip.constrain_mix_step_expected_output(
                                layouter.namespace(|| format!("expected_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)),
                                assigned_step,
                                step,
                                mix.mix_index,
                            )?;
                            if step.rotation.is_some() {
                                chip.constrain_mix_step_rotation(
                                    layouter.namespace(|| format!("rotate_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)),
                                    assigned_step,
                                    step,
                                    mix.mix_index,
                                )?;
                                chip.constrain_mix_step_rotation_xor_native(
                                    layouter.namespace(|| format!("rotate_xor_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)),
                                    assigned_step,
                                    step,
                                    mix.mix_index,
                                )?;
                            }
                            if step.addend_lane.is_some() {
                                chip.constrain_mix_step_wrapping_add_native(
                                    layouter.namespace(|| format!("add_{}_{}_{}_{}", i, round.round_index, mix.mix_index, step.step_index)),
                                    assigned_step,
                                    step,
                                    mix.mix_index,
                                )?;
                            }
                        }
                    }

                    assigned_rounds.push(assigned_round);
                }

                chip.constrain_round_chaining(
                    layouter.namespace(|| format!("round_chain_{}", i)),
                    &assigned_rounds,
                )?;

                chip.constrain_feed_forward_xor(
                    layouter.namespace(|| format!("feed_forward_{}", i)),
                    &assigned,
                    assigned_rounds.last().unwrap(),
                    &row.state_in,
                    &trace.rows[i].rounds.last().unwrap().work_out,
                    &row.state_out,
                )?;
            }

            chip.constrain_initial_round_state(
                layouter.namespace(|| "init_round_state"),
                first_state_row.as_ref().unwrap(),
                &assigned_rounds[0],
            )?;
            chip.constrain_initial_round_metadata(
                layouter.namespace(|| "init_round_meta"),
                &trace.rows[0].block,
                &assigned_rounds[0],
                "init_round_meta",
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_fq_compress_block_valid() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"The Magic Words are Squeamish Ossifrage");
        let circuit = FqCompressTest { stream, corrupt_feed_forward: false };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_fq_compress_wrong_feed_forward_rejected() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"hello world");
        let circuit = FqCompressTest { stream, corrupt_feed_forward: true };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for wrong feed-forward");
    }

    // ── S5: Vesta Transcript End-to-End (compress → squeeze → challenge) ──
    //
    // Tests the full pipeline: compress multi-block input, derive Fq challenge
    // from final Blake2b digest.  Uses squeeze_state columns via
    // assign_and_constrain_squeeze_block to chain blocks, exactly as the IPA
    // verifier circuit will.

    #[derive(Clone)]
    struct VestaSqueezeTestConfig {
        compression: Blake2bCompressionCircuitConfig,
        word_config: TranscriptWordConfig,
        fq_config: NonNativeFqConfig,
        challenge_col: Column<Advice>,
        s_witness: Selector,
    }

    struct VestaSqueezeTest {
        input: Vec<u8>,
        corrupt_challenge: bool,
    }

    impl Circuit<Fq> for VestaSqueezeTest {
        type Config = VestaSqueezeTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { input: vec![0; self.input.len()], corrupt_challenge: self.corrupt_challenge }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let compression = Blake2bCompressionCircuitChip::configure(meta);
            let word_config = TranscriptWordChip::configure(meta);
            let fq_config = NonNativeFqConfig::configure_no_gates(meta);
            let challenge_col = meta.advice_column();
            meta.enable_equality(challenge_col);
            let s_witness = meta.complex_selector();
            VestaSqueezeTestConfig { compression, word_config, fq_config, challenge_col, s_witness }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = Blake2bCompressionCircuitChip::new(
                config.compression.clone(),
                config.word_config.clone(),
                config.fq_config.clone(),
            );

            // Build the compression trace
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(&self.input);
            let trace = blake2b_compression_trace_skeleton(&stream);

            // Chain blocks via assign_and_constrain_squeeze_block, exactly as
            // the IPA verifier circuit does.
            let iv = halo2_blake2b_transcript_initial_state();
            let mut prev_cells: [Limb<Fq>; BLAKE2B_STATE_WORDS] = std::array::from_fn(|_| Limb {
                value: Value::known(Fq::ZERO), cell: None,
            });
            let mut last_assigned: Option<AssignedBlake2bStateRow<Fq>> = None;

            for (bi, row) in trace.rows.iter().enumerate() {
                let state_in = if bi == 0 { iv } else { trace.rows[bi - 1].state_out };
                let this_row = chip.assign_and_constrain_squeeze_block(
                    layouter.namespace(|| format!("squeeze_block_{}", bi)),
                    &state_in,
                    &row.block,
                    &prev_cells,
                    &format!("squeeze_block_{}", bi),
                )?;
                prev_cells = std::array::from_fn(|j| this_row.state_out[j].clone());
                last_assigned = Some(this_row);
            }

            let last_row = last_assigned.expect("trace must have rows");
            let digest = trace.rows.last().expect("trace must have rows").state_out;

            // Derive challenge from the final digest
            let expected = host_challenge(&digest);
            let witness_val = if self.corrupt_challenge {
                expected + Fq::ONE
            } else {
                expected
            };

            let challenge_limb = layouter.assign_region(
                || "challenge_witness",
                |mut region| {
                    config.s_witness.enable(&mut region, 0)?;
                    let cell = region.assign_advice(
                        || "challenge",
                        config.challenge_col,
                        0,
                        || Value::known(witness_val),
                    )?;
                    Ok(Limb { value: Value::known(witness_val), cell: Some(cell.cell()) })
                },
            )?;

            let state_out_arr: [Limb<Fq>; BLAKE2B_STATE_WORDS] = last_row.state_out.try_into().unwrap();
            constrain_challenge_scalar_native(
                &config.compression,
                layouter.namespace(|| "challenge_derivation"),
                &state_out_arr,
                &digest,
                &challenge_limb,
            )
        }
    }

    #[test]
    fn test_vesta_squeeze_challenge_valid() {
        let input = b"The Magic Words are Squeamish Ossifrage".to_vec();
        let circuit = VestaSqueezeTest { input, corrupt_challenge: false };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_vesta_squeeze_challenge_wrong_rejected() {
        let input = b"hello world".to_vec();
        let circuit = VestaSqueezeTest { input, corrupt_challenge: true };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for corrupt challenge");
    }

    #[test]
    fn test_vesta_squeeze_multi_block() {
        let input = vec![0xABu8; 200]; // 200 bytes → 2 Blake2b blocks
        let circuit = VestaSqueezeTest { input, corrupt_challenge: false };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("multi-block verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_vesta_squeeze_multi_block_wrong_rejected() {
        let input = vec![0xCDu8; 200]; // 2 blocks, corrupt challenge
        let circuit = VestaSqueezeTest { input, corrupt_challenge: true };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for multi-block corrupt challenge");
    }
}
