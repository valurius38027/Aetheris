//! Circuit scaffolding for Blake2b transcript compression.
//!
//! This module pins the circuit-visible state/block/round trace shape and binds
//! it to the host/reference Blake2b transcript semantics. It is not yet a sound
//! in-circuit Blake2b compression gadget: wrapping addition, XOR/rotation, and
//! feed-forward are still host-expected consistency checks unless explicitly
//! constrained below.

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::non_native_fq::NonNativeFqConfig;
use crate::transcript_blake2b::BLAKE2B_WORK_WORDS;
use crate::transcript_blake2b::{Blake2bBlockTrace, BLAKE2B_IV, BLAKE2B_STATE_WORDS};
use crate::transcript_blake2b_compression::{
    halo2_blake2b_transcript_initial_state, Blake2bCompressionTrace, Blake2bMixStepTrace,
    Blake2bMixTrace, Blake2bRoundTrace,
};
use crate::transcript_words::{
    AssignedTranscriptWordStream, TranscriptWordChip, TranscriptWordConfig, BLAKE2B_BLOCK_WORDS,
};
use crate::Limb;

#[derive(Clone, Debug)]
pub struct Blake2bCompressionCircuitConfig {
    pub state: [Column<Advice>; BLAKE2B_STATE_WORDS],
    pub message: [Column<Advice>; BLAKE2B_BLOCK_WORDS],
    pub round_message_pair: [Column<Advice>; 2],
    pub work: [Column<Advice>; BLAKE2B_WORK_WORDS],
    pub step_delta: [Column<Advice>; 3],
    pub step_sum: [Column<Advice>; 4],
    pub step_expected: [Column<Advice>; 2],
    pub feed_forward_words: [Column<Advice>; 4],
    pub feed_forward_bits: [Column<Advice>; 5],
    pub rotation_words: [Column<Advice>; 3],
    pub rotation_bits: [Column<Advice>; 4],
    pub metadata: [Column<Fixed>; 3],
    pub round_lane: Column<Advice>,
    pub s_round_placeholder: Selector,
    pub s_initial_work_metadata: Selector,
    pub s_step_delta: Selector,
    pub s_step_sum: Selector,
    pub s_step_expected: Selector,
    pub s_feed_forward_bit: Selector,
    pub s_feed_forward_pack: Selector,
    pub s_rotation_bit: Selector,
    pub s_rotation_pack: Selector,
    pub add_words: [Column<Advice>; 3],
    pub add_bits: [Column<Advice>; 5],
    pub s_add_bit: Selector,
    pub s_add_pack: Selector,
}

#[derive(Clone, Debug)]
pub struct AssignedBlake2bStateRow {
    pub state_in: Vec<Limb>,
    pub state_out: Vec<Limb>,
    pub block_words: Vec<Limb>,
    pub block_index: usize,
}

#[derive(Clone, Debug)]
pub struct AssignedBlake2bRoundRow {
    pub round_index: usize,
    pub message_pair: Vec<Limb>,
    pub work_in: Vec<Limb>,
    pub work_out: Vec<Limb>,
}

#[derive(Clone, Debug)]
pub struct AssignedBlake2bMixRow {
    pub mix_index: usize,
    pub message_pair: Vec<Limb>,
    pub work_in: Vec<Limb>,
    pub work_out: Vec<Limb>,
}

#[derive(Clone, Debug)]
pub struct AssignedBlake2bMixStepRow {
    pub step_index: usize,
    pub work_in: Vec<Limb>,
    pub work_out: Vec<Limb>,
}

#[derive(Clone, Debug)]
pub struct AssignedBlake2bTrace {
    pub rows: Vec<AssignedBlake2bStateRow>,
}

#[derive(Clone)]
pub struct Blake2bCompressionCircuitChip {
    pub compression: Blake2bCompressionCircuitConfig,
    pub words: TranscriptWordChip,
}

impl Blake2bCompressionCircuitChip {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Blake2bCompressionCircuitConfig {
        let state = [0; BLAKE2B_STATE_WORDS].map(|_| meta.advice_column());
        let message = [0; BLAKE2B_BLOCK_WORDS].map(|_| meta.advice_column());
        let round_message_pair = [0; 2].map(|_| meta.advice_column());
        let work = [0; BLAKE2B_WORK_WORDS].map(|_| meta.advice_column());
        let step_delta = [0; 3].map(|_| meta.advice_column());
        let step_sum = [0; 4].map(|_| meta.advice_column());
        let step_expected = [0; 2].map(|_| meta.advice_column());
        let feed_forward_words = [0; 4].map(|_| meta.advice_column());
        let feed_forward_bits = [0; 5].map(|_| meta.advice_column());
        let rotation_words = [0; 3].map(|_| meta.advice_column());
        let rotation_bits = [0; 4].map(|_| meta.advice_column());
        let metadata = [0; 3].map(|_| meta.fixed_column());
        let round_lane = meta.advice_column();
        let s_round_placeholder = meta.selector();
        let s_initial_work_metadata = meta.selector();
        let s_step_delta = meta.selector();
        let s_step_sum = meta.selector();
        let s_step_expected = meta.selector();
        let s_feed_forward_bit = meta.selector();
        let s_feed_forward_pack = meta.selector();
        let s_rotation_bit = meta.selector();
        let s_rotation_pack = meta.selector();
        let add_words = [0; 3].map(|_| meta.advice_column());
        let add_bits = [0; 5].map(|_| meta.advice_column());
        let s_add_bit = meta.selector();
        let s_add_pack = meta.selector();
        state.iter().for_each(|col| meta.enable_equality(*col));
        message.iter().for_each(|col| meta.enable_equality(*col));
        round_message_pair
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        work.iter().for_each(|col| meta.enable_equality(*col));
        step_delta.iter().for_each(|col| meta.enable_equality(*col));
        step_sum.iter().for_each(|col| meta.enable_equality(*col));
        step_expected
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        feed_forward_words
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        feed_forward_bits
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        rotation_words
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        rotation_bits
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        add_words
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        add_bits
            .iter()
            .for_each(|col| meta.enable_equality(*col));
        meta.enable_equality(round_lane);

        // Placeholder gate for the upcoming exact round constraints. For now it
        // pins a stable round-lane row shape without adding false semantics.
        meta.create_gate("blake2b_round_placeholder", |meta| {
            let s = meta.query_selector(s_round_placeholder);
            let lane_cur = meta.query_advice(round_lane, Rotation::cur());
            let lane_next = meta.query_advice(round_lane, Rotation::next());
            vec![s * (lane_cur - lane_next)]
        });

        meta.create_gate("blake2b_initial_work_metadata", |meta| {
            let s = meta.query_selector(s_initial_work_metadata);
            let expected_v12 = meta.query_fixed(metadata[0], Rotation::cur());
            let expected_v13 = meta.query_fixed(metadata[1], Rotation::cur());
            let expected_v14 = meta.query_fixed(metadata[2], Rotation::cur());
            vec![
                s.clone()
                    * (meta.query_advice(work[8], Rotation::cur())
                        - Expression::Constant(Fp::from(BLAKE2B_IV[0]))),
                s.clone()
                    * (meta.query_advice(work[9], Rotation::cur())
                        - Expression::Constant(Fp::from(BLAKE2B_IV[1]))),
                s.clone()
                    * (meta.query_advice(work[10], Rotation::cur())
                        - Expression::Constant(Fp::from(BLAKE2B_IV[2]))),
                s.clone()
                    * (meta.query_advice(work[11], Rotation::cur())
                        - Expression::Constant(Fp::from(BLAKE2B_IV[3]))),
                s.clone() * (meta.query_advice(work[12], Rotation::cur()) - expected_v12),
                s.clone() * (meta.query_advice(work[13], Rotation::cur()) - expected_v13),
                s.clone() * (meta.query_advice(work[14], Rotation::cur()) - expected_v14),
                s * (meta.query_advice(work[15], Rotation::cur())
                    - Expression::Constant(Fp::from(BLAKE2B_IV[7]))),
            ]
        });

        meta.create_gate("blake2b_mix_step_delta", |meta| {
            let s = meta.query_selector(s_step_delta);
            let in_lane = meta.query_advice(step_delta[0], Rotation::cur());
            let out_lane = meta.query_advice(step_delta[1], Rotation::cur());
            let expected_delta = meta.query_advice(step_delta[2], Rotation::cur());
            vec![s * (out_lane - in_lane - expected_delta)]
        });

        meta.create_gate("blake2b_mix_step_sum", |meta| {
            let s = meta.query_selector(s_step_sum);
            let in_lane = meta.query_advice(step_sum[0], Rotation::cur());
            let addend_lane = meta.query_advice(step_sum[1], Rotation::cur());
            let message_word = meta.query_advice(step_sum[2], Rotation::cur());
            let out_lane = meta.query_advice(step_sum[3], Rotation::cur());
            vec![s * (in_lane + addend_lane + message_word - out_lane)]
        });

        meta.create_gate("blake2b_mix_step_expected", |meta| {
            let s = meta.query_selector(s_step_expected);
            let actual = meta.query_advice(step_expected[0], Rotation::cur());
            let expected = meta.query_advice(step_expected[1], Rotation::cur());
            vec![s * (actual - expected)]
        });

        meta.create_gate("blake2b_feed_forward_xor_bit", |meta| {
            let s = meta.query_selector(s_feed_forward_bit);
            let a = meta.query_advice(feed_forward_bits[0], Rotation::cur());
            let b = meta.query_advice(feed_forward_bits[1], Rotation::cur());
            let c = meta.query_advice(feed_forward_bits[2], Rotation::cur());
            let tmp = meta.query_advice(feed_forward_bits[3], Rotation::cur());
            let out = meta.query_advice(feed_forward_bits[4], Rotation::cur());
            let one = Expression::Constant(Fp::ONE);
            let two = Expression::Constant(Fp::from(2));
            vec![
                s.clone() * a.clone() * (a.clone() - one.clone()),
                s.clone() * b.clone() * (b.clone() - one.clone()),
                s.clone() * c.clone() * (c.clone() - one.clone()),
                s.clone() * tmp.clone() * (tmp.clone() - one.clone()),
                s.clone() * out.clone() * (out.clone() - one),
                s.clone() * (tmp.clone() - a.clone() - b.clone() + two.clone() * a * b),
                s * (out - tmp.clone() - c.clone() + two * tmp * c),
            ]
        });

        meta.create_gate("blake2b_feed_forward_pack", |meta| {
            let s = meta.query_selector(s_feed_forward_pack);
            let mut constraints = Vec::with_capacity(4);
            let bit_columns = [0usize, 1, 2, 4];
            for word_idx in 0..4 {
                let mut packed = Expression::Constant(Fp::ZERO);
                for bit_idx in 0..64 {
                    let bit = meta.query_advice(
                        feed_forward_bits[bit_columns[word_idx]],
                        Rotation(bit_idx as i32),
                    );
                    packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_idx));
                }
                let word = meta.query_advice(feed_forward_words[word_idx], Rotation::cur());
                constraints.push(s.clone() * (word - packed));
            }
            constraints
        });

        meta.create_gate("blake2b_rotation_xor_bit", |meta| {
            let s = meta.query_selector(s_rotation_bit);
            let a = meta.query_advice(rotation_bits[0], Rotation::cur());
            let b = meta.query_advice(rotation_bits[1], Rotation::cur());
            let xor = meta.query_advice(rotation_bits[2], Rotation::cur());
            let out = meta.query_advice(rotation_bits[3], Rotation::cur());
            let one = Expression::Constant(Fp::ONE);
            let two = Expression::Constant(Fp::from(2));
            vec![
                s.clone() * a.clone() * (a.clone() - one.clone()),
                s.clone() * b.clone() * (b.clone() - one.clone()),
                s.clone() * xor.clone() * (xor.clone() - one.clone()),
                s.clone() * out.clone() * (out.clone() - one),
                s * (xor - a.clone() - b.clone() + two * a * b),
            ]
        });

        meta.create_gate("blake2b_rotation_pack", |meta| {
            let s = meta.query_selector(s_rotation_pack);
            let mut constraints = Vec::with_capacity(3);
            let bit_columns = [0usize, 1, 3];
            for word_idx in 0..3 {
                let mut packed = Expression::Constant(Fp::ZERO);
                for bit_idx in 0..64 {
                    let bit = meta.query_advice(
                        rotation_bits[bit_columns[word_idx]],
                        Rotation(bit_idx as i32),
                    );
                    packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_idx));
                }
                let word = meta.query_advice(rotation_words[word_idx], Rotation::cur());
                constraints.push(s.clone() * (word - packed));
            }
            constraints
        });

        meta.create_gate("blake2b_wrapping_add_bit", |meta| {
            let s = meta.query_selector(s_add_bit);
            let a_bit = meta.query_advice(add_bits[0], Rotation::cur());
            let b_bit = meta.query_advice(add_bits[1], Rotation::cur());
            let m_bit = meta.query_advice(add_bits[2], Rotation::cur());
            let o_bit = meta.query_advice(add_bits[3], Rotation::cur());
            let carry = meta.query_advice(add_bits[4], Rotation::cur());
            let carry_next = meta.query_advice(add_bits[4], Rotation::next());
            let one = Expression::Constant(Fp::ONE);
            let two = Expression::Constant(Fp::from(2));
            vec![
                s.clone() * a_bit.clone() * (a_bit.clone() - one.clone()),
                s.clone() * b_bit.clone() * (b_bit.clone() - one.clone()),
                s.clone() * m_bit.clone() * (m_bit.clone() - one.clone()),
                s.clone() * o_bit.clone() * (o_bit.clone() - one.clone()),
                s.clone() * carry.clone() * (carry.clone() - one.clone()) * (carry.clone() - two.clone()),
                s * (a_bit + b_bit + m_bit + carry - o_bit - two.clone() * carry_next),
            ]
        });

        meta.create_gate("blake2b_wrapping_add_pack", |meta| {
            let s = meta.query_selector(s_add_pack);
            let mut constraints = Vec::with_capacity(4);
            let word_cols = [0usize, 1, 2];
            let bit_cols = [0usize, 1, 3];
            for pair_idx in 0..3 {
                let mut packed = Expression::Constant(Fp::ZERO);
                for bit_idx in 0..64 {
                    let bit = meta.query_advice(
                        add_bits[bit_cols[pair_idx]],
                        Rotation(bit_idx as i32),
                    );
                    packed = packed + bit * Expression::Constant(Fp::from(1u64 << bit_idx));
                }
                let word = meta.query_advice(add_words[word_cols[pair_idx]], Rotation::cur());
                constraints.push(s.clone() * (word - packed));
            }
            let carry64 = meta.query_advice(add_bits[4], Rotation(64));
            let one = Expression::Constant(Fp::ONE);
            let two = Expression::Constant(Fp::from(2));
            constraints.push(s * carry64.clone() * (carry64.clone() - one) * (carry64 - two));
            constraints
        });

        Blake2bCompressionCircuitConfig {
            state,
            message,
            round_message_pair,
            work,
            step_delta,
            step_sum,
            step_expected,
            feed_forward_words,
            feed_forward_bits,
            rotation_words,
            rotation_bits,
            metadata,
            round_lane,
            s_round_placeholder,
            s_initial_work_metadata,
            s_step_delta,
            s_step_sum,
            s_step_expected,
            s_feed_forward_bit,
            s_feed_forward_pack,
            s_rotation_bit,
            s_rotation_pack,
            add_words,
            add_bits,
            s_add_bit,
            s_add_pack,
        }
    }

    pub fn new(
        compression: Blake2bCompressionCircuitConfig,
        word_config: TranscriptWordConfig,
        fq_config: NonNativeFqConfig,
    ) -> Self {
        Self {
            compression,
            words: TranscriptWordChip::new(word_config, fq_config),
        }
    }

    pub fn assign_word_stream(
        &self,
        layouter: impl Layouter<Fp>,
        stream: &crate::transcript_bytes::TranscriptByteStream,
        label: &str,
    ) -> Result<AssignedTranscriptWordStream, ErrorFront> {
        self.words.assign_stream(layouter, stream, label)
    }

    pub fn assign_state_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        block: &Blake2bBlockTrace,
        state_in: &[u64; BLAKE2B_STATE_WORDS],
        state_out: &[u64; BLAKE2B_STATE_WORDS],
        label: &str,
    ) -> Result<AssignedBlake2bStateRow, ErrorFront> {
        let (state_in_limbs, state_out_limbs, block_word_limbs) = layouter.assign_region(
            || format!("assign_blake2b_state_{}", label),
            |mut region| {
                let mut ins = Vec::with_capacity(BLAKE2B_STATE_WORDS);
                let mut outs = Vec::with_capacity(BLAKE2B_STATE_WORDS);
                let mut block_words = Vec::with_capacity(BLAKE2B_BLOCK_WORDS);

                for i in 0..BLAKE2B_STATE_WORDS {
                    let in_assigned = region.assign_advice(
                        || format!("state_in_{}_{}", label, i),
                        self.compression.state[i],
                        0,
                        || Value::known(Fp::from(state_in[i])),
                    )?;
                    let out_assigned = region.assign_advice(
                        || format!("state_out_{}_{}", label, i),
                        self.compression.state[i],
                        1,
                        || Value::known(Fp::from(state_out[i])),
                    )?;
                    ins.push(Limb {
                        value: Value::known(Fp::from(state_in[i])),
                        cell: Some(in_assigned.cell()),
                    });
                    outs.push(Limb {
                        value: Value::known(Fp::from(state_out[i])),
                        cell: Some(out_assigned.cell()),
                    });
                }

                for i in 0..BLAKE2B_BLOCK_WORDS {
                    let word_assigned = region.assign_advice(
                        || format!("block_word_{}_{}", label, i),
                        self.compression.message[i],
                        0,
                        || Value::known(Fp::from(block.words[i])),
                    )?;
                    block_words.push(Limb {
                        value: Value::known(Fp::from(block.words[i])),
                        cell: Some(word_assigned.cell()),
                    });
                }

                Ok((ins, outs, block_words))
            },
        )?;

        Ok(AssignedBlake2bStateRow {
            state_in: state_in_limbs,
            state_out: state_out_limbs,
            block_words: block_word_limbs,
            block_index: block.meta.block_index,
        })
    }

    pub fn constrain_message_words(
        &self,
        mut layouter: impl Layouter<Fp>,
        assigned_words: &AssignedTranscriptWordStream,
        trace: &AssignedBlake2bTrace,
    ) -> Result<(), ErrorFront> {
        assert_eq!(
            assigned_words.blocks.len(),
            trace.rows.len(),
            "assigned transcript blocks must match compression rows"
        );
        for (block_idx, (assigned_block, trace_row)) in
            assigned_words.blocks.iter().zip(&trace.rows).enumerate()
        {
            assert_eq!(
                assigned_block.words.len(),
                trace_row.block_words.len(),
                "assigned transcript words must match compression block words"
            );
            for word_idx in 0..BLAKE2B_BLOCK_WORDS {
                let transcript_word = &assigned_block.words[word_idx];
                let compression_word = &trace_row.block_words[word_idx];
                if let (Some(transcript_cell), Some(compression_cell)) =
                    (transcript_word.limb.cell, compression_word.cell)
                {
                    layouter.assign_region(
                        || format!("bind_message_block_{}_word_{}", block_idx, word_idx),
                        |mut region| region.constrain_equal(transcript_cell, compression_cell),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn constrain_chaining(
        &self,
        mut layouter: impl Layouter<Fp>,
        trace: &AssignedBlake2bTrace,
    ) -> Result<(), ErrorFront> {
        for i in 0..trace.rows.len().saturating_sub(1) {
            for word_idx in 0..BLAKE2B_STATE_WORDS {
                if let (Some(out_cell), Some(in_cell)) = (
                    trace.rows[i].state_out[word_idx].cell,
                    trace.rows[i + 1].state_in[word_idx].cell,
                ) {
                    layouter.assign_region(
                        || format!("chain_block_{}_word_{}", i, word_idx),
                        |mut region| region.constrain_equal(out_cell, in_cell),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn constrain_initial_state(
        &self,
        mut layouter: impl Layouter<Fp>,
        first_row: &AssignedBlake2bStateRow,
    ) -> Result<(), ErrorFront> {
        let initial_state = halo2_blake2b_transcript_initial_state();

        for (word_idx, expected_word) in initial_state.iter().copied().enumerate() {
            if let Some(state_in_cell) = first_row.state_in[word_idx].cell {
                layouter.assign_region(
                    || format!("bind_initial_state_word_{}", word_idx),
                    |mut region| {
                        self.compression.s_step_expected.enable(&mut region, 0)?;
                        let actual = region.assign_advice(
                            || format!("initial_state_actual_{}", word_idx),
                            self.compression.step_expected[0],
                            0,
                            || first_row.state_in[word_idx].value,
                        )?;
                        region.assign_advice(
                            || format!("initial_state_expected_{}", word_idx),
                            self.compression.step_expected[1],
                            0,
                            || Value::known(Fp::from(expected_word)),
                        )?;
                        region.constrain_equal(state_in_cell, actual.cell())
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_round_chaining(
        &self,
        mut layouter: impl Layouter<Fp>,
        rounds: &[AssignedBlake2bRoundRow],
    ) -> Result<(), ErrorFront> {
        for i in 0..rounds.len().saturating_sub(1) {
            for word_idx in 0..BLAKE2B_WORK_WORDS {
                if let (Some(out_cell), Some(in_cell)) = (
                    rounds[i].work_out[word_idx].cell,
                    rounds[i + 1].work_in[word_idx].cell,
                ) {
                    layouter.assign_region(
                        || format!("chain_round_{}_word_{}", i, word_idx),
                        |mut region| region.constrain_equal(out_cell, in_cell),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn constrain_round_message_pair(
        &self,
        mut layouter: impl Layouter<Fp>,
        state_row: &AssignedBlake2bStateRow,
        round_row: &AssignedBlake2bRoundRow,
        round: &Blake2bRoundTrace,
    ) -> Result<(), ErrorFront> {
        for pair_idx in 0..2 {
            let block_word_idx = round.sigma[pair_idx];
            if let (Some(round_cell), Some(block_cell)) = (
                round_row.message_pair[pair_idx].cell,
                state_row.block_words[block_word_idx].cell,
            ) {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_round_message_block_{}_round_{}_pair_{}",
                            state_row.block_index, round.round_index, pair_idx
                        )
                    },
                    |mut region| region.constrain_equal(round_cell, block_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_mix_message_pair(
        &self,
        mut layouter: impl Layouter<Fp>,
        state_row: &AssignedBlake2bStateRow,
        mix_row: &AssignedBlake2bMixRow,
        mix: &Blake2bMixTrace,
        round_index: usize,
    ) -> Result<(), ErrorFront> {
        for pair_idx in 0..2 {
            let block_word_idx = mix.message_word_indices[pair_idx];
            if let (Some(mix_cell), Some(block_cell)) = (
                mix_row.message_pair[pair_idx].cell,
                state_row.block_words[block_word_idx].cell,
            ) {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_mix_message_block_{}_round_{}_mix_{}_pair_{}",
                            state_row.block_index, round_index, mix.mix_index, pair_idx
                        )
                    },
                    |mut region| region.constrain_equal(mix_cell, block_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_mix_to_round_boundary(
        &self,
        mut layouter: impl Layouter<Fp>,
        round_row: &AssignedBlake2bRoundRow,
        mix_row: &AssignedBlake2bMixRow,
        bind_to_round_in: bool,
    ) -> Result<(), ErrorFront> {
        let round_words = if bind_to_round_in {
            &round_row.work_in
        } else {
            &round_row.work_out
        };
        let mix_words = if bind_to_round_in {
            &mix_row.work_in
        } else {
            &mix_row.work_out
        };
        for word_idx in 0..BLAKE2B_WORK_WORDS {
            if let (Some(round_cell), Some(mix_cell)) =
                (round_words[word_idx].cell, mix_words[word_idx].cell)
            {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_mix_round_boundary_round_{}_mix_{}_word_{}_{}",
                            round_row.round_index,
                            mix_row.mix_index,
                            word_idx,
                            if bind_to_round_in { "in" } else { "out" }
                        )
                    },
                    |mut region| region.constrain_equal(round_cell, mix_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_mix_chaining(
        &self,
        mut layouter: impl Layouter<Fp>,
        mixes: &[AssignedBlake2bMixRow],
    ) -> Result<(), ErrorFront> {
        for i in 0..mixes.len().saturating_sub(1) {
            for word_idx in 0..BLAKE2B_WORK_WORDS {
                if let (Some(out_cell), Some(in_cell)) = (
                    mixes[i].work_out[word_idx].cell,
                    mixes[i + 1].work_in[word_idx].cell,
                ) {
                    layouter.assign_region(
                        || format!("chain_mix_{}_word_{}", i, word_idx),
                        |mut region| region.constrain_equal(out_cell, in_cell),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn constrain_mix_step_chaining(
        &self,
        mut layouter: impl Layouter<Fp>,
        steps: &[AssignedBlake2bMixStepRow],
    ) -> Result<(), ErrorFront> {
        for i in 0..steps.len().saturating_sub(1) {
            for word_idx in 0..BLAKE2B_WORK_WORDS {
                if let (Some(out_cell), Some(in_cell)) = (
                    steps[i].work_out[word_idx].cell,
                    steps[i + 1].work_in[word_idx].cell,
                ) {
                    layouter.assign_region(
                        || format!("chain_mix_step_{}_word_{}", i, word_idx),
                        |mut region| region.constrain_equal(out_cell, in_cell),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn constrain_mix_step_unchanged_lanes(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        for word_idx in 0..BLAKE2B_WORK_WORDS {
            if word_idx == step.updated_lane {
                continue;
            }
            if let (Some(in_cell), Some(out_cell)) = (
                step_row.work_in[word_idx].cell,
                step_row.work_out[word_idx].cell,
            ) {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_mix_step_unchanged_mix_{}_step_{}_word_{}",
                            mix_index, step.step_index, word_idx
                        )
                    },
                    |mut region| region.constrain_equal(in_cell, out_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_mix_step_delta(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
        lane_idx: usize,
    ) -> Result<(), ErrorFront> {
        assert_eq!(
            step.updated_lane, lane_idx,
            "delta constraint must target the updated lane"
        );
        if step_row.work_in[lane_idx].cell.is_some() && step_row.work_out[lane_idx].cell.is_some() {
            let expected_delta =
                Fp::from(step.work_out[lane_idx]) - Fp::from(step.work_in[lane_idx]);
            layouter.assign_region(
                || {
                    format!(
                        "bind_mix_step_delta_mix_{}_step_{}_lane_{}",
                        mix_index, step.step_index, lane_idx
                    )
                },
                |mut region| {
                    self.compression.s_step_delta.enable(&mut region, 0)?;
                    let in_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_delta_in_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_delta[0],
                        0,
                        || step_row.work_in[lane_idx].value,
                    )?;
                    let out_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_delta_out_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_delta[1],
                        0,
                        || step_row.work_out[lane_idx].value,
                    )?;
                    if let Some(source_in) = step_row.work_in[lane_idx].cell {
                        region.constrain_equal(source_in, in_copy.cell())?;
                    }
                    if let Some(source_out) = step_row.work_out[lane_idx].cell {
                        region.constrain_equal(source_out, out_copy.cell())?;
                    }
                    region.assign_advice(
                        || {
                            format!(
                                "mix_step_delta_val_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_delta[2],
                        0,
                        || Value::known(expected_delta),
                    )?;
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn constrain_mix_step_sum(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let Some(addend_lane_idx) = step.addend_lane else {
            return Ok(());
        };
        let Some(message_word_value) = step.message_word_value else {
            return Ok(());
        };
        let lane_idx = step.updated_lane;
        if step_row.work_in[lane_idx].cell.is_some()
            && step_row.work_in[addend_lane_idx].cell.is_some()
            && step_row.work_out[lane_idx].cell.is_some()
        {
            layouter.assign_region(
                || {
                    format!(
                        "bind_mix_step_sum_mix_{}_step_{}_lane_{}",
                        mix_index, step.step_index, lane_idx
                    )
                },
                |mut region| {
                    self.compression.s_step_sum.enable(&mut region, 0)?;
                    let in_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_sum_in_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[0],
                        0,
                        || step_row.work_in[lane_idx].value,
                    )?;
                    let addend_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_sum_addend_{}_{}_{}",
                                mix_index, step.step_index, addend_lane_idx
                            )
                        },
                        self.compression.step_sum[1],
                        0,
                        || step_row.work_in[addend_lane_idx].value,
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "mix_step_sum_message_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[2],
                        0,
                        || Value::known(Fp::from(message_word_value)),
                    )?;
                    let out_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_sum_out_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[3],
                        0,
                        || step_row.work_out[lane_idx].value,
                    )?;
                    if let Some(source_in) = step_row.work_in[lane_idx].cell {
                        region.constrain_equal(source_in, in_copy.cell())?;
                    }
                    if let Some(source_addend) = step_row.work_in[addend_lane_idx].cell {
                        region.constrain_equal(source_addend, addend_copy.cell())?;
                    }
                    if let Some(source_out) = step_row.work_out[lane_idx].cell {
                        region.constrain_equal(source_out, out_copy.cell())?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn constrain_mix_step_add_only(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let Some(addend_lane_idx) = step.addend_lane else {
            return Ok(());
        };
        if step.message_word_value.is_some() {
            return Ok(());
        }
        let lane_idx = step.updated_lane;
        if step_row.work_in[lane_idx].cell.is_some()
            && step_row.work_in[addend_lane_idx].cell.is_some()
            && step_row.work_out[lane_idx].cell.is_some()
        {
            layouter.assign_region(
                || {
                    format!(
                        "bind_mix_step_add_only_mix_{}_step_{}_lane_{}",
                        mix_index, step.step_index, lane_idx
                    )
                },
                |mut region| {
                    self.compression.s_step_sum.enable(&mut region, 0)?;
                    let in_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_add_only_in_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[0],
                        0,
                        || step_row.work_in[lane_idx].value,
                    )?;
                    let addend_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_add_only_addend_{}_{}_{}",
                                mix_index, step.step_index, addend_lane_idx
                            )
                        },
                        self.compression.step_sum[1],
                        0,
                        || step_row.work_in[addend_lane_idx].value,
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "mix_step_add_only_message_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[2],
                        0,
                        || Value::known(Fp::ZERO),
                    )?;
                    let out_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_add_only_out_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_sum[3],
                        0,
                        || step_row.work_out[lane_idx].value,
                    )?;
                    if let Some(source_in) = step_row.work_in[lane_idx].cell {
                        region.constrain_equal(source_in, in_copy.cell())?;
                    }
                    if let Some(source_addend) = step_row.work_in[addend_lane_idx].cell {
                        region.constrain_equal(source_addend, addend_copy.cell())?;
                    }
                    if let Some(source_out) = step_row.work_out[lane_idx].cell {
                        region.constrain_equal(source_out, out_copy.cell())?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn constrain_mix_step_rotation(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let Some(rotation) = step.rotation else {
            return Ok(());
        };
        let expected_rotation = match step.step_index {
            1 => 32,
            3 => 24,
            5 => 16,
            7 => 63,
            _ => panic!("rotation constraint called for non-rotation Blake2b G step"),
        };
        assert_eq!(
            rotation, expected_rotation,
            "rotation constraint must match the Blake2b G-step schedule"
        );
        let lane_idx = step.updated_lane;
        let Some(source_lane_idx) = step.source_lane else {
            return Ok(());
        };
        let xor_input = step.work_in[lane_idx] ^ step.work_in[source_lane_idx];
        let expected = u64::rotate_right(xor_input, rotation);
        if step_row.work_out[lane_idx].cell.is_some() {
            layouter.assign_region(
                || {
                    format!(
                        "bind_mix_step_rotate_mix_{}_step_{}_lane_{}",
                        mix_index, step.step_index, lane_idx
                    )
                },
                |mut region| {
                    self.compression.s_step_expected.enable(&mut region, 0)?;
                    let out_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_rotate_out_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_expected[0],
                        0,
                        || step_row.work_out[lane_idx].value,
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "mix_step_rotate_expected_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_expected[1],
                        0,
                        || Value::known(Fp::from(expected)),
                    )?;
                    if let Some(source_out) = step_row.work_out[lane_idx].cell {
                        region.constrain_equal(source_out, out_copy.cell())?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn constrain_mix_step_rotation_xor_native(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let Some(rotation) = step.rotation else {
            return Ok(());
        };
        let expected_rotation = match step.step_index {
            1 => 32,
            3 => 24,
            5 => 16,
            7 => 63,
            _ => panic!("native rotation constraint called for non-rotation Blake2b G step"),
        };
        assert_eq!(
            rotation, expected_rotation,
            "native rotation constraint must match the Blake2b G-step schedule"
        );
        let lane_idx = step.updated_lane;
        let Some(source_lane_idx) = step.source_lane else {
            return Ok(());
        };
        let rotation = (rotation as usize) % 64;
        let a_word = step.work_in[lane_idx];
        let b_word = step.work_in[source_lane_idx];
        let out_word = step.work_out[lane_idx];

        layouter.assign_region(
            || {
                format!(
                    "bind_mix_step_rotate_xor_native_mix_{}_step_{}_lane_{}",
                    mix_index, step.step_index, lane_idx
                )
            },
            |mut region| {
                self.compression.s_rotation_pack.enable(&mut region, 0)?;
                let words = [a_word, b_word, out_word];
                let source_cells = [
                    step_row.work_in[lane_idx]
                        .cell
                        .expect("rotation input lane must be assigned"),
                    step_row.work_in[source_lane_idx]
                        .cell
                        .expect("rotation source lane must be assigned"),
                    step_row.work_out[lane_idx]
                        .cell
                        .expect("rotation output lane must be assigned"),
                ];

                for (col_idx, word) in words.iter().copied().enumerate() {
                    let assigned = region.assign_advice(
                        || {
                            format!(
                                "mix_step_rotate_word_{}_{}_{}_{}",
                                mix_index, step.step_index, lane_idx, col_idx
                            )
                        },
                        self.compression.rotation_words[col_idx],
                        0,
                        || Value::known(Fp::from(word)),
                    )?;
                    region.constrain_equal(source_cells[col_idx], assigned.cell())?;
                }

                let mut xor_cells = Vec::with_capacity(64);
                let mut out_cells = Vec::with_capacity(64);
                for bit_idx in 0..64 {
                    self.compression
                        .s_rotation_bit
                        .enable(&mut region, bit_idx)?;
                    let a_bit = (a_word >> bit_idx) & 1;
                    let b_bit = (b_word >> bit_idx) & 1;
                    let xor_bit = a_bit ^ b_bit;
                    let out_bit = (out_word >> bit_idx) & 1;
                    let bits = [a_bit, b_bit, xor_bit, out_bit];
                    for (col_idx, bit) in bits.iter().copied().enumerate() {
                        let assigned = region.assign_advice(
                            || {
                                format!(
                                    "mix_step_rotate_bit_{}_{}_{}_{}_{}",
                                    mix_index, step.step_index, lane_idx, col_idx, bit_idx
                                )
                            },
                            self.compression.rotation_bits[col_idx],
                            bit_idx,
                            || Value::known(Fp::from(bit)),
                        )?;
                        if col_idx == 2 {
                            xor_cells.push(assigned.cell());
                        } else if col_idx == 3 {
                            out_cells.push(assigned.cell());
                        }
                    }
                }

                for (out_bit_idx, out_cell) in out_cells.into_iter().enumerate() {
                    let xor_bit_idx = (out_bit_idx + rotation) % 64;
                    region.constrain_equal(out_cell, xor_cells[xor_bit_idx])?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn constrain_mix_step_wrapping_add_native(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let lane_idx = step.updated_lane;
        let Some(addend_lane_idx) = step.addend_lane else {
            return Ok(());
        };
        let message_word_value = step.message_word_value.unwrap_or(0);
        let in_word = step.work_in[lane_idx];
        let addend_word = step.work_in[addend_lane_idx];
        let out_word = step.work_out[lane_idx];

        layouter.assign_region(
            || {
                format!(
                    "wrapping_add_mix_{}_step_{}_lane_{}",
                    mix_index, step.step_index, lane_idx
                )
            },
            |mut region| {
                self.compression.s_add_pack.enable(&mut region, 0)?;
                self.compression.s_add_bit.enable(&mut region, 0)?;

                let words = [in_word, addend_word, out_word];
                let source_cells = [
                    step_row.work_in[lane_idx]
                        .cell
                        .expect("add input lane must be assigned"),
                    step_row.work_in[addend_lane_idx]
                        .cell
                        .expect("add addend lane must be assigned"),
                    step_row.work_out[lane_idx]
                        .cell
                        .expect("add output lane must be assigned"),
                ];

                for (col_idx, word) in words.iter().copied().enumerate() {
                    let assigned = region.assign_advice(
                        || {
                            format!(
                                "add_word_{}_{}_{}_{}",
                                mix_index, step.step_index, lane_idx, col_idx
                            )
                        },
                        self.compression.add_words[col_idx],
                        0,
                        || Value::known(Fp::from(word)),
                    )?;
                    region.constrain_equal(source_cells[col_idx], assigned.cell())?;
                }

                let mut carry_in: u64 = 0;
                for bit_idx in 0..64 {
                    if bit_idx > 0 {
                        self.compression.s_add_bit.enable(&mut region, bit_idx)?;
                    }
                    let a_bit = (in_word >> bit_idx) & 1;
                    let b_bit = (addend_word >> bit_idx) & 1;
                    let m_bit = (message_word_value >> bit_idx) & 1;
                    let sum = a_bit + b_bit + m_bit + carry_in;
                    let o_bit = sum & 1;
                    let carry_out = sum >> 1;
                    let bits = [a_bit, b_bit, m_bit, o_bit, carry_in];
                    for (col_idx, bit) in bits.iter().copied().enumerate() {
                        region.assign_advice(
                            || {
                                format!(
                                    "add_bit_{}_{}_{}_{}_{}",
                                    mix_index, step.step_index, lane_idx, col_idx, bit_idx
                                )
                            },
                            self.compression.add_bits[col_idx],
                            bit_idx,
                            || Value::known(Fp::from(bit)),
                        )?;
                    }
                    carry_in = carry_out;
                }

                region.assign_advice(
                    || {
                        format!(
                            "add_carry_final_{}_{}_{}",
                            mix_index, step.step_index, lane_idx
                        )
                    },
                    self.compression.add_bits[4],
                    64,
                    || Value::known(Fp::from(carry_in)),
                )?;

                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn constrain_mix_step_expected_output(
        &self,
        mut layouter: impl Layouter<Fp>,
        step_row: &AssignedBlake2bMixStepRow,
        step: &Blake2bMixStepTrace,
        mix_index: usize,
    ) -> Result<(), ErrorFront> {
        let lane_idx = step.updated_lane;
        if step_row.work_out[lane_idx].cell.is_some() {
            layouter.assign_region(
                || {
                    format!(
                        "bind_mix_step_expected_output_mix_{}_step_{}_lane_{}",
                        mix_index, step.step_index, lane_idx
                    )
                },
                |mut region| {
                    self.compression.s_step_expected.enable(&mut region, 0)?;
                    let out_copy = region.assign_advice(
                        || {
                            format!(
                                "mix_step_expected_out_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_expected[0],
                        0,
                        || step_row.work_out[lane_idx].value,
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "mix_step_expected_val_{}_{}_{}",
                                mix_index, step.step_index, lane_idx
                            )
                        },
                        self.compression.step_expected[1],
                        0,
                        || Value::known(Fp::from(step.work_out[lane_idx])),
                    )?;
                    if let Some(source_out) = step_row.work_out[lane_idx].cell {
                        region.constrain_equal(source_out, out_copy.cell())?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn constrain_mix_boundary(
        &self,
        mut layouter: impl Layouter<Fp>,
        mix_row: &AssignedBlake2bMixRow,
        step_row: &AssignedBlake2bMixStepRow,
        bind_to_mix_in: bool,
    ) -> Result<(), ErrorFront> {
        let mix_words = if bind_to_mix_in {
            &mix_row.work_in
        } else {
            &mix_row.work_out
        };
        let step_words = if bind_to_mix_in {
            &step_row.work_in
        } else {
            &step_row.work_out
        };
        for word_idx in 0..BLAKE2B_WORK_WORDS {
            if let (Some(mix_cell), Some(step_cell)) =
                (mix_words[word_idx].cell, step_words[word_idx].cell)
            {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_mix_step_boundary_mix_{}_step_{}_word_{}_{}",
                            mix_row.mix_index,
                            step_row.step_index,
                            word_idx,
                            if bind_to_mix_in { "in" } else { "out" }
                        )
                    },
                    |mut region| region.constrain_equal(mix_cell, step_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_initial_round_state(
        &self,
        mut layouter: impl Layouter<Fp>,
        state_row: &AssignedBlake2bStateRow,
        first_round: &AssignedBlake2bRoundRow,
    ) -> Result<(), ErrorFront> {
        for word_idx in 0..BLAKE2B_STATE_WORDS {
            if let (Some(state_cell), Some(work_cell)) = (
                state_row.state_in[word_idx].cell,
                first_round.work_in[word_idx].cell,
            ) {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_initial_round_state_block_{}_word_{}",
                            state_row.block_index, word_idx
                        )
                    },
                    |mut region| region.constrain_equal(state_cell, work_cell),
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_initial_round_metadata(
        &self,
        mut layouter: impl Layouter<Fp>,
        block: &Blake2bBlockTrace,
        first_round: &AssignedBlake2bRoundRow,
        label: &str,
    ) -> Result<(), ErrorFront> {
        let offset_lo = block.meta.offset as u64;
        let offset_hi = (block.meta.offset >> 64) as u64;
        let final_lane = if block.meta.is_final_block {
            !BLAKE2B_IV[6]
        } else {
            BLAKE2B_IV[6]
        };

        layouter.assign_region(
            || format!("initial_round_metadata_{}", label),
            |mut region| {
                self.compression
                    .s_initial_work_metadata
                    .enable(&mut region, 0)?;
                region.assign_fixed(
                    || format!("metadata_v12_{}", label),
                    self.compression.metadata[0],
                    0,
                    || Value::known(Fp::from(BLAKE2B_IV[4] ^ offset_lo)),
                )?;
                region.assign_fixed(
                    || format!("metadata_v13_{}", label),
                    self.compression.metadata[1],
                    0,
                    || Value::known(Fp::from(BLAKE2B_IV[5] ^ offset_hi)),
                )?;
                region.assign_fixed(
                    || format!("metadata_v14_{}", label),
                    self.compression.metadata[2],
                    0,
                    || Value::known(Fp::from(final_lane)),
                )?;

                for lane_idx in 8..=15 {
                    let copied = region.assign_advice(
                        || format!("initial_work_lane_{}_{}", label, lane_idx),
                        self.compression.work[lane_idx],
                        0,
                        || first_round.work_in[lane_idx].value,
                    )?;
                    if let Some(source_cell) = first_round.work_in[lane_idx].cell {
                        region.constrain_equal(source_cell, copied.cell())?;
                    }
                }
                Ok(())
            },
        )
    }

    pub fn constrain_feed_forward_expected(
        &self,
        mut layouter: impl Layouter<Fp>,
        state_row: &AssignedBlake2bStateRow,
        expected_state_out: &[u64; BLAKE2B_STATE_WORDS],
    ) -> Result<(), ErrorFront> {
        for word_idx in 0..BLAKE2B_STATE_WORDS {
            if let Some(state_out_cell) = state_row.state_out[word_idx].cell {
                layouter.assign_region(
                    || {
                        format!(
                            "bind_feed_forward_expected_block_{}_word_{}",
                            state_row.block_index, word_idx
                        )
                    },
                    |mut region| {
                        self.compression.s_step_expected.enable(&mut region, 0)?;
                        let actual = region.assign_advice(
                            || {
                                format!(
                                    "feed_forward_actual_{}_{}",
                                    state_row.block_index, word_idx
                                )
                            },
                            self.compression.step_expected[0],
                            0,
                            || state_row.state_out[word_idx].value,
                        )?;
                        region.assign_advice(
                            || {
                                format!(
                                    "feed_forward_expected_{}_{}",
                                    state_row.block_index, word_idx
                                )
                            },
                            self.compression.step_expected[1],
                            0,
                            || Value::known(Fp::from(expected_state_out[word_idx])),
                        )?;
                        region.constrain_equal(state_out_cell, actual.cell())
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn constrain_feed_forward_xor(
        &self,
        mut layouter: impl Layouter<Fp>,
        state_row: &AssignedBlake2bStateRow,
        final_round: &AssignedBlake2bRoundRow,
        state_in: &[u64; BLAKE2B_STATE_WORDS],
        final_work: &[u64; BLAKE2B_WORK_WORDS],
        state_out: &[u64; BLAKE2B_STATE_WORDS],
    ) -> Result<(), ErrorFront> {
        for word_idx in 0..BLAKE2B_STATE_WORDS {
            let a_word = state_in[word_idx];
            let b_word = final_work[word_idx];
            let c_word = final_work[word_idx + BLAKE2B_STATE_WORDS];
            let out_word = state_out[word_idx];

            layouter.assign_region(
                || {
                    format!(
                        "bind_feed_forward_xor_block_{}_word_{}",
                        state_row.block_index, word_idx
                    )
                },
                |mut region| {
                    self.compression
                        .s_feed_forward_pack
                        .enable(&mut region, 0)?;
                    let words = [a_word, b_word, c_word, out_word];
                    let source_cells = [
                        state_row.state_in[word_idx].cell,
                        final_round.work_out[word_idx].cell,
                        final_round.work_out[word_idx + BLAKE2B_STATE_WORDS].cell,
                        state_row.state_out[word_idx].cell,
                    ];

                    for (col_idx, word) in words.iter().copied().enumerate() {
                        let assigned = region.assign_advice(
                            || {
                                format!(
                                    "feed_forward_word_{}_{}_{}",
                                    state_row.block_index, word_idx, col_idx
                                )
                            },
                            self.compression.feed_forward_words[col_idx],
                            0,
                            || Value::known(Fp::from(word)),
                        )?;
                        if let Some(source_cell) = source_cells[col_idx] {
                            region.constrain_equal(source_cell, assigned.cell())?;
                        }
                    }

                    for bit_idx in 0..64 {
                        self.compression
                            .s_feed_forward_bit
                            .enable(&mut region, bit_idx)?;
                        let a_bit = (a_word >> bit_idx) & 1;
                        let b_bit = (b_word >> bit_idx) & 1;
                        let c_bit = (c_word >> bit_idx) & 1;
                        let tmp_bit = a_bit ^ b_bit;
                        let out_bit = tmp_bit ^ c_bit;
                        let bits = [a_bit, b_bit, c_bit, tmp_bit, out_bit];
                        for (col_idx, bit) in bits.iter().copied().enumerate() {
                            region.assign_advice(
                                || {
                                    format!(
                                        "feed_forward_bit_{}_{}_{}_{}",
                                        state_row.block_index, word_idx, col_idx, bit_idx
                                    )
                                },
                                self.compression.feed_forward_bits[col_idx],
                                bit_idx,
                                || Value::known(Fp::from(bit)),
                            )?;
                        }
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    pub fn assign_trace(
        &self,
        mut layouter: impl Layouter<Fp>,
        compression_trace: &Blake2bCompressionTrace,
        label: &str,
    ) -> Result<AssignedBlake2bTrace, ErrorFront> {
        let mut rows = Vec::with_capacity(compression_trace.rows.len());
        for (i, row) in compression_trace.rows.iter().enumerate() {
            rows.push(self.assign_state_row(
                layouter.namespace(|| format!("{}_row_{}", label, i)),
                &row.block,
                &row.state_in,
                &row.state_out,
                &format!("{}_row_{}", label, i),
            )?);
        }
        Ok(AssignedBlake2bTrace { rows })
    }

    pub fn assign_round_placeholder(
        &self,
        mut layouter: impl Layouter<Fp>,
        block_index: usize,
        label: &str,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || format!("assign_round_placeholder_{}", label),
            |mut region| {
                self.compression
                    .s_round_placeholder
                    .enable(&mut region, 0)?;
                let lane = Fp::from(block_index as u64);
                region.assign_advice(
                    || format!("round_lane_cur_{}", label),
                    self.compression.round_lane,
                    0,
                    || Value::known(lane),
                )?;
                region.assign_advice(
                    || format!("round_lane_next_{}", label),
                    self.compression.round_lane,
                    1,
                    || Value::known(lane),
                )?;
                Ok(())
            },
        )
    }

    pub fn assign_round_trace_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        block: &Blake2bBlockTrace,
        round: &Blake2bRoundTrace,
        label: &str,
    ) -> Result<AssignedBlake2bRoundRow, ErrorFront> {
        let (message_pair, work_in, work_out) = layouter.assign_region(
            || format!("assign_blake2b_round_{}", label),
            |mut region| {
                let mut pair = Vec::with_capacity(2);
                let mut ins = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                let mut outs = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                for i in 0..2 {
                    let selected_word = block.words[round.sigma[i]];
                    let assigned = region.assign_advice(
                        || format!("round_message_pair_{}_{}", label, i),
                        self.compression.round_message_pair[i],
                        0,
                        || Value::known(Fp::from(selected_word)),
                    )?;
                    pair.push(Limb {
                        value: Value::known(Fp::from(selected_word)),
                        cell: Some(assigned.cell()),
                    });
                }
                for i in 0..BLAKE2B_WORK_WORDS {
                    let in_assigned = region.assign_advice(
                        || format!("work_in_{}_{}", label, i),
                        self.compression.work[i],
                        0,
                        || Value::known(Fp::from(round.work_in[i])),
                    )?;
                    let out_assigned = region.assign_advice(
                        || format!("work_out_{}_{}", label, i),
                        self.compression.work[i],
                        1,
                        || Value::known(Fp::from(round.work_out[i])),
                    )?;
                    ins.push(Limb {
                        value: Value::known(Fp::from(round.work_in[i])),
                        cell: Some(in_assigned.cell()),
                    });
                    outs.push(Limb {
                        value: Value::known(Fp::from(round.work_out[i])),
                        cell: Some(out_assigned.cell()),
                    });
                }
                Ok((pair, ins, outs))
            },
        )?;

        Ok(AssignedBlake2bRoundRow {
            round_index: round.round_index,
            message_pair,
            work_in,
            work_out,
        })
    }

    pub fn assign_mix_trace_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        mix: &Blake2bMixTrace,
        label: &str,
    ) -> Result<AssignedBlake2bMixRow, ErrorFront> {
        let (message_pair, work_in, work_out) = layouter.assign_region(
            || format!("assign_blake2b_mix_{}", label),
            |mut region| {
                let mut pair = Vec::with_capacity(2);
                let mut ins = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                let mut outs = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                for i in 0..2 {
                    let assigned = region.assign_advice(
                        || format!("mix_message_pair_{}_{}", label, i),
                        self.compression.round_message_pair[i],
                        0,
                        || Value::known(Fp::from(mix.message_word_values[i])),
                    )?;
                    pair.push(Limb {
                        value: Value::known(Fp::from(mix.message_word_values[i])),
                        cell: Some(assigned.cell()),
                    });
                }
                for i in 0..BLAKE2B_WORK_WORDS {
                    let in_assigned = region.assign_advice(
                        || format!("mix_work_in_{}_{}", label, i),
                        self.compression.work[i],
                        0,
                        || Value::known(Fp::from(mix.work_in[i])),
                    )?;
                    let out_assigned = region.assign_advice(
                        || format!("mix_work_out_{}_{}", label, i),
                        self.compression.work[i],
                        1,
                        || Value::known(Fp::from(mix.work_out[i])),
                    )?;
                    ins.push(Limb {
                        value: Value::known(Fp::from(mix.work_in[i])),
                        cell: Some(in_assigned.cell()),
                    });
                    outs.push(Limb {
                        value: Value::known(Fp::from(mix.work_out[i])),
                        cell: Some(out_assigned.cell()),
                    });
                }
                Ok((pair, ins, outs))
            },
        )?;

        Ok(AssignedBlake2bMixRow {
            mix_index: mix.mix_index,
            message_pair,
            work_in,
            work_out,
        })
    }

    pub fn assign_mix_step_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        step: &Blake2bMixStepTrace,
        label: &str,
    ) -> Result<AssignedBlake2bMixStepRow, ErrorFront> {
        let (work_in, work_out) = layouter.assign_region(
            || format!("assign_blake2b_mix_step_{}", label),
            |mut region| {
                let mut ins = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                let mut outs = Vec::with_capacity(BLAKE2B_WORK_WORDS);
                for i in 0..BLAKE2B_WORK_WORDS {
                    let in_assigned = region.assign_advice(
                        || format!("mix_step_in_{}_{}", label, i),
                        self.compression.work[i],
                        0,
                        || Value::known(Fp::from(step.work_in[i])),
                    )?;
                    let out_assigned = region.assign_advice(
                        || format!("mix_step_out_{}_{}", label, i),
                        self.compression.work[i],
                        1,
                        || Value::known(Fp::from(step.work_out[i])),
                    )?;
                    ins.push(Limb {
                        value: Value::known(Fp::from(step.work_in[i])),
                        cell: Some(in_assigned.cell()),
                    });
                    outs.push(Limb {
                        value: Value::known(Fp::from(step.work_out[i])),
                        cell: Some(out_assigned.cell()),
                    });
                }
                Ok((ins, outs))
            },
        )?;

        Ok(AssignedBlake2bMixStepRow {
            step_index: step.step_index,
            work_in,
            work_out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::non_native_fq::NonNativeFqChip;
    use crate::transcript_blake2b_compression::blake2b_compression_trace_skeleton;
    use crate::transcript_bytes::TranscriptByteStream;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    };

    #[derive(Clone, Debug)]
    struct Blake2bCircuitTestConfig {
        fq: NonNativeFqConfig,
        words: TranscriptWordConfig,
        compression: Blake2bCompressionCircuitConfig,
    }

    #[derive(Default)]
    struct Blake2bCircuit {
        bytes: Vec<u8>,
        corrupt_first_trace_word: bool,
        corrupt_first_round_state_binding: bool,
        corrupt_first_round_metadata_binding: Option<usize>,
        corrupt_first_round_message_pair: bool,
        corrupt_first_mix_message_pair: bool,
        corrupt_first_mix_step_chain: bool,
        corrupt_first_mix_step_unchanged_lane: bool,
        corrupt_first_mix_step_delta: bool,
        corrupt_first_mix_step_sum: bool,
        corrupt_first_mix_step_add_only: bool,
        corrupt_first_mix_step_rotation32: bool,
        corrupt_first_mix_step_rotation24: bool,
        corrupt_first_mix_step_sum_second_half: bool,
        corrupt_first_mix_step_add_only_second_half: bool,
        corrupt_first_mix_step_rotation16: bool,
        corrupt_first_mix_step_rotation63: bool,
        corrupt_first_feed_forward_state_out: bool,
    }

    impl Circuit<Fp> for Blake2bCircuit {
        type Config = Blake2bCircuitTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                bytes: vec![0; self.bytes.len()],
                corrupt_first_trace_word: self.corrupt_first_trace_word,
                corrupt_first_round_state_binding: self.corrupt_first_round_state_binding,
                corrupt_first_round_metadata_binding: self.corrupt_first_round_metadata_binding,
                corrupt_first_round_message_pair: self.corrupt_first_round_message_pair,
                corrupt_first_mix_message_pair: self.corrupt_first_mix_message_pair,
                corrupt_first_mix_step_chain: self.corrupt_first_mix_step_chain,
                corrupt_first_mix_step_unchanged_lane: self.corrupt_first_mix_step_unchanged_lane,
                corrupt_first_mix_step_delta: self.corrupt_first_mix_step_delta,
                corrupt_first_mix_step_sum: self.corrupt_first_mix_step_sum,
                corrupt_first_mix_step_add_only: self.corrupt_first_mix_step_add_only,
                corrupt_first_mix_step_rotation32: self.corrupt_first_mix_step_rotation32,
                corrupt_first_mix_step_rotation24: self.corrupt_first_mix_step_rotation24,
                corrupt_first_mix_step_sum_second_half: self.corrupt_first_mix_step_sum_second_half,
                corrupt_first_mix_step_add_only_second_half: self
                    .corrupt_first_mix_step_add_only_second_half,
                corrupt_first_mix_step_rotation16: self.corrupt_first_mix_step_rotation16,
                corrupt_first_mix_step_rotation63: self.corrupt_first_mix_step_rotation63,
                corrupt_first_feed_forward_state_out: self.corrupt_first_feed_forward_state_out,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Blake2bCircuitTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
                compression: Blake2bCompressionCircuitChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip =
                Blake2bCompressionCircuitChip::new(config.compression, config.words, config.fq);
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(&self.bytes);
            let assigned_words =
                chip.assign_word_stream(layouter.namespace(|| "words"), &stream, "words")?;
            let reference_trace = blake2b_compression_trace_skeleton(&stream);
            let mut trace = reference_trace.clone();

            if self.corrupt_first_trace_word {
                trace.rows[0].block.words[0] = trace.rows[0].block.words[0].wrapping_add(1);
            }
            if self.corrupt_first_round_state_binding {
                trace.rows[0].state_in[7] = trace.rows[0].state_in[7].wrapping_add(1);
                trace.rows[0].rounds[0].work_in[7] =
                    trace.rows[0].rounds[0].work_in[7].wrapping_add(1);
            }
            if let Some(lane_idx) = self.corrupt_first_round_metadata_binding {
                trace.rows[0].rounds[0].work_in[lane_idx] =
                    trace.rows[0].rounds[0].work_in[lane_idx].wrapping_add(1);
            }
            if self.corrupt_first_feed_forward_state_out {
                trace.rows[0].state_out[0] = trace.rows[0].state_out[0].wrapping_add(1);
            }

            assert_eq!(assigned_words.blocks.len(), trace.rows.len());
            let assigned_trace =
                chip.assign_trace(layouter.namespace(|| "trace"), &trace, "trace")?;
            chip.constrain_message_words(
                layouter.namespace(|| "message_word_bindings"),
                &assigned_words,
                &assigned_trace,
            )?;
            for (i, assigned) in assigned_trace.rows.iter().enumerate() {
                assert_eq!(assigned.block_index, i);
                assert_eq!(assigned.state_in.len(), BLAKE2B_STATE_WORDS);
                assert_eq!(assigned.state_out.len(), BLAKE2B_STATE_WORDS);
                assert_eq!(assigned.block_words.len(), BLAKE2B_BLOCK_WORDS);
                if i == 0 {
                    chip.constrain_initial_state(layouter.namespace(|| "initial_state"), assigned)?;
                }
                chip.assign_round_placeholder(
                    layouter.namespace(|| format!("placeholder_{}", i)),
                    i,
                    &format!("placeholder_{}", i),
                )?;
                let mut assigned_rounds = Vec::new();
                for round in &trace.rows[i].rounds {
                    let corrupted_block = if self.corrupt_first_round_message_pair
                        && i == 0
                        && round.round_index == 0
                    {
                        let mut block = trace.rows[i].block.clone();
                        block.words[round.sigma[0]] = block.words[round.sigma[0]].wrapping_add(1);
                        Some(block)
                    } else {
                        None
                    };
                    let round_block = corrupted_block.as_ref().unwrap_or(&trace.rows[i].block);
                    let assigned_round = chip.assign_round_trace_row(
                        layouter.namespace(|| format!("round_{}_{}", i, round.round_index)),
                        round_block,
                        round,
                        &format!("round_{}_{}", i, round.round_index),
                    )?;
                    assert_eq!(assigned_round.round_index, round.round_index);
                    assert_eq!(assigned_round.message_pair.len(), 2);
                    assert_eq!(assigned_round.work_in.len(), BLAKE2B_WORK_WORDS);
                    assert_eq!(assigned_round.work_out.len(), BLAKE2B_WORK_WORDS);
                    chip.constrain_round_message_pair(
                        layouter.namespace(|| {
                            format!("round_message_pair_{}_{}", i, round.round_index)
                        }),
                        assigned,
                        &assigned_round,
                        round,
                    )?;
                    {
                        let mut assigned_mixes = Vec::new();
                        for mix in &round.mixes {
                            let corrupted_mix = if self.corrupt_first_mix_message_pair
                                && i == 0
                                && round.round_index == 0
                                && mix.mix_index == 0
                            {
                                let mut mix_override = mix.clone();
                                mix_override.message_word_values[0] =
                                    mix_override.message_word_values[0].wrapping_add(1);
                                Some(mix_override)
                            } else {
                                None
                            };
                            let mix_trace = corrupted_mix.as_ref().unwrap_or(mix);
                            let assigned_mix = chip.assign_mix_trace_row(
                                layouter.namespace(|| format!("mix_0_0_{}", mix.mix_index)),
                                mix_trace,
                                &format!("mix_0_0_{}", mix.mix_index),
                            )?;
                            chip.constrain_mix_message_pair(
                                layouter.namespace(|| {
                                    format!("mix_message_pair_0_0_{}", mix.mix_index)
                                }),
                                assigned,
                                &assigned_mix,
                                mix,
                                round.round_index,
                            )?;
                            assigned_mixes.push(assigned_mix);
                        }
                        chip.constrain_mix_to_round_boundary(
                            layouter.namespace(|| "mix_round_in_0_0_0"),
                            &assigned_round,
                            &assigned_mixes[0],
                            true,
                        )?;
                        chip.constrain_mix_to_round_boundary(
                            layouter.namespace(|| "mix_round_out_0_0_7"),
                            &assigned_round,
                            assigned_mixes.last().expect("round must have mixes"),
                            false,
                        )?;
                        chip.constrain_mix_chaining(
                            layouter.namespace(|| "mix_chain_0_0"),
                            &assigned_mixes,
                        )?;

                        for (mix, assigned_mix) in round.mixes.iter().zip(&assigned_mixes) {
                            let mut assigned_steps = Vec::new();
                            for step in &mix.steps {
                                let mut step_override = step.clone();
                                if i == 0 && round.round_index == 0 && mix.mix_index == 0 {
                                    if self.corrupt_first_mix_step_chain && step.step_index == 1 {
                                        step_override.work_in[0] =
                                            step_override.work_in[0].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_unchanged_lane
                                        && step.step_index == 0
                                    {
                                        step_override.work_out[1] =
                                            step_override.work_out[1].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_delta && step.step_index == 0 {
                                        step_override.work_out[0] =
                                            step_override.work_out[0].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_sum && step.step_index == 0 {
                                        step_override.work_out[0] =
                                            step_override.work_out[0].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_add_only && step.step_index == 2
                                    {
                                        step_override.work_out[8] =
                                            step_override.work_out[8].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_rotation32
                                        && step.step_index == 1
                                    {
                                        step_override.work_out[12] =
                                            step_override.work_out[12].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_rotation24
                                        && step.step_index == 3
                                    {
                                        step_override.work_out[4] =
                                            step_override.work_out[4].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_sum_second_half
                                        && step.step_index == 4
                                    {
                                        step_override.work_out[0] =
                                            step_override.work_out[0].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_rotation16
                                        && step.step_index == 5
                                    {
                                        step_override.work_out[12] =
                                            step_override.work_out[12].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_add_only_second_half
                                        && step.step_index == 6
                                    {
                                        step_override.work_out[8] =
                                            step_override.work_out[8].wrapping_add(1);
                                    }
                                    if self.corrupt_first_mix_step_rotation63
                                        && step.step_index == 7
                                    {
                                        step_override.work_out[4] =
                                            step_override.work_out[4].wrapping_add(1);
                                    }
                                }
                                assigned_steps.push(chip.assign_mix_step_row(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_0_0_{}_{}",
                                            mix.mix_index, step.step_index
                                        )
                                    }),
                                    &step_override,
                                    &format!("mix_step_0_0_{}_{}", mix.mix_index, step.step_index),
                                )?);
                            }
                            chip.constrain_mix_boundary(
                                layouter.namespace(|| {
                                    format!("mix_step_boundary_in_0_0_{}", mix.mix_index)
                                }),
                                assigned_mix,
                                &assigned_steps[0],
                                true,
                            )?;
                            chip.constrain_mix_boundary(
                                layouter.namespace(|| {
                                    format!("mix_step_boundary_out_0_0_{}", mix.mix_index)
                                }),
                                assigned_mix,
                                assigned_steps.last().expect("mix must have steps"),
                                false,
                            )?;
                            chip.constrain_mix_step_chaining(
                                layouter
                                    .namespace(|| format!("mix_step_chain_0_0_{}", mix.mix_index)),
                                &assigned_steps,
                            )?;
                            for (assigned_step, step) in assigned_steps.iter().zip(&mix.steps) {
                                chip.constrain_mix_step_unchanged_lanes(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_unchanged_{}_{}_{}",
                                            round.round_index, mix.mix_index, step.step_index
                                        )
                                    }),
                                    assigned_step,
                                    step,
                                    mix.mix_index,
                                )?;
                                chip.constrain_mix_step_expected_output(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_expected_{}_{}_{}",
                                            round.round_index, mix.mix_index, step.step_index
                                        )
                                    }),
                                    assigned_step,
                                    step,
                                    mix.mix_index,
                                )?;
                                if step.rotation.is_some() {
                                    chip.constrain_mix_step_rotation(
                                        layouter.namespace(|| {
                                            format!(
                                                "mix_step_rotate_{}_{}_{}",
                                                round.round_index, mix.mix_index, step.step_index
                                            )
                                        }),
                                        assigned_step,
                                        step,
                                        mix.mix_index,
                                    )?;
                                    if round.round_index == 0 && mix.mix_index == 0 {
                                        chip.constrain_mix_step_rotation_xor_native(
                                            layouter.namespace(|| {
                                                format!(
                                                    "mix_step_rotate_native_{}_{}_{}",
                                                    round.round_index,
                                                    mix.mix_index,
                                                    step.step_index
                                                )
                                            }),
                                            assigned_step,
                                            step,
                                            mix.mix_index,
                                        )?;
                                    }
                                }
                                if step.addend_lane.is_some() && round.round_index == 0 && mix.mix_index == 0 {
                                    chip.constrain_mix_step_wrapping_add_native(
                                        layouter.namespace(|| {
                                            format!(
                                                "mix_step_wrapping_add_native_{}_{}_{}",
                                                round.round_index,
                                                mix.mix_index,
                                                step.step_index
                                            )
                                        }),
                                        assigned_step,
                                        step,
                                        mix.mix_index,
                                    )?;
                                }
                            }
                            if round.round_index == 0 && mix.mix_index == 0 {
                                chip.constrain_mix_step_delta(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_delta_{}_{}_0",
                                            round.round_index, mix.mix_index
                                        )
                                    }),
                                    &assigned_steps[0],
                                    &mix.steps[0],
                                    mix.mix_index,
                                    mix.steps[0].updated_lane,
                                )?;
                                chip.constrain_mix_step_sum(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_sum_{}_{}_0",
                                            round.round_index, mix.mix_index
                                        )
                                    }),
                                    &assigned_steps[0],
                                    &mix.steps[0],
                                    mix.mix_index,
                                )?;
                                chip.constrain_mix_step_add_only(
                                    layouter.namespace(|| {
                                        format!(
                                            "mix_step_add_only_{}_{}_2",
                                            round.round_index, mix.mix_index
                                        )
                                    }),
                                    &assigned_steps[2],
                                    &mix.steps[2],
                                    mix.mix_index,
                                )?;
                            }
                        }
                    }
                    assigned_rounds.push(assigned_round);
                }
                chip.constrain_initial_round_state(
                    layouter.namespace(|| format!("initial_round_state_{}", i)),
                    assigned,
                    &assigned_rounds[0],
                )?;
                chip.constrain_initial_round_metadata(
                    layouter.namespace(|| format!("initial_round_metadata_{}", i)),
                    &trace.rows[i].block,
                    &assigned_rounds[0],
                    &format!("initial_round_metadata_{}", i),
                )?;
                chip.constrain_feed_forward_xor(
                    layouter.namespace(|| format!("feed_forward_xor_{}", i)),
                    assigned,
                    assigned_rounds.last().expect("block must have rounds"),
                    &trace.rows[i].state_in,
                    &trace.rows[i]
                        .rounds
                        .last()
                        .expect("block trace must have rounds")
                        .work_out,
                    &trace.rows[i].state_out,
                )?;
                chip.constrain_round_chaining(
                    layouter.namespace(|| format!("round_chain_{}", i)),
                    &assigned_rounds,
                )?;
            }
            chip.constrain_chaining(layouter.namespace(|| "chain"), &assigned_trace)?;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FeedForwardCircuit {
        bytes: Vec<u8>,
        corrupt_final_work: bool,
    }

    impl Circuit<Fp> for FeedForwardCircuit {
        type Config = Blake2bCircuitTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                bytes: vec![0; self.bytes.len()],
                corrupt_final_work: self.corrupt_final_work,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Blake2bCircuitTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
                compression: Blake2bCompressionCircuitChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip =
                Blake2bCompressionCircuitChip::new(config.compression, config.words, config.fq);
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(&self.bytes);
            let mut trace = blake2b_compression_trace_skeleton(&stream);
            let row = trace
                .rows
                .first_mut()
                .expect("trace must have at least one row");
            if self.corrupt_final_work {
                let final_work = row
                    .rounds
                    .last()
                    .expect("trace row must have rounds")
                    .work_out[0];
                row.rounds
                    .last_mut()
                    .expect("trace row must have rounds")
                    .work_out[0] = final_work.wrapping_add(1);
            }

            let assigned_state = chip.assign_state_row(
                layouter.namespace(|| "feed_forward_state"),
                &row.block,
                &row.state_in,
                &row.state_out,
                "feed_forward_state",
            )?;
            let final_round = row.rounds.last().expect("trace row must have rounds");
            let assigned_final_round = chip.assign_round_trace_row(
                layouter.namespace(|| "feed_forward_final_round"),
                &row.block,
                final_round,
                "feed_forward_final_round",
            )?;
            chip.constrain_feed_forward_xor(
                layouter.namespace(|| "feed_forward_xor"),
                &assigned_state,
                &assigned_final_round,
                &row.state_in,
                &final_round.work_out,
                &row.state_out,
            )
        }
    }

    #[derive(Default)]
    struct RotationXorCircuit {
        rotation: u32,
        corrupt_output: bool,
        corrupt_updated_input: bool,
        corrupt_source_input: bool,
        wrong_rotation_output: Option<u32>,
    }

    impl Circuit<Fp> for RotationXorCircuit {
        type Config = Blake2bCircuitTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                rotation: self.rotation,
                corrupt_output: self.corrupt_output,
                corrupt_updated_input: self.corrupt_updated_input,
                corrupt_source_input: self.corrupt_source_input,
                wrong_rotation_output: self.wrong_rotation_output,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Blake2bCircuitTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
                compression: Blake2bCompressionCircuitChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip =
                Blake2bCompressionCircuitChip::new(config.compression, config.words, config.fq);
            let updated_lane = 12usize;
            let source_lane = 0usize;
            let updated_input = 0x0123_4567_89ab_cdefu64;
            let source_input = 0x0f1e_2d3c_4b5a_6978u64;
            let mut work_in = [0u64; BLAKE2B_WORK_WORDS];
            let mut work_out = work_in;
            work_in[updated_lane] = updated_input;
            work_in[source_lane] = source_input;

            let output_rotation = self.wrong_rotation_output.unwrap_or(self.rotation);
            work_out[updated_lane] = (updated_input ^ source_input).rotate_right(output_rotation);
            if self.corrupt_output {
                work_out[updated_lane] ^= 1;
            }
            if self.corrupt_updated_input {
                work_in[updated_lane] ^= 1;
            }
            if self.corrupt_source_input {
                work_in[source_lane] ^= 1;
            }
            let step_index = match self.rotation {
                32 => 1,
                24 => 3,
                16 => 5,
                63 => 7,
                _ => panic!("test rotation must be one of the Blake2b G rotations"),
            };

            let step = Blake2bMixStepTrace {
                step_index,
                updated_lane,
                source_lane: Some(source_lane),
                addend_lane: None,
                message_word_value: None,
                rotation: Some(self.rotation),
                work_in,
                work_out,
            };
            let assigned_step = chip.assign_mix_step_row(
                layouter.namespace(|| "rotation_xor_step"),
                &step,
                "rotation_xor_step",
            )?;
            chip.constrain_mix_step_rotation_xor_native(
                layouter.namespace(|| "rotation_xor_native"),
                &assigned_step,
                &step,
                0,
            )
        }
    }

    #[derive(Default)]
    struct WrappingAddCircuit {
        corrupt_output: bool,
        corrupt_input: bool,
        corrupt_addend: bool,
        corrupt_message: bool,
    }

    impl Circuit<Fp> for WrappingAddCircuit {
        type Config = Blake2bCircuitTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                corrupt_output: self.corrupt_output,
                corrupt_input: self.corrupt_input,
                corrupt_addend: self.corrupt_addend,
                corrupt_message: self.corrupt_message,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Blake2bCircuitTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
                compression: Blake2bCompressionCircuitChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip =
                Blake2bCompressionCircuitChip::new(config.compression, config.words, config.fq);
            let updated_lane = 0usize;
            let addend_lane = 4usize;
            let input_val = 0xFFFF_FFFF_FFFF_FFFEu64;
            let addend_val = 0x0000_0000_0000_0003u64;
            let msg_val = 0x0000_0000_0000_0001u64;
            let mut work_in = [0u64; BLAKE2B_WORK_WORDS];
            let mut work_out = work_in;
            work_in[updated_lane] = input_val;
            work_in[addend_lane] = addend_val;

            let msg = if self.corrupt_message {
                msg_val.wrapping_add(1)
            } else {
                msg_val
            };
            let (in_v, addend_v, out_v) = if self.corrupt_output {
                (input_val, addend_val, input_val.wrapping_add(addend_val).wrapping_add(msg).wrapping_add(1))
            } else if self.corrupt_input {
                (input_val.wrapping_add(1), addend_val, input_val.wrapping_add(addend_val).wrapping_add(msg_val))
            } else if self.corrupt_addend {
                (input_val, addend_val.wrapping_add(1), input_val.wrapping_add(addend_val).wrapping_add(msg_val))
            } else if self.corrupt_message {
                (input_val, addend_val, input_val.wrapping_add(addend_val).wrapping_add(msg_val))
            } else {
                (input_val, addend_val, input_val.wrapping_add(addend_val).wrapping_add(msg))
            };
            work_out[updated_lane] = out_v;
            work_in[updated_lane] = in_v;
            work_in[addend_lane] = addend_v;

            let step = Blake2bMixStepTrace {
                step_index: 0,
                updated_lane,
                source_lane: None,
                addend_lane: Some(addend_lane),
                message_word_value: Some(msg),
                rotation: None,
                work_in,
                work_out,
            };
            let assigned_step = chip.assign_mix_step_row(
                layouter.namespace(|| "wrapping_add_step"),
                &step,
                "wrapping_add_step",
            )?;
            chip.constrain_mix_step_wrapping_add_native(
                layouter.namespace(|| "wrapping_add_native"),
                &assigned_step,
                &step,
                0,
            )
        }
    }

    #[test]
    fn blake2b_circuit_wrapping_add_accepts_valid() {
        let circuit = WrappingAddCircuit {
            corrupt_output: false,
            corrupt_input: false,
            corrupt_addend: false,
            corrupt_message: false,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }

    #[test]
    fn blake2b_circuit_wrapping_add_rejects_wrong_output() {
        let circuit = WrappingAddCircuit {
            corrupt_output: true,
            corrupt_input: false,
            corrupt_addend: false,
            corrupt_message: false,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native wrapping add must reject a wrong output word"
        );
    }

    #[test]
    fn blake2b_circuit_wrapping_add_rejects_wrong_input() {
        let circuit = WrappingAddCircuit {
            corrupt_output: false,
            corrupt_input: true,
            corrupt_addend: false,
            corrupt_message: false,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native wrapping add must reject a wrong input word"
        );
    }

    #[test]
    fn blake2b_circuit_wrapping_add_rejects_wrong_addend() {
        let circuit = WrappingAddCircuit {
            corrupt_output: false,
            corrupt_input: false,
            corrupt_addend: true,
            corrupt_message: false,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native wrapping add must reject a wrong addend word"
        );
    }

    #[test]
    fn blake2b_circuit_wrapping_add_rejects_wrong_message() {
        let circuit = WrappingAddCircuit {
            corrupt_output: false,
            corrupt_input: false,
            corrupt_addend: false,
            corrupt_message: true,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native wrapping add must reject a wrong message word"
        );
    }

    #[test]
    fn blake2b_circuit_wrapping_add_carry_two() {
        #[derive(Default)]
        struct CarryTwoCircuit;

        impl Circuit<Fp> for CarryTwoCircuit {
            type Config = Blake2bCircuitTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                Blake2bCircuitTestConfig {
                    fq: NonNativeFqChip::configure(meta),
                    words: TranscriptWordChip::configure(meta),
                    compression: Blake2bCompressionCircuitChip::configure(meta),
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                // Three all-ones operands force carry=2 at bit 1+:
                //   bit 0: 1+1+1+0=3 → o=1, carry=1
                //   bit 1: 1+1+1+1=4 → o=0, carry=2
                //   bit 2+: 1+1+1+2=5 → o=1, carry=2 (final carry=2)
                let input_val = 0xFFFF_FFFF_FFFF_FFFFu64;
                let addend_val = 0xFFFF_FFFF_FFFF_FFFFu64;
                let msg_val = 0xFFFF_FFFF_FFFF_FFFFu64;
                let out_val = input_val.wrapping_add(addend_val).wrapping_add(msg_val);

                let chip = Blake2bCompressionCircuitChip::new(
                    config.compression,
                    config.words,
                    config.fq,
                );
                let mut work_in = [0u64; BLAKE2B_WORK_WORDS];
                let mut work_out = work_in;
                work_in[0] = input_val;
                work_in[4] = addend_val;
                work_out[0] = out_val;

                let step = Blake2bMixStepTrace {
                    step_index: 0,
                    updated_lane: 0,
                    source_lane: None,
                    addend_lane: Some(4),
                    message_word_value: Some(msg_val),
                    rotation: None,
                    work_in,
                    work_out,
                };
                let assigned_step = chip.assign_mix_step_row(
                    layouter.namespace(|| "carry_two_step"),
                    &step,
                    "carry_two_step",
                )?;
                chip.constrain_mix_step_wrapping_add_native(
                    layouter.namespace(|| "carry_two_native"),
                    &assigned_step,
                    &step,
                    0,
                )
            }
        }

        let circuit = CarryTwoCircuit;
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();

        // Also verify the constraint rejects a wrong output in carry=2 regime
        let reject = CarryTwoCircuitReject;
        let prover = MockProver::run(10, &reject, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native wrapping add must reject wrong output with carry=2"
        );
    }

    #[derive(Default)]
    struct CarryTwoCircuitReject;

    impl Circuit<Fp> for CarryTwoCircuitReject {
        type Config = Blake2bCircuitTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Blake2bCircuitTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
                compression: Blake2bCompressionCircuitChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let input_val = 0xFFFF_FFFF_FFFF_FFFFu64;
            let addend_val = 0xFFFF_FFFF_FFFF_FFFFu64;
            let msg_val = 0xFFFF_FFFF_FFFF_FFFFu64;
            let correct_out = input_val.wrapping_add(addend_val).wrapping_add(msg_val);
            let wrong_out = correct_out.wrapping_add(1);

            let chip = Blake2bCompressionCircuitChip::new(
                config.compression,
                config.words,
                config.fq,
            );
            let mut work_in = [0u64; BLAKE2B_WORK_WORDS];
            let mut work_out = work_in;
            work_in[0] = input_val;
            work_in[4] = addend_val;
            work_out[0] = wrong_out;

            let step = Blake2bMixStepTrace {
                step_index: 0,
                updated_lane: 0,
                source_lane: None,
                addend_lane: Some(4),
                message_word_value: Some(msg_val),
                rotation: None,
                work_in,
                work_out,
            };
            let assigned_step = chip.assign_mix_step_row(
                layouter.namespace(|| "carry_two_reject_step"),
                &step,
                "carry_two_reject_step",
            )?;
            chip.constrain_mix_step_wrapping_add_native(
                layouter.namespace(|| "carry_two_reject_native"),
                &assigned_step,
                &step,
                0,
            )
        }
    }

    #[test]
    fn blake2b_circuit_chip_assigns_state_rows() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }

    #[test]
    fn blake2b_circuit_feed_forward_xor_accepts_reference() {
        let circuit = FeedForwardCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_final_work: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }

    #[test]
    fn blake2b_circuit_feed_forward_xor_rejects_final_work_mismatch() {
        let circuit = FeedForwardCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_final_work: true,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "feed-forward XOR must bind state_out to final work lanes"
        );
    }

    #[test]
    fn blake2b_circuit_rotation_xor_accepts_blake2b_rotations() {
        for rotation in [32, 24, 16, 63] {
            let circuit = RotationXorCircuit {
                rotation,
                corrupt_output: false,
                corrupt_updated_input: false,
                corrupt_source_input: false,
                wrong_rotation_output: None,
            };
            let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
            prover.assert_satisfied();
        }
    }

    #[test]
    fn blake2b_circuit_rotation_xor_rejects_wrong_output() {
        let circuit = RotationXorCircuit {
            rotation: 32,
            corrupt_output: true,
            corrupt_updated_input: false,
            corrupt_source_input: false,
            wrong_rotation_output: None,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native rotation/XOR must reject a mismatched output word"
        );
    }

    #[test]
    fn blake2b_circuit_rotation_xor_rejects_updated_input_mismatch() {
        let circuit = RotationXorCircuit {
            rotation: 32,
            corrupt_output: false,
            corrupt_updated_input: true,
            corrupt_source_input: false,
            wrong_rotation_output: None,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native rotation/XOR must bind the updated input lane"
        );
    }

    #[test]
    fn blake2b_circuit_rotation_xor_rejects_source_input_mismatch() {
        let circuit = RotationXorCircuit {
            rotation: 32,
            corrupt_output: false,
            corrupt_updated_input: false,
            corrupt_source_input: true,
            wrong_rotation_output: None,
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native rotation/XOR must bind the source input lane"
        );
    }

    #[test]
    fn blake2b_circuit_rotation_xor_rejects_wrong_rotation_amount() {
        let circuit = RotationXorCircuit {
            rotation: 32,
            corrupt_output: false,
            corrupt_updated_input: false,
            corrupt_source_input: false,
            wrong_rotation_output: Some(24),
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "native rotation/XOR must enforce the configured rotation amount"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_block_word_binding() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: true,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "mismatched transcript/compression words must fail"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_initial_state() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: true,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "initial Blake2b state must match the parameterized IV"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_initial_round_metadata_binding() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: Some(12),
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "initial round metadata lanes must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_initial_round_metadata_high_offset_lane() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: Some(13),
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "round-0 offset_hi lane must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_initial_round_metadata_final_lane() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: Some(14),
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "round-0 final-block lane must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_round_message_pair_binding() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: true,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "round message schedule witnesses must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_message_pair_binding() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: true,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "mix message schedule witnesses must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_chain() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: true,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "mix-step chain witnesses must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_unchanged_lane() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: true,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "unchanged mix-step lanes must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_delta() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: true,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "updated mix-step lane delta must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_sum() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: true,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "first G-step sum relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_add_only() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: true,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "add-only G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_rotation32() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: true,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "rotate32 G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_rotation24() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: true,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "rotate24 G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_sum_second_half() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: true,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "second-half sum G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_rotation16() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: true,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "rotate16 G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_add_only_second_half() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: true,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "second-half add-only G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_mix_step_rotation63() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: true,
            corrupt_first_feed_forward_state_out: false,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "rotate63 G-step relation must fail on mismatch"
        );
    }

    #[test]
    fn blake2b_circuit_rejects_mismatched_first_feed_forward_state_out() {
        let circuit = Blake2bCircuit {
            bytes: vec![1, 2, 3, 4, 5],
            corrupt_first_trace_word: false,
            corrupt_first_round_state_binding: false,
            corrupt_first_round_metadata_binding: None,
            corrupt_first_round_message_pair: false,
            corrupt_first_mix_message_pair: false,
            corrupt_first_mix_step_chain: false,
            corrupt_first_mix_step_unchanged_lane: false,
            corrupt_first_mix_step_delta: false,
            corrupt_first_mix_step_sum: false,
            corrupt_first_mix_step_add_only: false,
            corrupt_first_mix_step_rotation32: false,
            corrupt_first_mix_step_rotation24: false,
            corrupt_first_mix_step_sum_second_half: false,
            corrupt_first_mix_step_add_only_second_half: false,
            corrupt_first_mix_step_rotation16: false,
            corrupt_first_mix_step_rotation63: false,
            corrupt_first_feed_forward_state_out: true,
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        assert!(
            prover.verify().is_err(),
            "feed-forward state_out must fail on mismatch"
        );
    }
}
