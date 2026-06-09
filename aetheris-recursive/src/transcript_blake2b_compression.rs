//! Blake2b compression trace scaffolding for exact transcript gadgets.
//!
//! This module fixes the block-by-block host/reference trace shape that the
//! later in-circuit compression gadget must reproduce. It does not yet add the
//! round-function constraints; it pins the state transition interface so those
//! constraints have an unambiguous target.

use crate::ipa_transcript::HALO2_TRANSCRIPT_PERSONALIZATION;
use crate::transcript_blake2b::{
    blake2b_block_trace, Blake2bBlockTrace, BLAKE2B_IV, BLAKE2B_STATE_WORDS,
};
use crate::transcript_blake2b::{BLAKE2B_SIGMA, BLAKE2B_WORK_WORDS};
use crate::transcript_bytes::TranscriptByteStream;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bCompressionTraceRow {
    pub block: Blake2bBlockTrace,
    pub state_in: [u64; BLAKE2B_STATE_WORDS],
    pub state_out: [u64; BLAKE2B_STATE_WORDS],
    pub rounds: Vec<Blake2bRoundTrace>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bCompressionTrace {
    pub rows: Vec<Blake2bCompressionTraceRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bRoundTrace {
    pub round_index: usize,
    pub sigma: [usize; 16],
    pub mixes: Vec<Blake2bMixTrace>,
    pub work_in: [u64; BLAKE2B_WORK_WORDS],
    pub work_out: [u64; BLAKE2B_WORK_WORDS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bMixTrace {
    pub mix_index: usize,
    pub lanes: [usize; 4],
    pub message_word_indices: [usize; 2],
    pub message_word_values: [u64; 2],
    pub steps: Vec<Blake2bMixStepTrace>,
    pub work_in: [u64; BLAKE2B_WORK_WORDS],
    pub work_out: [u64; BLAKE2B_WORK_WORDS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bMixStepTrace {
    pub step_index: usize,
    pub updated_lane: usize,
    pub source_lane: Option<usize>,
    pub addend_lane: Option<usize>,
    pub message_word_value: Option<u64>,
    pub rotation: Option<u32>,
    pub work_in: [u64; BLAKE2B_WORK_WORDS],
    pub work_out: [u64; BLAKE2B_WORK_WORDS],
}

fn rotr64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

fn mixing_g_trace(
    v: &mut [u64; BLAKE2B_WORK_WORDS],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: u64,
    y: u64,
) -> Vec<Blake2bMixStepTrace> {
    let mut steps = Vec::with_capacity(8);

    let before = *v;
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    steps.push(Blake2bMixStepTrace {
        step_index: 0,
        updated_lane: a,
        source_lane: None,
        addend_lane: Some(b),
        message_word_value: Some(x),
        rotation: None,
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[d] = rotr64(v[d] ^ v[a], 32);
    steps.push(Blake2bMixStepTrace {
        step_index: 1,
        updated_lane: d,
        source_lane: Some(a),
        addend_lane: None,
        message_word_value: None,
        rotation: Some(32),
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[c] = v[c].wrapping_add(v[d]);
    steps.push(Blake2bMixStepTrace {
        step_index: 2,
        updated_lane: c,
        source_lane: None,
        addend_lane: Some(d),
        message_word_value: None,
        rotation: None,
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[b] = rotr64(v[b] ^ v[c], 24);
    steps.push(Blake2bMixStepTrace {
        step_index: 3,
        updated_lane: b,
        source_lane: Some(c),
        addend_lane: None,
        message_word_value: None,
        rotation: Some(24),
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    steps.push(Blake2bMixStepTrace {
        step_index: 4,
        updated_lane: a,
        source_lane: None,
        addend_lane: Some(b),
        message_word_value: Some(y),
        rotation: None,
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[d] = rotr64(v[d] ^ v[a], 16);
    steps.push(Blake2bMixStepTrace {
        step_index: 5,
        updated_lane: d,
        source_lane: Some(a),
        addend_lane: None,
        message_word_value: None,
        rotation: Some(16),
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[c] = v[c].wrapping_add(v[d]);
    steps.push(Blake2bMixStepTrace {
        step_index: 6,
        updated_lane: c,
        source_lane: None,
        addend_lane: Some(d),
        message_word_value: None,
        rotation: None,
        work_in: before,
        work_out: *v,
    });

    let before = *v;
    v[b] = rotr64(v[b] ^ v[c], 63);
    steps.push(Blake2bMixStepTrace {
        step_index: 7,
        updated_lane: b,
        source_lane: Some(c),
        addend_lane: None,
        message_word_value: None,
        rotation: Some(63),
        work_in: before,
        work_out: *v,
    });

    steps
}

fn initialize_work_vector(
    state: &[u64; BLAKE2B_STATE_WORDS],
    block: &Blake2bBlockTrace,
) -> [u64; BLAKE2B_WORK_WORDS] {
    let mut v = [0u64; BLAKE2B_WORK_WORDS];
    v[..8].copy_from_slice(state);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= block.meta.offset as u64;
    v[13] ^= (block.meta.offset >> 64) as u64;
    if block.meta.is_final_block {
        v[14] = !v[14];
    }
    v
}

pub(crate) fn compress_block(
    state: &[u64; BLAKE2B_STATE_WORDS],
    block: &Blake2bBlockTrace,
) -> ([u64; BLAKE2B_STATE_WORDS], Vec<Blake2bRoundTrace>) {
    let mut v = initialize_work_vector(state, block);
    let m = &block.words;
    let mut rounds = Vec::with_capacity(BLAKE2B_SIGMA.len());

    for (round_index, sigma) in BLAKE2B_SIGMA.iter().copied().enumerate() {
        let work_in = v;
        let mut mixes = Vec::with_capacity(8);
        for (mix_index, (lanes, msg_pair)) in [
            ([0usize, 4, 8, 12], [sigma[0], sigma[1]]),
            ([1, 5, 9, 13], [sigma[2], sigma[3]]),
            ([2, 6, 10, 14], [sigma[4], sigma[5]]),
            ([3, 7, 11, 15], [sigma[6], sigma[7]]),
            ([0, 5, 10, 15], [sigma[8], sigma[9]]),
            ([1, 6, 11, 12], [sigma[10], sigma[11]]),
            ([2, 7, 8, 13], [sigma[12], sigma[13]]),
            ([3, 4, 9, 14], [sigma[14], sigma[15]]),
        ]
        .into_iter()
        .enumerate()
        {
            let mix_in = v;
            let message_word_values = [m[msg_pair[0]], m[msg_pair[1]]];
            let steps = mixing_g_trace(
                &mut v,
                lanes[0],
                lanes[1],
                lanes[2],
                lanes[3],
                message_word_values[0],
                message_word_values[1],
            );
            mixes.push(Blake2bMixTrace {
                mix_index,
                lanes,
                message_word_indices: msg_pair,
                message_word_values,
                steps,
                work_in: mix_in,
                work_out: v,
            });
        }
        rounds.push(Blake2bRoundTrace {
            round_index,
            sigma,
            mixes,
            work_in,
            work_out: v,
        });
    }

    let mut out = [0u64; BLAKE2B_STATE_WORDS];
    for i in 0..BLAKE2B_STATE_WORDS {
        out[i] = state[i] ^ v[i] ^ v[i + 8];
    }
    (out, rounds)
}

pub fn halo2_blake2b_transcript_initial_state() -> [u64; BLAKE2B_STATE_WORDS] {
    let mut state = BLAKE2B_IV;
    state[0] ^= 0x0101_0000 ^ 64;
    state[6] ^= u64::from_le_bytes(HALO2_TRANSCRIPT_PERSONALIZATION[..8].try_into().unwrap());
    state[7] ^= u64::from_le_bytes(HALO2_TRANSCRIPT_PERSONALIZATION[8..].try_into().unwrap());
    state
}

pub fn blake2b_compression_trace_skeleton(
    stream: &TranscriptByteStream,
) -> Blake2bCompressionTrace {
    let blocks = blake2b_block_trace(stream);
    let mut rows = Vec::with_capacity(blocks.len());
    let mut current = halo2_blake2b_transcript_initial_state();

    for block in blocks {
        let (next, rounds) = compress_block(&current, &block);
        rows.push(Blake2bCompressionTraceRow {
            block,
            state_in: current,
            state_out: next,
            rounds,
        });
        current = next;
    }

    Blake2bCompressionTrace { rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_bytes::BLAKE2B_BLOCK_BYTES;
    use blake2b_simd::Params as Blake2bParams;

    fn final_state_digest(trace: &Blake2bCompressionTrace) -> [u8; 64] {
        let final_state = trace
            .rows
            .last()
            .expect("trace must contain a final row")
            .state_out;
        let mut digest = [0u8; 64];
        for (i, word) in final_state.iter().enumerate() {
            digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    #[test]
    fn compression_trace_skeleton_uses_halo2_blake2b_initial_state() {
        let trace = blake2b_compression_trace_skeleton(&TranscriptByteStream::new());
        assert_eq!(trace.rows.len(), 1);
        assert_eq!(
            trace.rows[0].state_in,
            halo2_blake2b_transcript_initial_state()
        );
    }

    #[test]
    fn halo2_blake2b_initial_state_includes_personalization() {
        let state = halo2_blake2b_transcript_initial_state();
        assert_eq!(state[0], BLAKE2B_IV[0] ^ (0x0101_0000 ^ 64));
        assert_eq!(state[6], BLAKE2B_IV[6] ^ u64::from_le_bytes(*b"Halo2-Tr"));
        assert_eq!(state[7], BLAKE2B_IV[7] ^ u64::from_le_bytes(*b"anscript"));
        assert_ne!(state, BLAKE2B_IV);
    }

    #[test]
    fn compression_trace_digest_matches_halo2_blake2b() {
        for bytes in [
            Vec::new(),
            b"abc".to_vec(),
            vec![7u8; BLAKE2B_BLOCK_BYTES],
            vec![7u8; BLAKE2B_BLOCK_BYTES + 1],
            vec![7u8; BLAKE2B_BLOCK_BYTES * 2],
        ] {
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(&bytes);

            let trace = blake2b_compression_trace_skeleton(&stream);
            let expected = Blake2bParams::new()
                .hash_length(64)
                .personal(HALO2_TRANSCRIPT_PERSONALIZATION)
                .hash(&bytes);

            assert_eq!(final_state_digest(&trace), *expected.as_array());
        }
    }

    #[test]
    fn compression_trace_skeleton_has_one_row_per_padded_block() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&vec![1u8; BLAKE2B_BLOCK_BYTES + 3]);

        let trace = blake2b_compression_trace_skeleton(&stream);
        assert_eq!(trace.rows.len(), 2);
        assert_eq!(trace.rows[0].block.meta.block_index, 0);
        assert_eq!(trace.rows[1].block.meta.block_index, 1);
    }

    #[test]
    fn compression_trace_changes_state_for_nonempty_stream() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&[1, 2, 3, 4]);

        let trace = blake2b_compression_trace_skeleton(&stream);
        assert_ne!(trace.rows[0].state_in, trace.rows[0].state_out);
        assert_eq!(trace.rows[0].rounds.len(), 12);
    }

    #[test]
    fn compression_trace_state_chain_is_self_consistent() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&vec![5u8; BLAKE2B_BLOCK_BYTES + 9]);

        let trace = blake2b_compression_trace_skeleton(&stream);
        assert_eq!(trace.rows.len(), 2);
        assert_eq!(trace.rows[1].state_in, trace.rows[0].state_out);
    }

    #[test]
    fn compression_trace_rounds_chain_work_vectors() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"abc");

        let trace = blake2b_compression_trace_skeleton(&stream);
        let rounds = &trace.rows[0].rounds;
        assert_eq!(rounds.len(), 12);
        for i in 0..rounds.len() - 1 {
            assert_eq!(rounds[i].work_out, rounds[i + 1].work_in);
        }
    }

    #[test]
    fn compression_trace_rounds_record_all_eight_mix_steps() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"abc");

        let trace = blake2b_compression_trace_skeleton(&stream);
        let first_round = &trace.rows[0].rounds[0];
        assert_eq!(first_round.mixes.len(), 8);
        assert_eq!(first_round.mixes[0].lanes, [0, 4, 8, 12]);
        assert_eq!(first_round.mixes[0].message_word_indices, [0, 1]);
        assert_eq!(first_round.mixes[7].lanes, [3, 4, 9, 14]);
        assert_eq!(first_round.mixes[7].message_word_indices, [14, 15]);
    }

    #[test]
    fn compression_trace_mix_steps_chain_within_round() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"abc");

        let trace = blake2b_compression_trace_skeleton(&stream);
        let mixes = &trace.rows[0].rounds[0].mixes;
        for i in 0..mixes.len() - 1 {
            assert_eq!(mixes[i].work_out, mixes[i + 1].work_in);
        }
        assert_eq!(trace.rows[0].rounds[0].work_in, mixes[0].work_in);
        assert_eq!(
            trace.rows[0].rounds[0].work_out,
            mixes[mixes.len() - 1].work_out
        );
    }

    #[test]
    fn compression_trace_mix_records_all_eight_g_steps() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"abc");

        let trace = blake2b_compression_trace_skeleton(&stream);
        let mix = &trace.rows[0].rounds[0].mixes[0];
        assert_eq!(mix.steps.len(), 8);
        for (i, step) in mix.steps.iter().enumerate() {
            assert_eq!(step.step_index, i);
        }
        assert_eq!(mix.steps[0].updated_lane, 0);
        assert_eq!(mix.steps[0].addend_lane, Some(4));
        assert_eq!(
            mix.steps[0].message_word_value,
            Some(mix.message_word_values[0])
        );
        assert_eq!(mix.steps[1].updated_lane, 12);
        assert_eq!(mix.steps[1].rotation, Some(32));
        assert_eq!(mix.steps[7].updated_lane, 4);
        assert_eq!(mix.steps[7].rotation, Some(63));
        assert_eq!(mix.work_in, mix.steps[0].work_in);
        assert_eq!(mix.work_out, mix.steps[7].work_out);
    }

    #[test]
    fn compression_trace_g_steps_chain_within_mix() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(b"abc");

        let trace = blake2b_compression_trace_skeleton(&stream);
        let steps = &trace.rows[0].rounds[0].mixes[0].steps;
        for i in 0..steps.len() - 1 {
            assert_eq!(steps[i].work_out, steps[i + 1].work_in);
        }
    }
}
