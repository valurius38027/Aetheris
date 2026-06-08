//! Blake2b constants and block metadata for exact transcript gadgets.
//!
//! This module intentionally stays below the full compression gadget: it pins
//! the word-level constants, schedule, and per-block metadata that the later
//! circuit implementation must follow exactly.

use crate::transcript_bytes::{TranscriptByteStream, BLAKE2B_BLOCK_BYTES};
use crate::transcript_words::{
    block_bytes_to_words, AssignedTranscriptWordStream, BLAKE2B_BLOCK_WORDS,
};

pub const BLAKE2B_STATE_WORDS: usize = 8;
pub const BLAKE2B_WORK_WORDS: usize = 16;
pub const BLAKE2B_ROUNDS: usize = 12;

pub const BLAKE2B_IV: [u64; BLAKE2B_STATE_WORDS] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub const BLAKE2B_SIGMA: [[usize; BLAKE2B_BLOCK_WORDS]; BLAKE2B_ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake2bBlockMeta {
    pub block_index: usize,
    pub offset: u128,
    pub is_final_block: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bBlockTrace {
    pub meta: Blake2bBlockMeta,
    pub bytes: [u8; BLAKE2B_BLOCK_BYTES],
    pub words: [u64; BLAKE2B_BLOCK_WORDS],
}

pub fn blake2b_block_trace(stream: &TranscriptByteStream) -> Vec<Blake2bBlockTrace> {
    let blocks = stream.blocks();
    let block_count = blocks.len();
    let mut offset = 0u128;
    let mut traces = Vec::with_capacity(blocks.len());

    for (i, bytes) in blocks.into_iter().enumerate() {
        let remaining = stream.len().saturating_sub(i * BLAKE2B_BLOCK_BYTES);
        let consumed = remaining.min(BLAKE2B_BLOCK_BYTES);
        offset += consumed as u128;
        traces.push(Blake2bBlockTrace {
            meta: Blake2bBlockMeta {
                block_index: i,
                offset,
                is_final_block: i + 1 == block_count,
            },
            words: block_bytes_to_words(&bytes),
            bytes,
        });
    }

    traces
}

pub fn block_trace_matches_assigned_words(
    trace: &[Blake2bBlockTrace],
    assigned: &AssignedTranscriptWordStream,
) -> bool {
    if trace.len() != assigned.blocks.len() {
        return false;
    }

    trace
        .iter()
        .zip(&assigned.blocks)
        .all(|(block_trace, assigned_block)| block_trace.words.len() == assigned_block.words.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_sigma_rows_are_permutations() {
        for row in BLAKE2B_SIGMA {
            let mut seen = [false; BLAKE2B_BLOCK_WORDS];
            for idx in row {
                assert!(idx < BLAKE2B_BLOCK_WORDS);
                assert!(!seen[idx]);
                seen[idx] = true;
            }
            assert!(seen.iter().all(|v| *v));
        }
    }

    #[test]
    fn blake2b_block_trace_tracks_offsets_and_final_flag() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&vec![7u8; BLAKE2B_BLOCK_BYTES + 5]);

        let trace = blake2b_block_trace(&stream);
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].meta.offset, BLAKE2B_BLOCK_BYTES as u128);
        assert_eq!(trace[1].meta.offset, (BLAKE2B_BLOCK_BYTES + 5) as u128);
        assert!(!trace[0].meta.is_final_block);
        assert!(trace[1].meta.is_final_block);
    }

    #[test]
    fn blake2b_block_trace_marks_exact_full_block_final() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&vec![7u8; BLAKE2B_BLOCK_BYTES]);

        let trace = blake2b_block_trace(&stream);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].meta.offset, BLAKE2B_BLOCK_BYTES as u128);
        assert!(trace[0].meta.is_final_block);
    }

    #[test]
    fn blake2b_block_trace_decodes_words_from_bytes() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&0x0807060504030201u64.to_le_bytes());

        let trace = blake2b_block_trace(&stream);
        assert_eq!(trace[0].words[0], 0x0807060504030201u64);
    }

    #[test]
    fn block_trace_shape_check_rejects_mismatched_block_count() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&[1, 2, 3]);
        let trace = blake2b_block_trace(&stream);

        let fake_assigned = AssignedTranscriptWordStream {
            blocks: Vec::new(),
            original_len: 3,
            byte_blocks: 0,
        };

        assert!(!block_trace_matches_assigned_words(&trace, &fake_assigned));
    }
}
