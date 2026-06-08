//! 64-bit word helpers for exact Blake2b transcript gadgets.
//!
//! Blake2b's compression function operates on little-endian 64-bit words. The
//! recursive circuit field is large enough to hold those words natively, so we
//! expose a word layer above `transcript_bytes` before implementing the full
//! compression constraints.

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Selector},
    poly::Rotation,
};

use crate::non_native_fq::{NonNativeFqChip, NonNativeFqConfig};
use crate::transcript_bytes::{
    AssignedTranscriptByteStream, TranscriptByteChip, TranscriptByteStream, BLAKE2B_BLOCK_BYTES,
};
use crate::Limb;

pub const BLAKE2B_WORD_BYTES: usize = 8;
pub const BLAKE2B_BLOCK_WORDS: usize = BLAKE2B_BLOCK_BYTES / BLAKE2B_WORD_BYTES;

#[derive(Clone, Debug)]
pub struct TranscriptWord64 {
    pub limb: Limb,
}

#[derive(Clone, Debug)]
pub struct TranscriptWordBlock {
    pub words: Vec<TranscriptWord64>,
}

#[derive(Clone, Debug)]
pub struct AssignedTranscriptWordStream {
    pub blocks: Vec<TranscriptWordBlock>,
    pub original_len: usize,
    pub byte_blocks: usize,
}

#[derive(Clone, Debug)]
pub struct TranscriptWordConfig {
    pub word: Column<Advice>,
    pub byte_cols: [Column<Advice>; BLAKE2B_WORD_BYTES],
    pub s_decode: Selector,
}

#[derive(Clone)]
pub struct TranscriptWordChip {
    word_config: TranscriptWordConfig,
    fq: NonNativeFqChip,
    bytes: TranscriptByteChip,
}

pub fn bytes_to_word_le(bytes: &[u8]) -> u64 {
    assert_eq!(bytes.len(), BLAKE2B_WORD_BYTES, "word must be 8 bytes");
    let mut arr = [0u8; BLAKE2B_WORD_BYTES];
    arr.copy_from_slice(bytes);
    u64::from_le_bytes(arr)
}

pub fn block_bytes_to_words(block: &[u8; BLAKE2B_BLOCK_BYTES]) -> [u64; BLAKE2B_BLOCK_WORDS] {
    let mut words = [0u64; BLAKE2B_BLOCK_WORDS];
    for (i, chunk) in block.chunks(BLAKE2B_WORD_BYTES).enumerate() {
        words[i] = bytes_to_word_le(chunk);
    }
    words
}

fn reconstruct_word_value(byte_slice: &[crate::transcript_bytes::TranscriptByte]) -> Value<Fp> {
    let mut acc = Value::known(Fp::ZERO);
    for (i, byte) in byte_slice.iter().enumerate() {
        let coeff = 1u64 << (8 * i);
        acc = acc
            .zip(byte.limb.value)
            .map(|(a, b)| a + b * Fp::from(coeff));
    }
    acc
}

impl TranscriptWordChip {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> TranscriptWordConfig {
        let word = meta.advice_column();
        let byte_cols = [0; BLAKE2B_WORD_BYTES].map(|_| meta.advice_column());
        let s_decode = meta.selector();

        meta.enable_equality(word);
        byte_cols.iter().for_each(|col| meta.enable_equality(*col));

        meta.create_gate("transcript_word_decode", |meta| {
            let s = meta.query_selector(s_decode);
            let word_expr = meta.query_advice(word, Rotation::cur());
            let byte_exprs = byte_cols.map(|col| meta.query_advice(col, Rotation::cur()));
            let acc_expr = byte_exprs.into_iter().enumerate().fold(
                halo2_proofs::plonk::Expression::Constant(Fp::ZERO),
                |acc, (i, byte)| {
                    acc + byte
                        * halo2_proofs::plonk::Expression::Constant(Fp::from(1u64 << (8 * i)))
                },
            );
            vec![s * (word_expr - acc_expr)]
        });

        TranscriptWordConfig {
            word,
            byte_cols,
            s_decode,
        }
    }

    pub fn new(word_config: TranscriptWordConfig, fq_config: NonNativeFqConfig) -> Self {
        Self {
            fq: NonNativeFqChip::new(fq_config.clone()),
            bytes: TranscriptByteChip::new(fq_config),
            word_config,
        }
    }

    pub fn constrain_word_from_bytes(
        &self,
        mut layouter: impl Layouter<Fp>,
        byte_slice: &[crate::transcript_bytes::TranscriptByte],
        label: &str,
    ) -> Result<TranscriptWord64, ErrorFront> {
        assert_eq!(byte_slice.len(), BLAKE2B_WORD_BYTES, "word must be 8 bytes");

        let value = reconstruct_word_value(byte_slice);

        let limb = layouter.assign_region(
            || format!("decode_word_{}", label),
            |mut region| {
                self.word_config.s_decode.enable(&mut region, 0)?;

                let assigned = region.assign_advice(
                    || format!("word_{}", label),
                    self.word_config.word,
                    0,
                    || value,
                )?;
                for (i, byte) in byte_slice.iter().enumerate() {
                    let byte_copy = region.assign_advice(
                        || format!("word_byte_{}_{}", label, i),
                        self.word_config.byte_cols[i],
                        0,
                        || byte.limb.value,
                    )?;
                    if let Some(source_cell) = byte.limb.cell {
                        region.constrain_equal(source_cell, byte_copy.cell())?;
                    }
                }
                Ok(Limb {
                    value,
                    cell: Some(assigned.cell()),
                })
            },
        )?;

        self.fq.range_check(
            layouter.namespace(|| format!("word_range_{}", label)),
            &limb,
            64,
        )?;
        Ok(TranscriptWord64 { limb })
    }

    pub fn assign_stream(
        &self,
        mut layouter: impl Layouter<Fp>,
        stream: &TranscriptByteStream,
        label: &str,
    ) -> Result<AssignedTranscriptWordStream, ErrorFront> {
        let assigned_bytes: AssignedTranscriptByteStream = self.bytes.assign_stream(
            layouter.namespace(|| format!("{}_bytes", label)),
            stream,
            label,
        )?;

        let mut word_blocks = Vec::with_capacity(assigned_bytes.blocks.len());
        for (block_idx, block) in assigned_bytes.blocks.iter().enumerate() {
            let mut words = Vec::with_capacity(BLAKE2B_BLOCK_WORDS);
            for word_idx in 0..BLAKE2B_BLOCK_WORDS {
                let start = word_idx * BLAKE2B_WORD_BYTES;
                let end = start + BLAKE2B_WORD_BYTES;
                words.push(
                    self.constrain_word_from_bytes(
                        layouter.namespace(|| {
                            format!("{}_block_{}_word_{}", label, block_idx, word_idx)
                        }),
                        &block.bytes[start..end],
                        &format!("{}_{}_{}", label, block_idx, word_idx),
                    )?,
                );
            }
            word_blocks.push(TranscriptWordBlock { words });
        }

        Ok(AssignedTranscriptWordStream {
            blocks: word_blocks,
            original_len: assigned_bytes.original_len,
            byte_blocks: assigned_bytes.blocks.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    };

    #[derive(Clone, Debug)]
    struct WordTestConfig {
        fq: NonNativeFqConfig,
        words: TranscriptWordConfig,
    }

    #[test]
    fn block_bytes_decode_to_little_endian_words() {
        let mut block = [0u8; BLAKE2B_BLOCK_BYTES];
        block[..8].copy_from_slice(&0x0807060504030201u64.to_le_bytes());
        block[8..16].copy_from_slice(&0x11100f0e0d0c0b0au64.to_le_bytes());

        let words = block_bytes_to_words(&block);
        assert_eq!(words[0], 0x0807060504030201u64);
        assert_eq!(words[1], 0x11100f0e0d0c0b0au64);
    }

    #[test]
    fn bytes_to_word_le_decodes_expected_value() {
        let word = bytes_to_word_le(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(word, 0x0807060504030201u64);
    }

    #[derive(Default)]
    struct WordCircuit {
        bytes: Vec<u8>,
    }

    impl Circuit<Fp> for WordCircuit {
        type Config = WordTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                bytes: vec![0; self.bytes.len()],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            WordTestConfig {
                fq: NonNativeFqChip::configure(meta),
                words: TranscriptWordChip::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip = TranscriptWordChip::new(config.words, config.fq);
            let mut stream = TranscriptByteStream::new();
            stream.extend_bytes(&self.bytes);
            let assigned =
                chip.assign_stream(layouter.namespace(|| "stream"), &stream, "stream")?;
            assert_eq!(assigned.original_len, self.bytes.len());
            assert_eq!(assigned.byte_blocks, assigned.blocks.len());
            assert_eq!(assigned.blocks[0].words.len(), BLAKE2B_BLOCK_WORDS);
            Ok(())
        }
    }

    #[test]
    fn transcript_word_chip_assigns_word_blocks() {
        let circuit = WordCircuit {
            bytes: vec![1, 2, 3, 4, 5],
        };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }
}
