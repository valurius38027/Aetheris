//! Byte-level helpers for exact transcript gadgets.
//!
//! `§1.12d2` needs a circuit-native byte representation before implementing the
//! Blake2b state machine. This module provides the minimal assignment and 8-bit
//! range-check layer that later exact transcript gadgets can build on.

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fp,
    plonk::ErrorFront,
};

use crate::non_native_fq::{NonNativeFqChip, NonNativeFqConfig};
use crate::Limb;

pub const BLAKE2B_BLOCK_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub struct TranscriptByte {
    pub limb: Limb<Fp>,
}

#[derive(Clone, Debug)]
pub struct TranscriptByteVec {
    pub bytes: Vec<TranscriptByte>,
}

#[derive(Clone, Debug)]
pub struct AssignedTranscriptBlock {
    pub bytes: Vec<TranscriptByte>,
}

#[derive(Clone, Debug)]
pub struct AssignedTranscriptByteStream {
    pub blocks: Vec<AssignedTranscriptBlock>,
    pub original_len: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TranscriptByteStream {
    pub bytes: Vec<u8>,
}

impl TranscriptByteStream {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn push_byte(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    pub fn extend_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn blocks(&self) -> Vec<[u8; BLAKE2B_BLOCK_BYTES]> {
        let mut blocks = Vec::new();
        for chunk in self.bytes.chunks(BLAKE2B_BLOCK_BYTES) {
            let mut block = [0u8; BLAKE2B_BLOCK_BYTES];
            block[..chunk.len()].copy_from_slice(chunk);
            blocks.push(block);
        }

        if self.bytes.is_empty() {
            blocks.push([0u8; BLAKE2B_BLOCK_BYTES]);
        }

        blocks
    }
}

#[derive(Clone)]
pub struct TranscriptByteChip {
    config: NonNativeFqConfig,
    fq: NonNativeFqChip,
}

impl TranscriptByteChip {
    pub fn new(config: NonNativeFqConfig) -> Self {
        Self {
            fq: NonNativeFqChip::new(config.clone()),
            config,
        }
    }

    pub fn assign_byte(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<u8>,
        label: &str,
    ) -> Result<TranscriptByte, ErrorFront> {
        let limb = layouter.assign_region(
            || format!("assign_byte_{}", label),
            |mut region| {
                let assigned = region.assign_advice(
                    || format!("byte_{}", label),
                    self.config.a,
                    0,
                    || value.map(|v| Fp::from(v as u64)),
                )?;
                Ok(Limb {
                    value: value.map(|v| Fp::from(v as u64)),
                    cell: Some(assigned.cell()),
                })
            },
        )?;

        self.fq.range_check(
            layouter.namespace(|| format!("byte_range_{}", label)),
            &limb,
            8,
        )?;
        Ok(TranscriptByte { limb })
    }

    pub fn assign_bytes(
        &self,
        mut layouter: impl Layouter<Fp>,
        values: &[u8],
        label: &str,
    ) -> Result<TranscriptByteVec, ErrorFront> {
        let mut bytes = Vec::with_capacity(values.len());
        for (i, value) in values.iter().copied().enumerate() {
            bytes.push(self.assign_byte(
                layouter.namespace(|| format!("{}_{}", label, i)),
                Value::known(value),
                &format!("{}_{}", label, i),
            )?);
        }
        Ok(TranscriptByteVec { bytes })
    }

    pub fn assign_stream(
        &self,
        mut layouter: impl Layouter<Fp>,
        stream: &TranscriptByteStream,
        label: &str,
    ) -> Result<AssignedTranscriptByteStream, ErrorFront> {
        let mut blocks = Vec::new();
        for (block_idx, block) in stream.blocks().into_iter().enumerate() {
            let assigned = self.assign_bytes(
                layouter.namespace(|| format!("{}_block_{}", label, block_idx)),
                &block,
                &format!("{}_block_{}", label, block_idx),
            )?;
            blocks.push(AssignedTranscriptBlock {
                bytes: assigned.bytes,
            });
        }

        Ok(AssignedTranscriptByteStream {
            blocks,
            original_len: stream.len(),
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

    #[derive(Default)]
    struct ByteCircuit {
        bytes: Vec<u8>,
    }

    impl Circuit<Fp> for ByteCircuit {
        type Config = NonNativeFqConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                bytes: vec![0; self.bytes.len()],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            NonNativeFqChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), ErrorFront> {
            let chip = TranscriptByteChip::new(config);
            let assigned =
                chip.assign_bytes(layouter.namespace(|| "bytes"), &self.bytes, "bytes")?;
            assert_eq!(assigned.bytes.len(), self.bytes.len());
            Ok(())
        }
    }

    #[test]
    fn transcript_byte_chip_accepts_byte_values() {
        let circuit = ByteCircuit {
            bytes: vec![0, 1, 2, 127, 255],
        };
        let prover = MockProver::run(10, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }

    #[test]
    fn transcript_byte_stream_pads_partial_block() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&[1, 2, 3, 4, 5]);

        let blocks = stream.blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(&blocks[0][..5], &[1, 2, 3, 4, 5]);
        assert!(blocks[0][5..].iter().all(|b| *b == 0));
    }

    #[test]
    fn transcript_byte_stream_keeps_single_full_boundary_block() {
        let mut stream = TranscriptByteStream::new();
        stream.extend_bytes(&vec![9u8; BLAKE2B_BLOCK_BYTES]);

        let blocks = stream.blocks();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].iter().all(|b| *b == 9));
    }

    #[test]
    fn transcript_byte_stream_adds_zero_block_for_empty_stream() {
        let stream = TranscriptByteStream::new();

        let blocks = stream.blocks();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].iter().all(|b| *b == 0));
    }

    #[test]
    fn transcript_byte_chip_assigns_padded_blocks() {
        #[derive(Default)]
        struct BlockCircuit {
            bytes: Vec<u8>,
        }

        impl Circuit<Fp> for BlockCircuit {
            type Config = NonNativeFqConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self {
                    bytes: vec![0; self.bytes.len()],
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                NonNativeFqChip::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), ErrorFront> {
                let chip = TranscriptByteChip::new(config);
                let mut stream = TranscriptByteStream::new();
                stream.extend_bytes(&self.bytes);
                let assigned =
                    chip.assign_stream(layouter.namespace(|| "stream"), &stream, "stream")?;
                assert_eq!(assigned.original_len, self.bytes.len());
                assert_eq!(assigned.blocks.len(), 1);
                assert_eq!(assigned.blocks[0].bytes.len(), BLAKE2B_BLOCK_BYTES);
                Ok(())
            }
        }

        let circuit = BlockCircuit {
            bytes: vec![1, 2, 3, 4, 5],
        };
        let prover = MockProver::run(11, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }
}
