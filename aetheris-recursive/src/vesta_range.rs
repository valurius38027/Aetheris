//! Native Fq range-check gadget for `Circuit<Fq>`.
//!
//! Replaces `NonNativeFqChip::range_check` in the Vesta IPA circuit.
//! Since Fq is native in `Circuit<Fq>`, the range check is a simple
//! bit-decomposition gate: each bit is assigned to a row and constrained
//! as binary (`bit * (1 - bit) == 0`), then the reconstructed value is
//! equality-constrained to the original.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Selector},
    poly::Rotation,
};

use crate::Limb;

#[derive(Clone, Debug)]
pub struct FqRangeCheckConfig {
    pub aux: Column<Advice>,
    pub recon: Column<Advice>,
    pub s_range: Selector,
}

impl FqRangeCheckConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        let aux = meta.advice_column();
        let recon = meta.advice_column();
        let s_range = meta.selector();

        meta.enable_equality(aux);
        meta.enable_equality(recon);

        meta.create_gate("fq_bit_range", |meta| {
            let s = meta.query_selector(s_range);
            let bit = meta.query_advice(aux, Rotation::cur());
            vec![s * bit.clone() * (Expression::Constant(Fq::ONE) - bit)]
        });

        Self { aux, recon, s_range }
    }
}

#[derive(Clone, Debug)]
pub struct FqRangeCheckChip {
    config: FqRangeCheckConfig,
}

impl FqRangeCheckChip {
    pub fn new(config: FqRangeCheckConfig) -> Self {
        Self { config }
    }

    pub fn range_check(
        &self,
        mut layouter: impl Layouter<Fq>,
        value: &Limb<Fq>,
        num_bits: usize,
    ) -> Result<(), ErrorFront> {
        let bits: Vec<Value<Fq>> = (0..num_bits)
            .map(|i| {
                value.value.map(|v| {
                    let bytes = v.to_repr();
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                        Fq::ONE
                    } else {
                        Fq::ZERO
                    }
                })
            })
            .collect();

        layouter.assign_region(
            || "fq_range_check",
            |mut region| {
                let mut acc = Value::known(Fq::ZERO);
                let mut base = Fq::ONE;

                for (i, bit_val) in bits.iter().enumerate() {
                    self.config.s_range.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("bit_{}", i),
                        self.config.aux,
                        i,
                        || *bit_val,
                    )?;
                    acc = acc.zip(*bit_val).map(|(a, bv)| a + bv * base);
                    base = base.double();
                }

                let acc_cell = region.assign_advice(
                    || "recon",
                    self.config.recon,
                    num_bits,
                    || acc,
                )?;
                if let Some(c) = value.cell {
                    region.constrain_equal(acc_cell.cell(), c)?;
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ErrorFront},
        halo2curves::pasta::Fq,
    };

    #[derive(Default)]
    struct FqRangeTestCircuit {
        values: Vec<u64>,
    }

    impl Circuit<Fq> for FqRangeTestCircuit {
        type Config = FqRangeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                values: vec![0; self.values.len()],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            FqRangeCheckConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = FqRangeCheckChip::new(config);

            for (i, v) in self.values.iter().enumerate() {
                let limb = Limb {
                    value: Value::known(Fq::from(*v)),
                    cell: None,
                };

                // Range check with enough bits to cover the value
                let bits_needed = if *v == 0 {
                    1
                } else {
                    (64 - v.leading_zeros()) as usize
                };
                chip.range_check(
                    layouter.namespace(|| format!("value_{}", i)),
                    &limb,
                    bits_needed.max(1),
                )?;
            }
            Ok(())
        }
    }

    #[test]
    fn fq_range_small_values_pass() {
        let circuit = FqRangeTestCircuit {
            values: vec![0, 1, 2, 42, 127, 255],
        };
        let prover = MockProver::run(13, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }

    #[test]
    fn fq_range_64bit_value_passes() {
        let circuit = FqRangeTestCircuit {
            values: vec![0xDEAD_BEEF_CAFE_FACE],
        };
        let prover = MockProver::run(13, &circuit, vec![]).expect("mock prover should run");
        prover.assert_satisfied();
    }
}
