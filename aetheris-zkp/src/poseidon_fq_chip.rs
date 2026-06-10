use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2_proofs::halo2curves::pasta::Fq;
#[cfg(test)]
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::arithmetic::Field;

use crate::poseidon_fq::{PoseidonFqSpec, ensure_poseidon_spec};

const T: usize = 3;

#[derive(Clone, Debug)]
pub struct PoseidonFqConfig {
    pub state: [Column<Advice>; T],
    pub rc: [Column<Fixed>; T],
    pub partial_sbox: Column<Advice>,
    pub s_full: Selector,
    pub s_partial: Selector,
}

pub struct PoseidonFqChip {
    config: PoseidonFqConfig,
    spec: &'static PoseidonFqSpec,
}

impl PoseidonFqChip {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> PoseidonFqConfig {
        let spec = ensure_poseidon_spec();
        let state = [0u8; T].map(|_| meta.advice_column());
        let rc = [0u8; T].map(|_| meta.fixed_column());
        let partial_sbox = meta.advice_column();
        let s_full = meta.selector();
        let s_partial = meta.selector();

        for col in &state {
            meta.enable_equality(*col);
        }
        meta.enable_equality(partial_sbox);

        let mds = spec.mds;

        meta.create_gate("poseidon_full", |meta| {
            let s = meta.query_selector(s_full);
            let sbox_outputs: Vec<_> = (0..T)
                .map(|i| {
                    let state_cur = meta.query_advice(state[i], Rotation::cur());
                    let rc = meta.query_fixed(rc[i], Rotation::cur());
                    let x = state_cur + rc;
                    let x2 = x.clone() * x.clone();
                    x2.clone() * x2 * x
                })
                .collect();

            let mut exprs = vec![];
            for i in 0..T {
                let mut mds_sum = Expression::Constant(Fq::ZERO);
                for j in 0..T {
                    mds_sum = mds_sum + sbox_outputs[j].clone() * Expression::Constant(mds[i][j]);
                }
                let state_next = meta.query_advice(state[i], Rotation::next());
                exprs.push(s.clone() * (mds_sum - state_next));
            }
            exprs
        });

        meta.create_gate("poseidon_partial_sbox", |meta| {
            let s = meta.query_selector(s_partial);
            let state0 = meta.query_advice(state[0], Rotation::cur());
            let rc0 = meta.query_fixed(rc[0], Rotation::cur());
            let x0 = state0 + rc0;
            let x0_2 = x0.clone() * x0.clone();
            let x0_5 = x0_2.clone() * x0_2 * x0;
            let sbox_val = meta.query_advice(partial_sbox, Rotation::cur());
            vec![s * (x0_5 - sbox_val)]
        });

        meta.create_gate("poseidon_partial_mds", |meta| {
            let s = meta.query_selector(s_partial);
            let sbox_val = meta.query_advice(partial_sbox, Rotation::cur());
            let mut mixed = vec![sbox_val];
            for i in 1..T {
                let state_cur = meta.query_advice(state[i], Rotation::cur());
                let rc = meta.query_fixed(rc[i], Rotation::cur());
                mixed.push(state_cur + rc);
            }

            let mut exprs = vec![];
            for i in 0..T {
                let mut mds_sum = Expression::Constant(Fq::ZERO);
                for j in 0..T {
                    mds_sum = mds_sum + mixed[j].clone() * Expression::Constant(mds[i][j]);
                }
                let state_next = meta.query_advice(state[i], Rotation::next());
                exprs.push(s.clone() * (mds_sum - state_next));
            }
            exprs
        });

        PoseidonFqConfig {
            state,
            rc,
            partial_sbox,
            s_full,
            s_partial,
        }
    }

    pub fn new(config: PoseidonFqConfig) -> Self {
        Self {
            config,
            spec: ensure_poseidon_spec(),
        }
    }

    /// Assign a Poseidon permutation over Fq, returning the output cell (state[0] after all
    /// rounds). The input `left` / `right` values are assigned as state[0]/state[1] on the
    /// first row; state[2] is always Fq::ZERO (capacity).
    ///
    /// If `left_cell` / `right_cell` are `Some`, the first-row state[0]/state[1] cells are
    /// copy-constrained to those cells. This allows chaining hash outputs to subsequent inputs.
    ///
    /// Layout: (r_f + r_p) round rows followed by one output row.
    /// Each round row enables the corresponding gate (s_full or s_partial).
    /// The output row has NO selector — it stores the final state.
    pub fn assign_hash(
        &self,
        mut layouter: impl Layouter<Fq>,
        left: Value<Fq>,
        right: Value<Fq>,
        left_cell: Option<Cell>,
        right_cell: Option<Cell>,
    ) -> Result<AssignedCell<Fq, Fq>, ErrorFront> {
        let spec = self.spec;
        layouter.assign_region(
            || "poseidon_fq_perm",
            |mut region| {
                let mut state = [left, right, Value::known(Fq::ZERO)];
                let mut offset = 0;

                // First row — constrain left/right cells if provided
                self.config.s_full.enable(&mut region, offset)?;
                for i in 0..T {
                    let assigned = region.assign_advice(
                        || format!("state_{}", i),
                        self.config.state[i],
                        offset,
                        || state[i],
                    )?;
                    if i == 0 {
                        if let Some(cell) = left_cell {
                            region.constrain_equal(assigned.cell(), cell)?;
                        }
                    }
                    if i == 1 {
                        if let Some(cell) = right_cell {
                            region.constrain_equal(assigned.cell(), cell)?;
                        }
                    }
                    region.assign_fixed(
                        || format!("rc_{}", i),
                        self.config.rc[i],
                        offset,
                        || Value::known(spec.constants[offset][i]),
                    )?;
                }

                let sbox: Vec<Value<Fq>> = (0..T)
                    .map(|i| {
                        state[i].map(|s| {
                            let x = s + spec.constants[offset][i];
                            let x2 = x * x;
                            x2 * x2 * x
                        })
                    })
                    .collect();

                for i in 0..T {
                    let mut sum = sbox[0].map(|s| s * spec.mds[i][0]);
                    for j in 1..T {
                        sum = sum
                            .zip(sbox[j])
                            .map(|(acc, s)| acc + s * spec.mds[i][j]);
                    }
                    state[i] = sum;
                }
                offset += 1;

                // Remaining first-half full rounds
                for _ in 1..spec.r_f / 2 {
                    self.config.s_full.enable(&mut region, offset)?;
                    for i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(spec.constants[offset][i]),
                        )?;
                    }

                    let sbox: Vec<Value<Fq>> = (0..T)
                        .map(|i| {
                            state[i].map(|s| {
                                let x = s + spec.constants[offset][i];
                                let x2 = x * x;
                                x2 * x2 * x
                            })
                        })
                        .collect();

                    for i in 0..T {
                        let mut sum = sbox[0].map(|s| s * spec.mds[i][0]);
                        for j in 1..T {
                            sum = sum
                                .zip(sbox[j])
                                .map(|(acc, s)| acc + s * spec.mds[i][j]);
                        }
                        state[i] = sum;
                    }
                    offset += 1;
                }

                // Partial rounds (r_p rows)
                for _ in 0..spec.r_p {
                    self.config.s_partial.enable(&mut region, offset)?;
                    for i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(spec.constants[offset][i]),
                        )?;
                    }

                    let sbox0 = state[0].map(|s| {
                        let x = s + spec.constants[offset][0];
                        let x2 = x * x;
                        x2 * x2 * x
                    });

                    region.assign_advice(
                        || "partial_sbox",
                        self.config.partial_sbox,
                        offset,
                        || sbox0,
                    )?;

                    let other: Vec<Value<Fq>> = state[1..]
                        .iter()
                        .enumerate()
                        .map(|(i, &s)| s.map(|v| v + spec.constants[offset][i + 1]))
                        .collect();

                    for i in 0..T {
                        let mut sum = sbox0.map(|s| s * spec.mds[i][0]);
                        for j in 1..T {
                            sum = sum
                                .zip(other[j - 1])
                                .map(|(acc, s)| acc + s * spec.mds[i][j]);
                        }
                        state[i] = sum;
                    }
                    offset += 1;
                }

                // Second half full rounds (r_f/2 rows)
                for _ in 0..spec.r_f / 2 {
                    self.config.s_full.enable(&mut region, offset)?;
                    for i in 0..T {
                        region.assign_advice(
                            || format!("state_{}", i),
                            self.config.state[i],
                            offset,
                            || state[i],
                        )?;
                        region.assign_fixed(
                            || format!("rc_{}", i),
                            self.config.rc[i],
                            offset,
                            || Value::known(spec.constants[offset][i]),
                        )?;
                    }

                    let sbox: Vec<Value<Fq>> = (0..T)
                        .map(|i| {
                            state[i].map(|s| {
                                let x = s + spec.constants[offset][i];
                                let x2 = x * x;
                                x2 * x2 * x
                            })
                        })
                        .collect();

                    for i in 0..T {
                        let mut sum = sbox[0].map(|s| s * spec.mds[i][0]);
                        for j in 1..T {
                            sum = sum
                                .zip(sbox[j])
                                .map(|(acc, s)| acc + s * spec.mds[i][j]);
                        }
                        state[i] = sum;
                    }
                    offset += 1;
                }

                // Output row — no gate, just stores the final state.
                debug_assert!(offset == spec.r_f + spec.r_p);
                let out = region.assign_advice(
                    || "output",
                    self.config.state[0],
                    offset,
                    || state[0],
                )?;
                for i in 1..T {
                    region.assign_advice(
                        || format!("state_final_{}", i),
                        self.config.state[i],
                        offset,
                        || state[i],
                    )?;
                }
                Ok(out)
            },
        )
    }

    /// Native hash (no circuit assignment) — useful for computing expected values.
    pub fn native_hash(&self, left: Fq, right: Fq) -> Fq {
        let spec = self.spec;
        let mut state = [left, right, Fq::ZERO];
        let mut offset = 0;

        for _ in 0..spec.r_f / 2 {
            let sbox: Vec<Fq> = (0..T)
                .map(|i| {
                    let x = state[i] + spec.constants[offset][i];
                    let x2 = x * x;
                    x2 * x2 * x
                })
                .collect();
            for i in 0..T {
                let mut sum = Fq::ZERO;
                for j in 0..T {
                    sum = sum + sbox[j] * spec.mds[i][j];
                }
                state[i] = sum;
            }
            offset += 1;
        }

        for _ in spec.r_f / 2..spec.r_f / 2 + spec.r_p {
            let sbox0 = {
                let x = state[0] + spec.constants[offset][0];
                let x2 = x * x;
                x2 * x2 * x
            };
            let other: Vec<Fq> = state[1..]
                .iter()
                .enumerate()
                .map(|(i, &s)| s + spec.constants[offset][i + 1])
                .collect();
            for i in 0..T {
                let mut sum = sbox0 * spec.mds[i][0];
                for j in 1..T {
                    sum = sum + other[j - 1] * spec.mds[i][j];
                }
                state[i] = sum;
            }
            offset += 1;
        }

        for _ in 0..spec.r_f / 2 {
            let sbox: Vec<Fq> = (0..T)
                .map(|i| {
                    let x = state[i] + spec.constants[offset][i];
                    let x2 = x * x;
                    x2 * x2 * x
                })
                .collect();
            for i in 0..T {
                let mut sum = Fq::ZERO;
                for j in 0..T {
                    sum = sum + sbox[j] * spec.mds[i][j];
                }
                state[i] = sum;
            }
            offset += 1;
        }

        state[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_fq;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, Instance},
    };

    #[derive(Clone)]
    struct PoseidonHashCircuit {
        left: [u8; 32],
        right: [u8; 32],
    }

    impl Circuit<Fq> for PoseidonHashCircuit {
        type Config = (PoseidonFqConfig, Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                left: [0u8; 32],
                right: [0u8; 32],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            let poseidon = PoseidonFqChip::configure(meta);
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            (poseidon, instance)
        }

        fn synthesize(
            &self,
            (config, instance): Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let state_col = config.state[0];
            let chip = PoseidonFqChip::new(config);

            let left_fq = Fq::from_repr(self.left).expect("left is canonical Fq");
            let right_fq = Fq::from_repr(self.right).expect("right is canonical Fq");

            let out = chip.assign_hash(
                layouter.namespace(|| "poseidon"),
                Value::known(left_fq),
                Value::known(right_fq),
                None,
                None,
            )?;

            let expected =
                poseidon_fq::poseidon_hash(&self.left, &self.right);
            let expected_fq = Fq::from_repr(expected).expect("expected is canonical Fq");

            layouter.assign_region(|| "constrain", |mut region| {
                let instance_cell = region.assign_advice_from_instance(
                    || "instance", instance, 0, state_col, 0,
                )?;
                region.constrain_equal(out.cell(), instance_cell.cell())?;
                Ok(())
            })?;

            out.value().copied().map(|out_val| {
                assert_eq!(out_val, expected_fq, "chip hash must match native hash");
            });
            Ok(())
        }
    }

    #[test]
    fn test_poseidon_chip_matches_native() {
        let circuit = PoseidonHashCircuit {
            left: {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&1u64.to_le_bytes());
                b
            },
            right: {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&2u64.to_le_bytes());
                b
            },
        };

        let expected = poseidon_fq::poseidon_hash(&circuit.left, &circuit.right);
        let expected_fq = Fq::from_repr(expected).expect("expected is canonical Fq");
        let instances = vec![vec![expected_fq]];
        let prover = MockProver::run(11, &circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_poseidon_chip_rejects_wrong_instance() {
        let circuit = PoseidonHashCircuit {
            left: {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&1u64.to_le_bytes());
                b
            },
            right: {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&2u64.to_le_bytes());
                b
            },
        };

        let instances = vec![vec![Fq::from(999)]];
        let prover = MockProver::run(11, &circuit, instances).unwrap();
        assert!(prover.verify().is_err(), "wrong instance should be rejected");
    }
}
