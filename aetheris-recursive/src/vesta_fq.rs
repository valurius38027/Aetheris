use ff::Field;
use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Selector},
    poly::Rotation,
};

use crate::Limb;

#[derive(Clone, Debug)]
pub struct VestaFqConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub out: Column<Advice>,
    pub s_mul: Selector,
    pub s_add: Selector,
    pub s_inv: Selector,
}

impl VestaFqConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let out = meta.advice_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(out);

        let s_mul = meta.complex_selector();
        let s_add = meta.complex_selector();
        let s_inv = meta.complex_selector();

        meta.create_gate("vesta_fq_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let x = meta.query_advice(a, Rotation::cur());
            let y = meta.query_advice(b, Rotation::cur());
            let z = meta.query_advice(out, Rotation::cur());
            vec![s * (z - x * y)]
        });

        meta.create_gate("vesta_fq_add", |meta| {
            let s = meta.query_selector(s_add);
            let x = meta.query_advice(a, Rotation::cur());
            let y = meta.query_advice(b, Rotation::cur());
            let z = meta.query_advice(out, Rotation::cur());
            vec![s * (z - x - y)]
        });

        meta.create_gate("vesta_fq_inv", |meta| {
            let s = meta.query_selector(s_inv);
            let x = meta.query_advice(a, Rotation::cur());
            let inv = meta.query_advice(out, Rotation::cur());
            vec![s * (x * inv - Expression::Constant(Fq::ONE))]
        });

        Self { a, b, out, s_mul, s_add, s_inv }
    }
}

#[derive(Clone)]
pub struct VestaFqChip {
    config: VestaFqConfig,
}

impl VestaFqChip {
    pub fn new(config: VestaFqConfig) -> Self {
        Self { config }
    }

    pub fn mul(
        &self,
        mut layouter: impl Layouter<Fq>,
        x: &Limb<Fq>,
        y: &Limb<Fq>,
        label: &str,
    ) -> Result<Limb<Fq>, ErrorFront> {
        let val = x.value.zip(y.value).map(|(xv, yv)| xv * yv);
        layouter.assign_region(
            || format!("fq_mul_{}", label),
            |mut region| {
                self.config.s_mul.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, x.value, x.cell)?;
                Self::copy_or_assign(&mut region, self.config.b, y.value, y.cell)?;
                let out = region.assign_advice(|| "out", self.config.out, 0, || val)?;
                Ok(Limb { value: val, cell: Some(out.cell()) })
            },
        )
    }

    pub fn add(
        &self,
        mut layouter: impl Layouter<Fq>,
        x: &Limb<Fq>,
        y: &Limb<Fq>,
        label: &str,
    ) -> Result<Limb<Fq>, ErrorFront> {
        let val = x.value.zip(y.value).map(|(xv, yv)| xv + yv);
        layouter.assign_region(
            || format!("fq_add_{}", label),
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, x.value, x.cell)?;
                Self::copy_or_assign(&mut region, self.config.b, y.value, y.cell)?;
                let out = region.assign_advice(|| "out", self.config.out, 0, || val)?;
                Ok(Limb { value: val, cell: Some(out.cell()) })
            },
        )
    }

    pub fn invert(
        &self,
        mut layouter: impl Layouter<Fq>,
        x: &Limb<Fq>,
        label: &str,
    ) -> Result<Limb<Fq>, ErrorFront> {
        let inv = x.value.map(|xv| xv.invert().unwrap_or(Fq::ZERO));
        layouter.assign_region(
            || format!("fq_inv_{}", label),
            |mut region| {
                self.config.s_inv.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, x.value, x.cell)?;
                let out = region.assign_advice(|| "inv", self.config.out, 0, || inv)?;
                Ok(Limb { value: inv, cell: Some(out.cell()) })
            },
        )
    }

    pub fn assign_constant(
        &self,
        mut layouter: impl Layouter<Fq>,
        val: Fq,
        label: &str,
    ) -> Result<Limb<Fq>, ErrorFront> {
        layouter.assign_region(
            || format!("fq_const_{}", label),
            |mut region| {
                let cell = region.assign_advice(
                    || "const", self.config.a, 0, || Value::known(val),
                )?;
                Ok(Limb { value: Value::known(val), cell: Some(cell.cell()) })
            },
        )
    }

    fn copy_or_assign(
        region: &mut halo2_proofs::circuit::Region<Fq>,
        col: Column<Advice>,
        val: Value<Fq>,
        cell: Option<Cell>,
    ) -> Result<Cell, ErrorFront> {
        let assigned = region.assign_advice(|| "", col, 0, || val)?;
        if let Some(c) = cell {
            region.constrain_equal(c, assigned.cell())?;
        }
        Ok(assigned.cell())
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

    #[derive(Clone)]
    struct FqArithTestConfig {
        fq: VestaFqConfig,
    }

    struct FqArithTest {
        a: Fq,
        b: Fq,
        op: Op,
        corrupt: bool,
    }

    enum Op {
        Mul,
        Add,
        Invert,
    }

    impl Circuit<Fq> for FqArithTest {
        type Config = FqArithTestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { a: Fq::ZERO, b: Fq::ZERO, op: Op::Mul, corrupt: false }
        }

        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            FqArithTestConfig { fq: VestaFqConfig::configure(meta) }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let chip = VestaFqChip::new(config.fq);
            let a_limb = chip.assign_constant(
                layouter.namespace(|| "a"), self.a, "a",
            )?;
            let b_limb = chip.assign_constant(
                layouter.namespace(|| "b"), self.b, "b",
            )?;

            let expected = match self.op {
                Op::Mul => self.a * self.b,
                Op::Add => self.a + self.b,
                Op::Invert => self.a.invert().unwrap_or(Fq::ZERO),
            };
            let witness = if self.corrupt { expected + Fq::ONE } else { expected };

            let result = match self.op {
                Op::Mul => chip.mul(layouter.namespace(|| "mul"), &a_limb, &b_limb, "mul")?,
                Op::Add => chip.add(layouter.namespace(|| "add"), &a_limb, &b_limb, "add")?,
                Op::Invert => chip.invert(layouter.namespace(|| "inv"), &a_limb, "inv")?,
            };

            let witness_limb = chip.assign_constant(
                layouter.namespace(|| "witness"), witness, "witness",
            )?;
            if let (Some(r), Some(w)) = (result.cell, witness_limb.cell) {
                layouter.assign_region(
                    || "constrain",
                    |mut region| region.constrain_equal(r, w),
                )?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_fq_mul_small() {
        let circuit = FqArithTest { a: Fq::from(3), b: Fq::from(7), op: Op::Mul, corrupt: false };
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("failed: {:?}", e),
        }
    }

    #[test]
    fn test_fq_mul_wrong_rejected() {
        let circuit = FqArithTest { a: Fq::from(3), b: Fq::from(7), op: Op::Mul, corrupt: true };
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_fq_add_small() {
        let circuit = FqArithTest { a: Fq::from(10), b: Fq::from(32), op: Op::Add, corrupt: false };
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("failed: {:?}", e),
        }
    }

    #[test]
    fn test_fq_inv_small() {
        let a = Fq::from(5);
        let circuit = FqArithTest { a, b: Fq::ZERO, op: Op::Invert, corrupt: false };
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        match prover.verify() {
            Ok(()) => {}
            Err(e) => panic!("failed: {:?}", e),
        }
    }

    #[test]
    fn test_fq_inv_zero_rejected() {
        let a = Fq::ZERO;
        let circuit = FqArithTest { a, b: Fq::ZERO, op: Op::Invert, corrupt: false };
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err(), "expected rejection for 0 inversion");
    }
}
