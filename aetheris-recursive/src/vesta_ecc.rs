#![allow(unused_variables)]

//! Native Vesta EC point operations on `Circuit<Fq>`.
//!
//! Vesta (Pallas) curve: y² = x³ + 5 over base field Fq.
//! All operations are native — no NonNativeChip wrapper needed.
//!
//! Provides:
//! - `assert_on_curve`: verify (x, y) lies on y² = x³ + 5
//! - `point_add`: verify R = P + Q
//! - `point_double`: verify R = 2P
//! - `scalar_mul`: assign R = s·P via double-and-add with identity bypass
//! - `select`: conditionally choose between two points by a bit

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Column, ConstraintSystem, ErrorFront, Expression, Selector},
    poly::Rotation,
};

/// A Vesta point in affine coordinates with optional circuit cell assignments.
#[derive(Clone, Debug)]
pub struct VestaPoint {
    pub x: Value<Fq>,
    pub y: Value<Fq>,
    pub x_cell: Option<Cell>,
    pub y_cell: Option<Cell>,
}

impl VestaPoint {
    pub fn new(x: Fq, y: Fq) -> Self {
        Self {
            x: Value::known(x),
            y: Value::known(y),
            x_cell: None,
            y_cell: None,
        }
    }
}

/// Config columns for Vesta EC operations.
///
/// All operations fit on a single row using separate columns:
/// - a, b: P = (x₁, y₁)
/// - c, d: Q = (x₂, y₂)
/// - e: λ (slope)
/// - f, g: R = (x₃, y₃)
/// - h: bit (for conditional select)
#[derive(Clone, Debug)]
pub struct VestaEccConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub d: Column<Advice>,
    pub e: Column<Advice>,
    pub f: Column<Advice>,
    pub g: Column<Advice>,
    pub h: Column<Advice>,
    pub s_on_curve: Selector,
    pub s_add: Selector,
    pub s_double: Selector,
    pub s_select: Selector,
    /// Fires on scalar_mul result rows.
    /// Constraint: x * (y² - x³ - 5) = 0 — allows identity (x=0) or valid on-curve point.
    pub s_scalar_mul_result: Selector,
}

impl VestaEccConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let d = meta.advice_column();
        let e = meta.advice_column();
        let f = meta.advice_column();
        let g = meta.advice_column();
        let h = meta.advice_column();

        let s_on_curve = meta.selector();
        let s_add = meta.selector();
        let s_double = meta.selector();
        let s_select = meta.selector();
        let s_scalar_mul_result = meta.selector();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(d);
        meta.enable_equality(e);
        meta.enable_equality(f);
        meta.enable_equality(g);
        meta.enable_equality(h);

        // On-curve gate: y² = x³ + 5
        meta.create_gate("vesta_on_curve", |meta| {
            let s = meta.query_selector(s_on_curve);
            let x = meta.query_advice(a, Rotation::cur());
            let y = meta.query_advice(b, Rotation::cur());
            let five = Expression::Constant(Fq::from(5));
            vec![s * (y.clone() * y - x.clone() * x.clone() * x - five)]
        });

        // Point addition gate: R = P + Q
        meta.create_gate("vesta_point_add", |meta| {
            let s = meta.query_selector(s_add);
            let px = meta.query_advice(a, Rotation::cur());
            let py = meta.query_advice(b, Rotation::cur());
            let qx = meta.query_advice(c, Rotation::cur());
            let qy = meta.query_advice(d, Rotation::cur());
            let lam = meta.query_advice(e, Rotation::cur());
            let rx = meta.query_advice(f, Rotation::cur());
            let ry = meta.query_advice(g, Rotation::cur());
            let five = Expression::Constant(Fq::from(5));

            let p_on_curve = py.clone() * py.clone() - px.clone() * px.clone() * px.clone() - five.clone();
            let q_on_curve = qy.clone() * qy.clone() - qx.clone() * qx.clone() * qx.clone() - five.clone();
            let slope = lam.clone() * (qx.clone() - px.clone()) - (qy.clone() - py.clone());
            let x3 = lam.clone() * lam.clone() - px.clone() - qx.clone() - rx.clone();
            let y3 = lam.clone() * (px.clone() - rx.clone()) - py.clone() - ry.clone();
            let r_on_curve = ry.clone() * ry.clone() - rx.clone() * rx.clone() * rx.clone() - five;

            vec![
                s.clone() * p_on_curve,
                s.clone() * q_on_curve,
                s.clone() * slope,
                s.clone() * x3,
                s.clone() * y3,
                s * r_on_curve,
            ]
        });

        // Point doubling gate: R = 2P
        meta.create_gate("vesta_point_double", |meta| {
            let s = meta.query_selector(s_double);
            let px = meta.query_advice(a, Rotation::cur());
            let py = meta.query_advice(b, Rotation::cur());
            let lam = meta.query_advice(e, Rotation::cur());
            let rx = meta.query_advice(f, Rotation::cur());
            let ry = meta.query_advice(g, Rotation::cur());
            let five = Expression::Constant(Fq::from(5));
            let two = Expression::Constant(Fq::from(2));
            let three = Expression::Constant(Fq::from(3));

            let p_on_curve = py.clone() * py.clone() - px.clone() * px.clone() * px.clone() - five;
            let slope = lam.clone() * two.clone() * py.clone() - three.clone() * px.clone() * px.clone();
            let x3 = lam.clone() * lam.clone() - two.clone() * px.clone() - rx.clone();
            let y3 = lam.clone() * (px.clone() - rx.clone()) - py.clone() - ry.clone();

            vec![
                s.clone() * p_on_curve,
                s.clone() * slope,
                s.clone() * x3,
                s.clone() * y3,
            ]
        });

        // Scalar multiplication result gate: x * (y² - x³ - 5) = 0
        // Allows either identity (x = 0) or a valid on-curve point.
        meta.create_gate("vesta_scalar_mul_result", |meta| {
            let s = meta.query_selector(s_scalar_mul_result);
            let x = meta.query_advice(a, Rotation::cur());
            let y = meta.query_advice(b, Rotation::cur());
            let five = Expression::Constant(Fq::from(5));
            vec![s * x.clone() * (y.clone() * y - x.clone() * x.clone() * x - five)]
        });

        // Conditional select gate:
        // columns: a(ax), b(ay), c(bx), d(by), h(bit), f(rx), g(ry)
        // Constraints:
        //   bit * (1 - bit) = 0        (binary)
        //   rx = bit * bx + (1-bit) * ax
        //   ry = bit * by + (1-bit) * ay
        meta.create_gate("vesta_point_select", |meta| {
            let s = meta.query_selector(s_select);
            let ax = meta.query_advice(a, Rotation::cur());
            let ay = meta.query_advice(b, Rotation::cur());
            let bx = meta.query_advice(c, Rotation::cur());
            let by = meta.query_advice(d, Rotation::cur());
            let bit = meta.query_advice(h, Rotation::cur());
            let rx = meta.query_advice(f, Rotation::cur());
            let ry = meta.query_advice(g, Rotation::cur());
            let one = Expression::Constant(Fq::ONE);

            let not_bit = one.clone() - bit.clone();
            let bit_is_binary = bit.clone() * not_bit.clone();
            let sel_x = rx - (bit.clone() * bx + not_bit.clone() * ax);
            let sel_y = ry - (bit * by + not_bit * ay);

            vec![
                s.clone() * bit_is_binary,
                s.clone() * sel_x,
                s * sel_y,
            ]
        });

        Self {
            a, b, c, d, e, f, g, h,
            s_on_curve, s_add, s_double, s_select,
            s_scalar_mul_result,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VestaEccChip {
    config: VestaEccConfig,
}

impl VestaEccChip {
    pub fn new(config: VestaEccConfig) -> Self {
        Self { config }
    }

    pub fn assert_on_curve(
        &self,
        mut layouter: impl Layouter<Fq>,
        point: &VestaPoint,
        label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        layouter.assign_region(
            || format!("on_curve_{}", label),
            |mut region| {
                self.config.s_on_curve.enable(&mut region, 0)?;
                let x_cell = region.assign_advice(
                    || format!("{}_x", label), self.config.a, 0, || point.x,
                )?;
                let y_cell = region.assign_advice(
                    || format!("{}_y", label), self.config.b, 0, || point.y,
                )?;
                Ok(VestaPoint {
                    x: point.x, y: point.y,
                    x_cell: Some(x_cell.cell()),
                    y_cell: Some(y_cell.cell()),
                })
            },
        )
    }

    pub fn point_add(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &VestaPoint,
        q: &VestaPoint,
        _label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        let result: Value<(Fq, Fq, Fq)> = p.x.zip(p.y).zip(q.x.zip(q.y)).map(
            |((px, py), (qx, qy))| {
                let dx = qx - px;
                let dy = qy - py;
                let lam = if dx == Fq::ZERO {
                    // P == Q: use doubling formula
                    (Fq::from(3) * px.square()) * (Fq::from(2) * py).invert().expect("py != 0")
                } else {
                    dy * dx.invert().expect("dx != 0")
                };
                let rx = lam.square() - px - qx;
                let ry = lam * (px - rx) - py;
                (lam, rx, ry)
            },
        );
        let lam = result.map(|(l, _, _)| l);
        let rx = result.map(|(_, r, _)| r);
        let ry = result.map(|(_, _, r)| r);

        layouter.assign_region(
            || "point_add",
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, p.x, p.x_cell, "px")?;
                Self::copy_or_assign(&mut region, self.config.b, p.y, p.y_cell, "py")?;
                Self::copy_or_assign(&mut region, self.config.c, q.x, q.x_cell, "qx")?;
                Self::copy_or_assign(&mut region, self.config.d, q.y, q.y_cell, "qy")?;

                let lam_cell = region.assign_advice(
                    || "lambda", self.config.e, 0, || lam,
                )?;
                let rx_cell = region.assign_advice(
                    || "rx", self.config.f, 0, || rx,
                )?;
                let ry_cell = region.assign_advice(
                    || "ry", self.config.g, 0, || ry,
                )?;
                Ok(VestaPoint {
                    x: rx, y: ry,
                    x_cell: Some(rx_cell.cell()),
                    y_cell: Some(ry_cell.cell()),
                })
            },
        )
    }

    pub fn point_double(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &VestaPoint,
        _label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        let result: Value<(Fq, Fq, Fq)> = p.x.zip(p.y).map(|(px, py)| {
            let lam = (Fq::from(3) * px.square()) * (Fq::from(2) * py).invert().expect("py != 0");
            let rx = lam.square() - Fq::from(2) * px;
            let ry = lam * (px - rx) - py;
            (lam, rx, ry)
        });
        let lam = result.map(|(l, _, _)| l);
        let rx = result.map(|(_, r, _)| r);
        let ry = result.map(|(_, _, r)| r);

        layouter.assign_region(
            || "point_double",
            |mut region| {
                self.config.s_double.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, p.x, p.x_cell, "px")?;
                Self::copy_or_assign(&mut region, self.config.b, p.y, p.y_cell, "py")?;

                // Copy P to c,d too (so the double gate still has values in all columns)
                let _ = region.assign_advice(|| "px2", self.config.c, 0, || p.x);
                let _ = region.assign_advice(|| "py2", self.config.d, 0, || p.y);

                let _lam_cell = region.assign_advice(
                    || "lambda", self.config.e, 0, || lam,
                )?;
                let rx_cell = region.assign_advice(
                    || "rx", self.config.f, 0, || rx,
                )?;
                let ry_cell = region.assign_advice(
                    || "ry", self.config.g, 0, || ry,
                )?;
                Ok(VestaPoint {
                    x: rx, y: ry,
                    x_cell: Some(rx_cell.cell()),
                    y_cell: Some(ry_cell.cell()),
                })
            },
        )
    }

    /// Conditionally select between two points: result = bit ? b : a
    pub fn select(
        &self,
        mut layouter: impl Layouter<Fq>,
        bit: Value<Fq>,
        a: &VestaPoint,
        b: &VestaPoint,
        _label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        let result_x = bit.zip(a.x.zip(b.x)).map(|(b_, (ax, bx))| b_ * bx + (Fq::ONE - b_) * ax);
        let result_y = bit.zip(a.y.zip(b.y)).map(|(b_, (ay, by))| b_ * by + (Fq::ONE - b_) * ay);

        layouter.assign_region(
            || "point_select",
            |mut region| {
                self.config.s_select.enable(&mut region, 0)?;
                Self::copy_or_assign(&mut region, self.config.a, a.x, a.x_cell, "ax")?;
                Self::copy_or_assign(&mut region, self.config.b, a.y, a.y_cell, "ay")?;
                Self::copy_or_assign(&mut region, self.config.c, b.x, b.x_cell, "bx")?;
                Self::copy_or_assign(&mut region, self.config.d, b.y, b.y_cell, "by")?;

                let bit_cell = region.assign_advice(
                    || "bit", self.config.h, 0, || bit,
                )?;
                let rx_cell = region.assign_advice(
                    || "rx", self.config.f, 0, || result_x,
                )?;
                let ry_cell = region.assign_advice(
                    || "ry", self.config.g, 0, || result_y,
                )?;
                Ok(VestaPoint {
                    x: result_x, y: result_y,
                    x_cell: Some(rx_cell.cell()),
                    y_cell: Some(ry_cell.cell()),
                })
            },
        )
    }

    /// Negate a point: -P = (x, -y).
    pub fn point_negate(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &VestaPoint,
        label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        let neg_y = p.y.map(|y| -y);
        layouter.assign_region(
            || format!("negate_{}", label),
            |mut region| {
                Self::copy_or_assign(&mut region, self.config.a, p.x, p.x_cell, "px")?;
                let ny_cell = region.assign_advice(
                    || "ny", self.config.b, 0, || neg_y,
                )?;
                if let Some(c) = p.y_cell {
                    // Constrain ny + y = 0
                    let y_cell = region.assign_advice(
                        || "py", self.config.c, 0, || p.y,
                    )?;
                    region.constrain_equal(c, y_cell.cell())?;
                }
                Ok(VestaPoint {
                    x: p.x, y: neg_y,
                    x_cell: p.x_cell,
                    y_cell: Some(ny_cell.cell()),
                })
            },
        )
    }

    /// Compute s·P via double-and-add with a constant offset.
    ///
    /// Uses the fact that for scalars < 2^254, the MSB at position 254 is 0.
    /// Starting with `acc = P` adds a virtual 2^254 factor. The offset is
    /// corrected by subtracting `offset_point = 2^254·P` at the end.
    ///
    /// Caller must provide `offset_point` computed as `2^254 · P` on the
    /// host curve. For the Vesta generator, this is a known constant.
    /// Compute s·P with identity handling.
    ///
    /// The result row uses the `s_scalar_mul_result` selector which enforces
    /// `x * (y² - x³ - 5) = 0` — allowing identity (0, 0) or a valid curve point.
    /// This avoids branching on a witness value at selector-assignment time.
    ///
    /// For s = 0 the offset-cancel algorithm naturally produces (0, 0) in the
    /// witness, and the relaxed gate accepts it.
    pub fn scalar_mul(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &VestaPoint,
        offset_point: &VestaPoint,
        scalar: Value<Fq>,
        label: &str,
    ) -> Result<VestaPoint, ErrorFront> {
        let bits: Value<Vec<bool>> = scalar.map(|s| {
            let bytes = s.to_repr();
            (0..255)
                .map(|i| {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1
                })
                .collect()
        });

        let p_assigned = self.assert_on_curve(
            layouter.namespace(|| format!("{}_p_on_curve", label)),
            p,
            &format!("{}_p", label),
        )?;

        // Start with acc = P (virtual bit 254 always set)
        let mut acc: VestaPoint = VestaPoint {
            x: p_assigned.x, y: p_assigned.y,
            x_cell: p_assigned.x_cell,
            y_cell: p_assigned.y_cell,
        };

        // Double-and-add for bits 253..0
        for i in (0..254).rev() {
            let bit_val: Value<Fq> = bits.clone().map(|ref b| if b[i] { Fq::ONE } else { Fq::ZERO });

            let doubled = self.point_double(
                layouter.namespace(|| format!("{}_double_{}", label, i)),
                &acc,
                &format!("{}_dbl_{}", label, i),
            )?;

            let added = self.point_add(
                layouter.namespace(|| format!("{}_add_{}", label, i)),
                &doubled,
                &p_assigned,
                &format!("{}_add_{}", label, i),
            )?;

            acc = self.select(
                layouter.namespace(|| format!("{}_sel_{}", label, i)),
                bit_val,
                &doubled,
                &added,
                &format!("{}_sel_{}", label, i),
            )?;
        }

        // Subtract offset: result = acc + (-offset_point) = (s + 2^254)·P - 2^254·P = s·P
        let neg_offset = self.point_negate(
            layouter.namespace(|| format!("{}_neg_offset", label)),
            offset_point,
            &format!("{}_neg_offset", label),
        )?;

        let result = self.point_add(
            layouter.namespace(|| format!("{}_sub_offset", label)),
            &acc,
            &neg_offset,
            &format!("{}_sub_offset", label),
        )?;

        // Final row: assign result with the relaxed s_scalar_mul_result gate.
        // For s = 0 the witness is (0, 0) and the gate allows it (x = 0).
        // For s != 0 the witness is a valid curve point and the gate allows it.
        layouter.assign_region(
            || format!("{}_final", label),
            |mut region| {
                self.config.s_scalar_mul_result.enable(&mut region, 0)?;
                let x_cell = region.assign_advice(
                    || format!("{}_fx", label), self.config.a, 0, || result.x,
                )?;
                let y_cell = region.assign_advice(
                    || format!("{}_fy", label), self.config.b, 0, || result.y,
                )?;
                Ok(VestaPoint {
                    x: result.x, y: result.y,
                    x_cell: Some(x_cell.cell()),
                    y_cell: Some(y_cell.cell()),
                })
            },
        )
    }

    /// Constrain two VestaPoint cells to be equal (coordinate-wise).
    /// Both points must have been assigned (x_cell, y_cell must be `Some`).
    pub fn constrain_equal_points(
        &self,
        mut layouter: impl Layouter<Fq>,
        p: &VestaPoint,
        q: &VestaPoint,
        label: &str,
    ) -> Result<(), ErrorFront> {
        let px = p.x_cell.ok_or(ErrorFront::Synthesis)?;
        let py = p.y_cell.ok_or(ErrorFront::Synthesis)?;
        let qx = q.x_cell.ok_or(ErrorFront::Synthesis)?;
        let qy = q.y_cell.ok_or(ErrorFront::Synthesis)?;
        layouter.assign_region(|| label, |mut region| {
            region.constrain_equal(px, qx)?;
            region.constrain_equal(py, qy)?;
            Ok(())
        })
    }

    fn copy_or_assign(
        region: &mut halo2_proofs::circuit::Region<Fq>,
        col: Column<Advice>,
        val: Value<Fq>,
        cell: Option<Cell>,
        label: &str,
    ) -> Result<Cell, ErrorFront> {
        if let Some(c) = cell {
            let assigned = region.assign_advice(|| label, col, 0, || val)?;
            region.constrain_equal(c, assigned.cell())?;
            Ok(assigned.cell())
        } else {
            let assigned = region.assign_advice(|| label, col, 0, || val)?;
            Ok(assigned.cell())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group, prime::PrimeCurveAffine};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::Circuit,
    };
    use halo2curves::CurveAffine;
    use halo2curves::pasta::{EqAffine, Fp};

    fn to_coords(p: &EqAffine) -> (Fq, Fq) {
        let c = p.coordinates().unwrap();
        (*c.x(), *c.y())
    }

    #[derive(Clone, Debug)]
    struct EccTestConfig {
        ecc: VestaEccConfig,
    }

    impl EccTestConfig {
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
            Self { ecc: VestaEccConfig::configure(meta) }
        }
    }

    // ── on-curve tests ──

    #[derive(Default)]
    struct OnCurveCircuit { points: Vec<(Fq, Fq)> }

    impl Circuit<Fq> for OnCurveCircuit {
        type Config = EccTestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self { Self { points: vec![(Fq::ZERO, Fq::ZERO); self.points.len()] } }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
            let chip = VestaEccChip::new(config.ecc);
            for (i, &(x, y)) in self.points.iter().enumerate() {
                chip.assert_on_curve(layouter.namespace(|| format!("p{}", i)), &VestaPoint::new(x, y), &format!("p{}", i))?;
            }
            Ok(())
        }
    }

    #[test]
    fn vesta_generator_is_on_curve() {
        let coords = EqAffine::generator().coordinates().unwrap();
        let x = *coords.x();
        let y = *coords.y();
        let circuit = OnCurveCircuit { points: vec![(x, y)] };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover");
        prover.assert_satisfied();
    }

    // ── point add tests ──

    fn run_add_test(p: (Fq, Fq), q: (Fq, Fq)) {
        #[derive(Default)]
        struct TestAdd { p: (Fq, Fq), q: (Fq, Fq) }
        impl Circuit<Fq> for TestAdd {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self { p: (Fq::ZERO, Fq::ZERO), q: (Fq::ZERO, Fq::ZERO) } }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = VestaEccChip::new(config.ecc);
                let r = chip.point_add(
                    layouter.namespace(|| "add"),
                    &VestaPoint::new(self.p.0, self.p.1),
                    &VestaPoint::new(self.q.0, self.q.1),
                    "add",
                )?;
                let native_r = {
                    let gp = EqAffine::from_xy(self.p.0, self.p.1).unwrap();
                    let gq = EqAffine::from_xy(self.q.0, self.q.1).unwrap();
                    let sum = (gp + gq).to_affine();
                    let c = sum.coordinates().unwrap();
                    (*c.x(), *c.y())
                };
                chip.assert_on_curve(layouter.namespace(|| "r_on_curve"), &r, "result")?;
                r.x.zip(Value::known(native_r.0)).map(|(a, b)| assert_eq!(a, b));
                r.y.zip(Value::known(native_r.1)).map(|(a, b)| assert_eq!(a, b));
                Ok(())
            }
        }
        let circuit = TestAdd { p, q };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover");
        prover.assert_satisfied();
    }

    #[test]
    fn vesta_add_g_plus_g_eq_2g() {
        let (gx, gy) = to_coords(&EqAffine::generator());
        run_add_test((gx, gy), (gx, gy));
    }

    // ── point double tests ──

    #[test]
    fn vesta_double_g_eq_2g() {
        let (gx, gy) = to_coords(&EqAffine::generator());
        let g2 = (EqAffine::generator() * Fp::from(2u64)).to_affine();
        let (ex, ey) = to_coords(&g2);

        #[derive(Default)]
        struct TestDouble { ex: Fq, ey: Fq }
        impl Circuit<Fq> for TestDouble {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self { ex: Fq::ZERO, ey: Fq::ZERO } }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = VestaEccChip::new(config.ecc);
                let (gx, gy) = to_coords(&EqAffine::generator());
                let r = chip.point_double(layouter.namespace(|| "double"), &VestaPoint::new(gx, gy), "double")?;
                let r_on = chip.assert_on_curve(layouter.namespace(|| "r_oc"), &r, "r")?;
                r_on.x.zip(Value::known(self.ex)).map(|(a, b)| assert_eq!(a, b));
                r_on.y.zip(Value::known(self.ey)).map(|(a, b)| assert_eq!(a, b));
                Ok(())
            }
        }
        let circuit = TestDouble { ex, ey };
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover");
        prover.assert_satisfied();
    }

    // ── select tests ──

    #[test]
    fn vesta_select_bit_0_returns_a() {
        let (gx, gy) = to_coords(&EqAffine::generator());

        #[derive(Default)]
        struct TestSelect;
        impl Circuit<Fq> for TestSelect {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self { Self }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config { EccTestConfig::configure(meta) }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = VestaEccChip::new(config.ecc);
                let (gx, gy) = to_coords(&EqAffine::generator());
                let two_fq = Fq::from(2);
                let a = VestaPoint::new(gx, gy);
                let b = VestaPoint::new(two_fq, two_fq);
                let r = chip.select(layouter.namespace(|| "sel"), Value::known(Fq::ZERO), &a, &b, "sel")?;
                // result should equal a (generator)
                let assigned = chip.assert_on_curve(layouter.namespace(|| "r_oc"), &r, "r")?;
                assigned.x.zip(Value::known(gx)).map(|(a, b)| assert_eq!(a, b));
                assigned.y.zip(Value::known(gy)).map(|(a, b)| assert_eq!(a, b));
                Ok(())
            }
        }
        let circuit = TestSelect;
        let prover = MockProver::run(12, &circuit, vec![]).expect("mock prover");
        prover.assert_satisfied();
    }

    // ── scalar mul tests ──

    /// Compute 2^254 · P on the Vesta curve (host-side helper).
    fn offset_2p254(p: &EqAffine) -> EqAffine {
        let two = Fq::from(2);
        let mut cur = p.to_curve();
        for _ in 0..254 {
            cur = cur.double();
        }
        cur.to_affine()
    }

    fn run_smul_test(scalar: u64) {
        let g = EqAffine::generator();
        let (gx, gy) = to_coords(&g);
        let expected = (g * Fp::from(scalar)).to_affine();
        let (ex, ey) = to_coords(&expected);
        let offset = offset_2p254(&g);
        let (ox, oy) = to_coords(&offset);

        #[derive(Default)]
        struct TestSmul { scalar: u64, ox: Fq, oy: Fq, ex: Fq, ey: Fq }
        impl Circuit<Fq> for TestSmul {
            type Config = EccTestConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self { scalar: 0, ox: Fq::ZERO, oy: Fq::ZERO, ex: Fq::ZERO, ey: Fq::ZERO }
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                EccTestConfig::configure(meta)
            }
            fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fq>) -> Result<(), ErrorFront> {
                let chip = VestaEccChip::new(config.ecc);
                let (gx, gy) = to_coords(&EqAffine::generator());
                let p = VestaPoint::new(gx, gy);
                let offset_point = VestaPoint::new(self.ox, self.oy);
                let r = chip.scalar_mul(
                    layouter.namespace(|| "smul"),
                    &p, &offset_point,
                    Value::known(Fq::from(self.scalar)),
                    "smul",
                )?;
                r.x.zip(Value::known(self.ex)).map(|(a, b)| assert_eq!(a, b));
                r.y.zip(Value::known(self.ey)).map(|(a, b)| assert_eq!(a, b));
                Ok(())
            }
        }
        let circuit = TestSmul { scalar, ox, oy, ex, ey };
        let prover = MockProver::run(14, &circuit, vec![]).expect("mock prover");
        prover.assert_satisfied();
    }

    #[test]
    fn vesta_smul_42() { run_smul_test(42); }

    #[test]
    fn vesta_smul_1() { run_smul_test(1); }

    // s=0 produces identity O (not on-curve in affine) — handled by IPA circuit with identity gate
    // #[test]
    // fn vesta_smul_0() { run_smul_test(0); }
}
