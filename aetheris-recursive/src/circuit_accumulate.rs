//! Native Vesta accumulator update circuit (§C).
//!
//! Verifies the accumulator transition from (Q_old, transcript_old, depth_old)
//! to (Q_new, transcript_new, depth_new) across one or more transactions.
//!
//! Per tx:
//!   1. challenge = Poseidon(Poseidon(domain, transcript_old), ipe)
//!   2. pi_commitment is on-curve
//!   3. Q_new = Q_old + challenge · pi_commitment
//!   4. transcript_new = Poseidon(Poseidon(transcript_old, challenge), Poseidon(Q_new.x, ipe))
//!   5. depth_new = depth_old + 1
//!
//! Public instances (4 cells):
//!   [0] Q_new.x    [1] Q_new.y
//!   [2] transcript_new
//!   [3] depth_new

use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::pasta::Fq,
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};

use aetheris_zkp::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};

use crate::vesta_ecc::{VestaEccChip, VestaEccConfig, VestaPoint};
use crate::vesta_fq::{VestaFqChip, VestaFqConfig};
use crate::Limb;

/// Number of public instance cells (Q.x, Q.y, transcript, depth).
pub const NUM_INSTANCES: usize = 4;

/// Domain separator for the hash chain.
const TRANSCRIPT_DOMAIN_FQ: Fq = Fq::from_raw([
    0x0000000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x224698fc094cf91b,
]);

/// Per-transaction witness data (host-precomputed).
#[derive(Clone, Debug)]
pub struct TxWitness {
    pub ipe: Value<Fq>,
    pub pi_commitment: VestaPoint,
    pub pi_commitment_offset: VestaPoint,
}

/// Configuration columns.
#[derive(Clone, Debug)]
pub struct AccumulateConfig {
    pub poseidon: PoseidonFqConfig,
    pub ecc: VestaEccConfig,
    pub fq: VestaFqConfig,
    pub instance: Column<Instance>,
    pub tx: AccumulateTxColumns,
}

#[derive(Clone, Debug)]
pub struct AccumulateTxColumns {
    pub ipe: Column<Advice>,
    pub pi_cmt_x: Column<Advice>,
    pub pi_cmt_y: Column<Advice>,
    pub pi_cmt_off_x: Column<Advice>,
    pub pi_cmt_off_y: Column<Advice>,
}

/// Accumulator update circuit.
#[derive(Clone, Debug)]
pub struct AccumulatorCircuit {
    pub q_old: VestaPoint,
    pub transcript_old: Value<Fq>,
    pub depth_old: Value<Fq>,
    pub txs: Vec<TxWitness>,
    pub q_new: VestaPoint,
    pub transcript_new: Value<Fq>,
    pub depth_new: Value<Fq>,
}

impl Default for AccumulatorCircuit {
    fn default() -> Self {
        Self {
            q_old: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_old: Value::known(Fq::ZERO),
            depth_old: Value::known(Fq::ZERO),
            txs: vec![],
            q_new: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_new: Value::known(Fq::ZERO),
            depth_new: Value::known(Fq::ZERO),
        }
    }
}

impl AccumulatorCircuit {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> AccumulateConfig {
        let poseidon = PoseidonFqChip::configure(meta);
        let ecc = VestaEccConfig::configure(meta);
        let fq = VestaFqConfig::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let ipe = meta.advice_column();
        let pi_cmt_x = meta.advice_column();
        let pi_cmt_y = meta.advice_column();
        let pi_cmt_off_x = meta.advice_column();
        let pi_cmt_off_y = meta.advice_column();
        meta.enable_equality(ipe);
        meta.enable_equality(pi_cmt_x);
        meta.enable_equality(pi_cmt_y);
        meta.enable_equality(pi_cmt_off_x);
        meta.enable_equality(pi_cmt_off_y);

        AccumulateConfig {
            poseidon,
            ecc,
            fq,
            instance,
            tx: AccumulateTxColumns {
                ipe,
                pi_cmt_x,
                pi_cmt_y,
                pi_cmt_off_x,
                pi_cmt_off_y,
            },
        }
    }
}

impl Circuit<Fq> for AccumulatorCircuit {
    type Config = AccumulateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        Self::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let poseidon = PoseidonFqChip::new(config.poseidon.clone());
        let ecc = VestaEccChip::new(config.ecc.clone());
        let fq = VestaFqChip::new(config.fq.clone());

        // ══ Load previous accumulator state ══
        let q_cur = assign_point(&ecc, &mut layouter, &config, &self.q_old, "q_old")?;
        let transcript_cell =
            assign_fq_cell(&mut layouter, &config, self.transcript_old, "transcript_old")?;
        let depth_cell =
            assign_fq_cell(&mut layouter, &config, self.depth_old, "depth_old")?;

        let mut q_cur = q_cur;
        let mut transcript_cur = transcript_cell;
        let mut depth_cur = Limb {
            value: self.depth_old,
            cell: Some(depth_cell.cell()),
        };

        // ══ Process each transaction ══
        for tx in &self.txs {
            // -- Assign per-tx witnesses --
            let ipe = assign_fq_cell(&mut layouter, &config, tx.ipe, "ipe")?;
            let pi_cmt = assign_point(&ecc, &mut layouter, &config, &tx.pi_commitment, "pi_cmt")?;
            let pi_off =
                raw_assign_point(&mut layouter, &config, &tx.pi_commitment_offset, "pi_off")?;

            // -- Challenge = Poseidon(Poseidon(domain, transcript_cur), ipe) --
            let chal_tmp = poseidon.assign_hash(
                layouter.namespace(|| "chal_tmp"),
                Value::known(TRANSCRIPT_DOMAIN_FQ),
                v(transcript_cur.value()),
                None,
                Some(transcript_cur.cell()),
            )?;
            let challenge = poseidon.assign_hash(
                layouter.namespace(|| "challenge"),
                v(chal_tmp.value()),
                v(ipe.value()),
                Some(chal_tmp.cell()),
                Some(ipe.cell()),
            )?;

            // -- Q_new = Q_cur + challenge · pi_commitment --
            let scaled = ecc.scalar_mul(
                layouter.namespace(|| "scaled"),
                &pi_cmt,
                &pi_off,
                v(challenge.value()),
                "challenge*pi",
            )?;
            let q_new = ecc.point_add(
                layouter.namespace(|| "q_new"),
                &q_cur,
                &scaled,
                "q_cur + scaled",
            )?;

            // -- Transcript chain --
            // h1 = Poseidon(transcript_cur, challenge)
            let h1 = poseidon.assign_hash(
                layouter.namespace(|| "h1"),
                v(transcript_cur.value()),
                v(challenge.value()),
                Some(transcript_cur.cell()),
                Some(challenge.cell()),
            )?;
            // h2 = Poseidon(q_new.x, ipe)
            let h2 = poseidon.assign_hash(
                layouter.namespace(|| "h2"),
                q_new.x,
                v(ipe.value()),
                q_new.x_cell,
                Some(ipe.cell()),
            )?;
            // transcript_new = Poseidon(h1, h2)
            let transcript_new = poseidon.assign_hash(
                layouter.namespace(|| "transcript_new"),
                v(h1.value()),
                v(h2.value()),
                Some(h1.cell()),
                Some(h2.cell()),
            )?;

            // -- Depth = depth + 1 --
            let one = fq.assign_constant(layouter.namespace(|| "one"), Fq::ONE, "one")?;
            let depth_new = fq.add(
                layouter.namespace(|| "depth_inc"),
                &depth_cur,
                &one,
                "depth",
            )?;

            q_cur = q_new;
            transcript_cur = transcript_new;
            depth_cur = depth_new;
        }

        // ══ Constrain public instances ══
        if let Some(cell) = q_cur.x_cell {
            layouter.constrain_instance(cell, config.instance, 0)?;
        }
        if let Some(cell) = q_cur.y_cell {
            layouter.constrain_instance(cell, config.instance, 1)?;
        }
        layouter.constrain_instance(transcript_cur.cell(), config.instance, 2)?;
        if let Some(cell) = depth_cur.cell {
            layouter.constrain_instance(cell, config.instance, 3)?;
        }

        Ok(())
    }
}

/// Convert `Value<&Fq>` (from `AssignedCell::value()`) to `Value<Fq>`.
fn v(val: Value<&Fq>) -> Value<Fq> {
    val.map(|&v| v)
}

// ── Helper functions ──

fn assign_fq_cell(
    layouter: &mut impl Layouter<Fq>,
    config: &AccumulateConfig,
    val: Value<Fq>,
    label: &str,
) -> Result<AssignedCell<Fq, Fq>, ErrorFront> {
    layouter.assign_region(
        || format!("assign_fq_{}", label),
        |mut region| region.assign_advice(|| label, config.tx.ipe, 0, || val),
    )
}

fn assign_point(
    ecc: &VestaEccChip,
    layouter: &mut impl Layouter<Fq>,
    config: &AccumulateConfig,
    pt: &VestaPoint,
    label: &str,
) -> Result<VestaPoint, ErrorFront> {
    let raw = raw_assign_point(layouter, config, pt, label)?;
    ecc.assert_on_curve(
        layouter.namespace(|| format!("on_curve_{}", label)),
        &raw,
        label,
    )
}

fn raw_assign_point(
    layouter: &mut impl Layouter<Fq>,
    config: &AccumulateConfig,
    pt: &VestaPoint,
    label: &str,
) -> Result<VestaPoint, ErrorFront> {
    layouter.assign_region(
        || format!("raw_point_{}", label),
        |mut region| {
            let x_cell = region.assign_advice(
                || format!("{}_x", label),
                config.tx.pi_cmt_x,
                0,
                || pt.x,
            )?;
            let y_cell = region.assign_advice(
                || format!("{}_y", label),
                config.tx.pi_cmt_y,
                0,
                || pt.y,
            )?;
            Ok(VestaPoint {
                x: pt.x,
                y: pt.y,
                x_cell: Some(x_cell.cell()),
                y_cell: Some(y_cell.cell()),
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::prime::PrimeCurveAffine;
    use halo2_proofs::halo2curves::CurveAffine;
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::pasta::EqAffine,
    };

    fn generator_coords() -> (Fq, Fq) {
        let g = EqAffine::generator();
        let coords = g.coordinates().unwrap();
        (*coords.x(), *coords.y())
    }

    #[test]
    fn test_empty_tx() {
        let (gx, gy) = generator_coords();
        let circuit = AccumulatorCircuit {
            q_old: VestaPoint::new(gx, gy),
            transcript_old: Value::known(Fq::from(42)),
            depth_old: Value::known(Fq::from(7)),
            txs: vec![],
            q_new: VestaPoint::new(gx, gy),
            transcript_new: Value::known(Fq::from(42)),
            depth_new: Value::known(Fq::from(7)),
        };
        let instances = vec![vec![gx, gy, Fq::from(42), Fq::from(7)]];
        let prover = MockProver::run(5, &circuit, instances).expect("mock prover");
        assert_eq!(prover.verify(), Ok(()));
    }
}
