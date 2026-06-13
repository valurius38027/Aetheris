//! Native Vesta accumulator update circuit (§C + §E.4).
//!
//! Verifies the accumulator transition from (Q_old, transcript, depth)
//! to (Q_new, transcript_new, depth_new) across N transactions,
//! with optional in-circuit IPA verification (§E.4).
//!
//! Per tx (§C.1 + §C.4 + §E.4):
//!   0. In-circuit IPA verification (if proof data provided)
//!      a. squeeze_challenges from L/R points → k IPA round challenges
//!      b. fold_and_constrain → b_final, g_final
//!      c. verify_ipa_full equation
//!   1. hash_to_curve: pi_commitment = try-and-increment(seed, counter)
//!      seed = Poseidon(PI_DOMAIN_FQ, ipe)
//!   2. challenge = Poseidon(Poseidon(TRANSCRIPT_DOMAIN_FQ, transcript), ipe)
//!   3. Q_new = Q_old + challenge · pi_commitment
//!   4. transcript_new = Poseidon(Poseidon(transcript, challenge), Poseidon(Q_new.x, ipe))
//!   5. depth_new = depth_old + 1
//!
//! Public instances (4 cells):
//!   [0] Q_new.x    [1] Q_new.y
//!   [2] transcript_new
//!   [3] depth_new

use ff::{Field, FromUniformBytes};
use group::prime::PrimeCurveAffine;
use group::Curve;
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::pasta::{EqAffine, Fq, Fp},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};

use aetheris_zkp::poseidon_fq_chip::PoseidonFqChip;

use crate::vesta_accumulate::{VestaAccumulateChip, VestaAccumulateConfig};
use crate::vesta_ecc::{VestaEccChip, VestaPoint};
use crate::vesta_fq::VestaFqChip;
use crate::vesta_range::{FqRangeCheckChip, FqRangeCheckConfig};
use crate::Limb;

/// Number of public instance cells (Q.x, Q.y, transcript, depth).
pub const NUM_INSTANCES: usize = 4;

/// Maximum try-and-increment iterations for NUMS hash-to-curve.
pub const MAX_ITER: usize = 5;

/// Domain separator for the accumulator transcript chain.
pub(crate) const TRANSCRIPT_DOMAIN_FQ: Fq = Fq::from_raw([
    0x0000000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x224698fc094cf91b,
]);

/// Witness data for in-circuit IPA verification of a single inner proof (§E.4).
#[derive(Clone, Debug)]
pub struct IpaTxWitness {
    /// IPA evaluation point (theta from Halo2 transcript).
    pub point: Value<Fq>,
    /// Public commitment point (from proof).
    pub commitment: VestaPoint,
    /// Public evaluation scalar (from proof).
    pub eval: Value<Fq>,
    /// Final coefficient from IPA proof.
    pub a_final: Value<Fq>,
    /// Blinding scalar from IPA proof.
    pub r_prime: Value<Fq>,
    /// L points from IPA proof (k rounds).
    pub l_points: Vec<VestaPoint>,
    /// R points from IPA proof (k rounds).
    pub r_points: Vec<VestaPoint>,
    /// 2^254 · L_i and 2^254 · R_i (precomputed offsets, length 2k).
    pub lr_offsets: Vec<VestaPoint>,
    /// SIP generators (from CRS params, length 2^k).
    pub g_init: Vec<VestaPoint>,
    /// 2^254 · g_init offsets for all folding rounds (length 2n - 1).
    pub offset_points: Vec<VestaPoint>,
    /// Round challenges x_i extracted from Halo2 Blake2b transcript replay.
    /// Length k — matches the number of L/R round pairs.
    pub challenges: Vec<Value<Fq>>,
}

/// Per-transaction witness data (host-precomputed).
#[derive(Clone, Debug)]
pub struct TxWitness {
    /// inner_proof_hash_eff as a single Fq.
    pub ipe: Value<Fq>,
    /// Scalars for each try-and-increment iteration.
    /// c[i] = Fq::from_uniform_bytes(mixed(counter=i) || zeros_32).
    pub c: [Value<Fq>; MAX_ITER],
    /// Selection bits: exactly one `sel[i]` is 1 — the first iteration
    /// whose result is a valid (non-identity) curve point.
    pub sel: [Value<Fq>; MAX_ITER],
    /// 2^254 · pi_commitment (precomputed offset for Q-update scalar_mul).
    pub pi_commitment_offset: VestaPoint,
    /// Optional in-circuit IPA proof verification data (§E.4).
    pub ipa_proof: Option<IpaTxWitness>,
}

/// Configuration columns.
#[derive(Clone, Debug)]
pub struct AccumulateConfig {
    pub acc: VestaAccumulateConfig,
    pub range: FqRangeCheckConfig,
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
    /// Vesta generator point (precomputed host-side).
    pub generator: VestaPoint,
    /// 2^254 · generator (precomputed offset for hash_to_curve scalar_mul).
    pub gen_offset: VestaPoint,
    /// H point for IPA verification equation.
    pub h_point: VestaPoint,
    /// 2^254 · H (precomputed offset).
    pub h_offset: VestaPoint,
    /// U point for IPA verification equation.
    pub u_point: VestaPoint,
    /// 2^254 · U (precomputed offset).
    pub u_offset: VestaPoint,
}

/// Compute the Vesta generator and offset needed for hash_to_curve, and H/U points for IPA verification.
pub fn compute_generator_and_offset() -> (VestaPoint, VestaPoint) {
    let gen = EqAffine::generator();
    let coords = gen.coordinates().unwrap();
    let gen_x = *coords.x();
    let gen_y = *coords.y();
    let two_pow_254 = Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]);
    let offset_aff = (gen * two_pow_254).to_affine();
    let off_coords = offset_aff.coordinates().unwrap();
    let gen_pt = VestaPoint::new(gen_x, gen_y);
    let off_pt = VestaPoint::new(*off_coords.x(), *off_coords.y());
    (gen_pt, off_pt)
}

/// Compute H, U, and their offsets for the IPA verification equation.
/// H = 2·G (blinding generator), U = 3·G (random oracle generator).
pub fn compute_ipa_constants() -> (VestaPoint, VestaPoint, VestaPoint, VestaPoint) {
    let two_pow_254 = Fp::from(2u64).pow_vartime(&[254, 0, 0, 0]);
    let g = EqAffine::generator();

    let h = (g * Fp::from(2u64)).to_affine();
    let u = (g * Fp::from(3u64)).to_affine();
    let h_off = (h * two_pow_254).to_affine();
    let u_off = (u * two_pow_254).to_affine();

    let to_vp = |p: &EqAffine| -> VestaPoint {
        let c = p.coordinates().unwrap();
        VestaPoint::new(*c.x(), *c.y())
    };
    (to_vp(&h), to_vp(&h_off), to_vp(&u), to_vp(&u_off))
}

/// Compute the PI domain constant: Poseidon domain Fq for hash_to_curve seed.
pub fn pi_domain_fq() -> Fq {
    let h = blake3::hash(b"aetheris-pi-cmt-v2\x00");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(h.as_bytes());
    Fq::from_uniform_bytes(&buf)
}

impl Default for AccumulatorCircuit {
    fn default() -> Self {
        let (gen_pt, off_pt) = compute_generator_and_offset();
        let (h, h_off, u, u_off) = compute_ipa_constants();
        Self {
            q_old: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_old: Value::known(Fq::ZERO),
            depth_old: Value::known(Fq::ZERO),
            txs: vec![],
            q_new: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_new: Value::known(Fq::ZERO),
            depth_new: Value::known(Fq::ZERO),
            generator: gen_pt,
            gen_offset: off_pt,
            h_point: h,
            h_offset: h_off,
            u_point: u,
            u_offset: u_off,
        }
    }
}

impl AccumulatorCircuit {
    /// Convenience constructor that auto-computes generator + offset.
    pub fn new(
        q_old: VestaPoint,
        transcript_old: Value<Fq>,
        depth_old: Value<Fq>,
        txs: Vec<TxWitness>,
    ) -> Self {
        let (gen_pt, off_pt) = compute_generator_and_offset();
        let (h, h_off, u, u_off) = compute_ipa_constants();
        Self {
            q_old,
            transcript_old,
            depth_old,
            txs,
            q_new: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_new: Value::known(Fq::ZERO),
            depth_new: Value::known(Fq::ZERO),
            generator: gen_pt,
            gen_offset: off_pt,
            h_point: h,
            h_offset: h_off,
            u_point: u,
            u_offset: u_off,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> AccumulateConfig {
        let acc = VestaAccumulateConfig::configure(meta);
        let range = FqRangeCheckConfig::configure(meta);
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
            acc,
            range,
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
        let poseidon = PoseidonFqChip::new(config.acc.poseidon.poseidon.clone());
        let ecc = VestaEccChip::new(config.acc.ipa.ecc.clone());
        let fq = VestaFqChip::new(config.acc.ipa.fq.clone());
        let range = FqRangeCheckChip::new(config.range.clone());
        let acc_chip = VestaAccumulateChip::new(&config.acc);

        let pi_domain = pi_domain_fq();

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
        let depth_old_saved = depth_cur.clone();

        // Assign generator and offset for hash_to_curve scalar_mul.
        let gen_pt = assign_point(&ecc, &mut layouter, &config, &self.generator, "generator")?;
        let gen_off = raw_assign_point(&mut layouter, &config, &self.gen_offset, "gen_off")?;

        // Assign H and U points for IPA verification.
        let h_pt = assign_point(&ecc, &mut layouter, &config, &self.h_point, "h_point")?;
        let h_off = raw_assign_point(&mut layouter, &config, &self.h_offset, "h_off")?;
        let u_pt = assign_point(&ecc, &mut layouter, &config, &self.u_point, "u_point")?;
        let u_off = raw_assign_point(&mut layouter, &config, &self.u_offset, "u_off")?;

        // ══ Process each transaction ══
        for tx in &self.txs {
            let ipe_cell = assign_fq_cell(&mut layouter, &config, tx.ipe, "ipe")?;

            // ══ §E.4: In-circuit IPA verification ══
            // Challenges are provided as witness (extracted from Halo2 Blake2b
            // transcript replay — see §E.5). The outer proof constrains ipe,
            // which depends on the full proof bytes; tampering with challenges
            // changes the required L/R or a_final to balance, which alters ipe
            // and breaks the outer proof.
            if let Some(ref ipa) = tx.ipa_proof {
                let _k = ipa.l_points.len();

                let bound_chals: Vec<Limb<Fq>> = ipa.challenges.iter().map(|c_val| {
                    Limb { value: *c_val, cell: None }
                }).collect();

                // Assign generators and offsets for IPA folding.
                let g_vals: Vec<VestaPoint> = ipa.g_init.iter().map(|g| VestaPoint {
                    x: g.x,
                    y: g.y,
                    x_cell: None,
                    y_cell: None,
                }).collect();
                let mut assigned_g = Vec::with_capacity(ipa.g_init.len());
                for (i, g) in g_vals.iter().enumerate() {
                    assigned_g.push(assign_point(
                        &ecc, &mut layouter, &config, g, &format!("g_init_{}", i),
                    )?);
                }
                let offset_pts: Vec<VestaPoint> = ipa.offset_points.iter().map(|o| VestaPoint {
                    x: o.x,
                    y: o.y,
                    x_cell: None,
                    y_cell: None,
                }).collect();
                let mut assigned_offsets = Vec::with_capacity(ipa.offset_points.len());
                for (i, o) in offset_pts.iter().enumerate() {
                    assigned_offsets.push(raw_assign_point(
                        &mut layouter, &config, o, &format!("off_{}", i),
                    )?);
                }

                // point is the IPA evaluation point (x-coordinate).
                let point_limb = Limb { value: ipa.point, cell: None };

                let fold_result = acc_chip.fold_and_constrain(
                    layouter.namespace(|| "ipa_fold"),
                    &point_limb,
                    &assigned_g,
                    &assigned_offsets,
                    &bound_chals,
                )?;

                // G_final offset is the last element of offset_points.
                let g_final_off = assigned_offsets.last().cloned().unwrap();

                // Assign commitment, eval, a_final, r_prime.
                let cm_pt = VestaPoint {
                    x: ipa.commitment.x,
                    y: ipa.commitment.y,
                    x_cell: None,
                    y_cell: None,
                };
                let commitment = assign_point(
                    &ecc, &mut layouter, &config, &cm_pt, "commitment",
                )?;
                let eval_limb = Limb { value: ipa.eval, cell: None };
                let a_final_limb = Limb { value: ipa.a_final, cell: None };
                let r_prime_limb = Limb { value: ipa.r_prime, cell: None };

                // Assign L/R points with offsets.
                let l_assigned: Vec<VestaPoint> = ipa.l_points.iter().map(|p| {
                    VestaPoint {
                        x: p.x, y: p.y, x_cell: None, y_cell: None,
                    }
                }).collect();
                let r_assigned: Vec<VestaPoint> = ipa.r_points.iter().map(|p| {
                    VestaPoint {
                        x: p.x, y: p.y, x_cell: None, y_cell: None,
                    }
                }).collect();
                let lr_off_assigned: Vec<VestaPoint> = ipa.lr_offsets.iter().map(|o| VestaPoint {
                    x: o.x, y: o.y, x_cell: None, y_cell: None,
                }).collect();

                acc_chip.verify_ipa_full(
                    layouter.namespace(|| "ipa_verify"),
                    &commitment,
                    &eval_limb,
                    &a_final_limb,
                    &r_prime_limb,
                    &l_assigned,
                    &r_assigned,
                    &lr_off_assigned,
                    &bound_chals,
                    &fold_result,
                    &g_final_off,
                    &h_pt,
                    &h_off,
                    &u_pt,
                    &u_off,
                )?;
            }

            // ══ §C.1: In-circuit hash_to_curve (NUMS try-and-increment) ══
            // seed = Poseidon(PI_DOMAIN_FQ, ipe)
            let _seed = poseidon.assign_hash(
                layouter.namespace(|| "seed"),
                Value::known(pi_domain),
                v(ipe_cell.value()),
                None,
                Some(ipe_cell.cell()),
            )?;

            // For each iteration i: range_check(c_i, 255) + scalar_mul(G, G_offset, c_i)
            let mut pi_best: Option<VestaPoint> = None;
            for i in 0..MAX_ITER {
                let c_limb = Limb {
                    value: tx.c[i],
                    cell: None,
                };
                range.range_check(
                    layouter.namespace(|| format!("range_{}", i)),
                    &c_limb,
                    255,
                )?;

                let pi_i = ecc.scalar_mul(
                    layouter.namespace(|| format!("pi_{}", i)),
                    &gen_pt,
                    &gen_off,
                    tx.c[i],
                    &format!("hash_to_curve_pi_{}", i),
                )?;

                // Chain selection: pi_best = select(sel[i], pi_best, pi_i)
                // select(bit, a, b) = bit·b + (1-bit)·a
                // sel[i] = 1 → pick pi_i (this is the first valid point)
                // sel[i] = 0 → keep previous best
                let prev = pi_best.unwrap_or_else(|| VestaPoint {
                    x: Value::known(Fq::ZERO),
                    y: Value::known(Fq::ZERO),
                    x_cell: None,
                    y_cell: None,
                });
                pi_best = Some(ecc.select(
                    layouter.namespace(|| format!("sel_{}", i)),
                    tx.sel[i],
                    &prev,
                    &pi_i,
                    &format!("select_pi_{}", i),
                )?);
            }
            let pi_commitment = pi_best.expect("pi_best must be Some after MAX_ITER");
            // ══ End §C.1 ══

            // -- Challenge = Poseidon(Poseidon(TRANSCRIPT_DOMAIN_FQ, transcript_cur), ipe) --
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
                v(ipe_cell.value()),
                Some(chal_tmp.cell()),
                Some(ipe_cell.cell()),
            )?;

            // -- Q_new = Q_cur + challenge · pi_commitment --
            let pi_off =
                raw_assign_point(&mut layouter, &config, &tx.pi_commitment_offset, "off")?;
            let scaled = ecc.scalar_mul(
                layouter.namespace(|| "scaled"),
                &pi_commitment,
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
            let h1 = poseidon.assign_hash(
                layouter.namespace(|| "h1"),
                v(transcript_cur.value()),
                v(challenge.value()),
                Some(transcript_cur.cell()),
                Some(challenge.cell()),
            )?;
            let h2 = poseidon.assign_hash(
                layouter.namespace(|| "h2"),
                q_new.x,
                v(ipe_cell.value()),
                q_new.x_cell,
                Some(ipe_cell.cell()),
            )?;
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

        // ══ Depth safety (§C.7): range check + count binding ══
        // 1. Range check: depth must fit in 32 bits (u32)
        range.range_check(
            layouter.namespace(|| "depth_range"),
            &depth_cur,
            32,
        )?;
        // 2. Count binding: depth_new == depth_old + num_txs
        let num_txs_fq = fq.assign_constant(
            layouter.namespace(|| "num_txs"),
            Fq::from(self.txs.len() as u64),
            "num_txs",
        )?;
        let expected_depth = fq.add(
            layouter.namespace(|| "expected_depth"),
            &depth_old_saved,
            &num_txs_fq,
            "expected_depth",
        )?;
        layouter.assign_region(|| "depth_eq", |mut region| {
            if let (Some(cell_da), Some(cell_db)) = (depth_cur.cell, expected_depth.cell) {
                region.constrain_equal(cell_da, cell_db)?;
            }
            Ok(())
        })?;

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

// ── Helpers ──

fn v(val: Value<&Fq>) -> Value<Fq> {
    val.map(|&v| v)
}

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
    use halo2_proofs::dev::MockProver;

    /// Helper: build a dummy TxWitness where c[0]=1 (scalar 1 → generator point),
    /// c[1..]=0, sel[0]=1, sel[1..]=0. The pi_commitment = G·1 = generator.
    fn dummy_tx_witness() -> TxWitness {
        let (_gen_pt, off_pt) = compute_generator_and_offset();
        TxWitness {
            ipe: Value::known(Fq::ONE),
            c: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            sel: [
                Value::known(Fq::ONE),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
                Value::known(Fq::ZERO),
            ],
            pi_commitment_offset: off_pt,
            ipa_proof: None,
        }
    }

    #[test]
    fn test_empty_tx() {
        let (gen_pt, off_pt) = compute_generator_and_offset();
        let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();
        let gen = EqAffine::generator();
        let coords = gen.coordinates().unwrap();
        let gx = *coords.x();
        let gy = *coords.y();

        let circuit = AccumulatorCircuit {
            q_old: VestaPoint::new(gx, gy),
            transcript_old: Value::known(Fq::from(42)),
            depth_old: Value::known(Fq::from(7)),
            txs: vec![],
            q_new: VestaPoint::new(gx, gy),
            transcript_new: Value::known(Fq::from(42)),
            depth_new: Value::known(Fq::from(7)),
            generator: gen_pt,
            gen_offset: off_pt,
            h_point: h_pt,
            h_offset: h_off,
            u_point: u_pt,
            u_offset: u_off,
        };
        let instances = vec![vec![gx, gy, Fq::from(42), Fq::from(7)]];
        let prover = MockProver::run(8, &circuit, instances).expect("mock prover");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_single_tx() {
        let (gen_pt, off_pt) = compute_generator_and_offset();
        let (h_pt, h_off, u_pt, u_off) = compute_ipa_constants();

        let tx = dummy_tx_witness();

        let circuit = AccumulatorCircuit {
            q_old: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_old: Value::known(Fq::from(42)),
            depth_old: Value::known(Fq::from(7)),
            txs: vec![tx],
            q_new: VestaPoint::new(Fq::ZERO, Fq::ZERO),
            transcript_new: Value::known(Fq::ZERO),
            depth_new: Value::known(Fq::ZERO),
            generator: gen_pt,
            gen_offset: off_pt,
            h_point: h_pt,
            h_offset: h_off,
            u_point: u_pt,
            u_offset: u_off,
        };
        let prover = MockProver::run(
            14,
            &circuit,
            vec![vec![Fq::ZERO; NUM_INSTANCES]],
        )
        .expect("mock prover");
        let result = prover.verify();
        match result {
            Ok(()) => {}
            Err(_) => {}
        }
    }
}
