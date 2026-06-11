//! Pallas IPA accumulation chip.
//!
//! PallasAccumulateChip orchestrates host-precomputed intermediate points and
//! calls `PallasIpaChip::verify_ipa_full` to verify the full IPA equation.
//!
//! # Flow
//!
//! 1. Host: parse `IpaProofWitness`, squeeze challenges from byte stream,
//!    precompute Lᵢ' = xᵢ⁻¹·Lᵢ, Rᵢ' = xᵢ·Rᵢ, G' = a·G_final,
//!    H' = r′·H, U' = (ab-eval)·U, and all intermediate point_add witnesses.
//! 2. Circuit: on-curve check all precomputed points, verify equation via
//!    `PallasIpaChip::verify_ipa_full`.

use core::array;

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::pasta::{EpAffine, Fp, Fq},
    plonk::ErrorFront,
    transcript::{Challenge255, EncodedChallenge},
};
use halo2curves::group::prime::PrimeCurveAffine;
use halo2curves::group::Curve;
use halo2curves::CurveAffine;

use crate::non_native_fp::{FpElement, NonNativeFpChip, NonNativeFpConfig, FP_NUM_LIMBS};
use crate::pallas_ecc::{PallasEccChip, PallasPoint};
use crate::pallas_ipa::PallasIpaChip;
use crate::proof_import::IpaProofWitness;
use crate::vesta_fq::{VestaFqChip, VestaFqConfig};
use crate::Limb;

/// Accumulate config — wires together NonNativeFpChip and VestaFqChip.
#[derive(Clone, Debug)]
pub struct PallasAccumulateConfig {
    pub fp: NonNativeFpConfig,
    pub fq: VestaFqConfig,
}

impl PallasAccumulateConfig {
    pub fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fq>) -> Self {
        Self {
            fp: NonNativeFpChip::configure(meta),
            fq: VestaFqConfig::configure(meta),
        }
    }
}

/// Accumulate chip — verifies a Pallas IPA proof using host-precomputed data.
pub struct PallasAccumulateChip {
    pub fp: NonNativeFpChip,
    pub fq: VestaFqChip,
    pub ecc: PallasEccChip,
    pub ipa: PallasIpaChip,
}

impl PallasAccumulateChip {
    pub fn new(config: &PallasAccumulateConfig) -> Self {
        let fp = NonNativeFpChip::new(config.fp.clone());
        let fq = VestaFqChip::new(config.fq.clone());
        let ecc = PallasEccChip::new(fp.clone(), fq.clone());
        let ipa = PallasIpaChip::new(ecc.clone(), fq.clone());
        Self { fp, fq, ecc, ipa }
    }

    /// Verify a Pallas IPA proof from host-precomputed data.
    ///
    /// All scalar_mul results must be computed on the host before calling this
    /// method. See `precompute_ipa_witness` for the host-side helper.
    pub fn verify_ipa_pallas(
        &self,
        mut layouter: impl Layouter<Fq>,
        commitment: &PallasPoint,
        l_scaled: &[PallasPoint],
        r_scaled: &[PallasPoint],
        a_mul_gfinal: &PallasPoint,
        r_prime_mul_h: &PallasPoint,
        ab_eval_mul_u: &PallasPoint,
        lhs_witnesses: &[(FpElement, FpElement, FpElement)],
        rhs_witnesses: &[(FpElement, FpElement, FpElement)],
    ) -> Result<(), ErrorFront> {
        self.ipa.verify_ipa_full(
            layouter.namespace(|| "verify_ipa"),
            commitment,
            l_scaled,
            r_scaled,
            a_mul_gfinal,
            r_prime_mul_h,
            ab_eval_mul_u,
            lhs_witnesses,
            rhs_witnesses,
        )
    }
}

// ── Host-side precomputation helpers (no circuit) ──

/// Big-endian: `0x00...020...0` where the `1` bit is at position 85.
pub fn big_limb_base() -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_le(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
}

pub fn big_to_fq(big: &num_bigint::BigUint) -> Fq {
    let bytes = big.to_bytes_le();
    let mut repr = <Fq as PrimeField>::Repr::default();
    let len = bytes.len().min(repr.as_ref().len());
    repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
    <Fq as PrimeField>::from_repr(repr).unwrap()
}

/// Convert an EpAffine (Pallas) point to a PallasPoint (3-limb Fp-over-Fq).
pub fn ep_to_pallas_point(p: &EpAffine) -> PallasPoint {
    let coords = p.coordinates().unwrap();
    let x_fp = *coords.x();
    let y_fp = *coords.y();
    let lbb = big_limb_base();
    let x_big = num_bigint::BigUint::from_bytes_le(x_fp.to_repr().as_ref());
    let y_big = num_bigint::BigUint::from_bytes_le(y_fp.to_repr().as_ref());
    let x_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
        let lv = (&x_big / &lbb.pow(i as u32)) % &lbb;
        Limb { value: Value::known(big_to_fq(&lv)), cell: None }
    });
    let y_limbs: [Limb<Fq>; FP_NUM_LIMBS] = array::from_fn(|i| {
        let lv = (&y_big / &lbb.pow(i as u32)) % &lbb;
        Limb { value: Value::known(big_to_fq(&lv)), cell: None }
    });
    PallasPoint {
        x: FpElement { limbs: x_limbs },
        y: FpElement { limbs: y_limbs },
        x_cell: None,
        y_cell: None,
    }
}

/// Host-side Fp point addition witness: returns (λ, rx, ry) as FpElements.
pub fn fp_add_witness(p: &PallasPoint, q: &PallasPoint) -> (FpElement, FpElement, FpElement) {
    let reconstruct = |el: &FpElement| -> Fp {
        let mut big = num_bigint::BigUint::from(0u32);
        let base = big_limb_base();
        for (i, limb) in el.limbs.iter().enumerate() {
            if let Ok(val) = limb.value.assign() {
                let lv_big = num_bigint::BigUint::from_bytes_le(val.to_repr().as_ref());
                big += lv_big * base.pow(i as u32);
            }
        }
        let mut repr = <Fp as PrimeField>::Repr::default();
        let le = big.to_bytes_le();
        repr.as_mut()[..le.len()].copy_from_slice(&le);
        <Fp as PrimeField>::from_repr(repr).unwrap()
    };
    let px = reconstruct(&p.x);
    let py = reconstruct(&p.y);
    let qx = reconstruct(&q.x);
    let qy = reconstruct(&q.y);

    let lam = (qy - py) * (qx - px).invert().unwrap();
    let rx = lam.square() - px - qx;
    let ry = lam * (px - rx) - py;

    let fp_to_el = |fp: Fp| -> FpElement {
        let big = num_bigint::BigUint::from_bytes_le(fp.to_repr().as_ref());
        let base = big_limb_base();
        let limbs = array::from_fn(|i| {
            let lv = (&big / &base.pow(i as u32)) % &base;
            Limb { value: Value::known(big_to_fq(&lv)), cell: None }
        });
        FpElement { limbs }
    };

    (fp_to_el(lam), fp_to_el(rx), fp_to_el(ry))
}

/// Extract the 6 commitment limb values as `Fq` for the instance column.
pub fn commitment_limbs(p: &PallasPoint) -> Vec<Fq> {
    let mut limbs = Vec::with_capacity(2 * FP_NUM_LIMBS);
    for limb in &p.x.limbs {
        limbs.push(limb.value.assign().unwrap_or(Fq::ZERO));
    }
    for limb in &p.y.limbs {
        limbs.push(limb.value.assign().unwrap_or(Fq::ZERO));
    }
    limbs
}

/// Precomputed witness data for the recursive proof circuit.
pub struct IpaPrecomputedWitness {
    pub commitment: PallasPoint,
    pub l_scaled: Vec<PallasPoint>,
    pub r_scaled: Vec<PallasPoint>,
    pub a_mul_gfinal: PallasPoint,
    pub r_prime_mul_h: PallasPoint,
    pub ab_eval_mul_u: PallasPoint,
    pub lhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
    pub rhs_witnesses: Vec<(FpElement, FpElement, FpElement)>,
}

/// Precompute all Pallas points and witnesses from an `IpaProofWitness`.
///
/// Squeezes round challenges from each `challenge_prefix`, computes
/// Lᵢ' = xᵢ⁻¹·Lᵢ, Rᵢ' = xᵢ·Rᵢ, G_final = G · Σ(L_i' + R_i'),
/// a·G_final, r′·H, eval·U, and all point_add witnesses.
pub fn precompute_ipa_witness(witness: &IpaProofWitness) -> Result<IpaPrecomputedWitness, String> {
    let k = witness.k as usize;
    if witness.challenge_prefixes.len() != k {
        return Err(format!(
            "expected {} challenge prefixes, got {}",
            k,
            witness.challenge_prefixes.len()
        ));
    }

    // Squeeze round challenges from each prefix.
    // Each prefix contains the cumulative transcript event bytes up to and
    // including the 0x00 challenge-marker byte. We absorb the raw bytes
    // directly into a Blake2b state (matching Halo2's personalization),
    // then clone and finalize to get the challenge. This avoids Halo2's
    // point/scalar encoding which differs from the IPA event stream format.
    let mut challenges = Vec::with_capacity(k);
    for prefix in &witness.challenge_prefixes {
        // Init Blake2b state with Halo2's personalization.
        let mut state = Blake2bParams::new()
            .hash_length(64)
            .personal(b"Halo2-Transcript")
            .to_state();
        // Absorb all prefix bytes (event data + trailing 0x00 marker).
        state.update(prefix);
        // Clone and finalize → challenge.
        let hash = state.clone().finalize();
        let mut result = [0u8; 64];
        result.copy_from_slice(hash.as_bytes());
        let mut x = Challenge255::<EpAffine>::new(&result).get_scalar();

        // Rejection loop: absorb common_scalar + squeeze.
        let mut reject_count = 0u32;
        while bool::from(x.is_zero()) || x == Fq::ONE {
            reject_count += 1;
            // BLAKE2B_PREFIX_SCALAR = 2
            state.update(&[2u8]);
            state.update(Fq::from(reject_count as u64).to_repr().as_ref());
            // BLAKE2B_PREFIX_CHALLENGE = 0
            state.update(&[0u8]);
            let hash = state.clone().finalize();
            let mut result = [0u8; 64];
            result.copy_from_slice(hash.as_bytes());
            x = Challenge255::<EpAffine>::new(&result).get_scalar();
        }
        challenges.push(x);
    }

    // Host generators: G = Pallas generator, H = 2·G, U = 3·G.
    let g = EpAffine::generator();
    let h = (g.to_curve() * Fq::from(2u64)).to_affine();
    let u = (g.to_curve() * Fq::from(3u64)).to_affine();
    let g_final = g;

    // Compute scaled points and fold.
    let mut l_scaled_pts = Vec::with_capacity(k);
    let mut r_scaled_pts = Vec::with_capacity(k);

    for (i, x) in challenges.iter().enumerate() {
        let x_inv = x.invert().unwrap();
        let l_scaled = (witness.l_points[i].to_curve() * x_inv).to_affine();
        let r_scaled = (witness.r_points[i].to_curve() * x).to_affine();
        l_scaled_pts.push(l_scaled);
        r_scaled_pts.push(r_scaled);
    }

    // Compute a·G_final, r′·H, eval·U.
    let a_mul_g = (g_final.to_curve() * witness.a_final).to_affine();
    let r_prime_mul_h = (h.to_curve() * witness.r_prime).to_affine();
    let ab_eval_mul_u = (u.to_curve() * witness.eval).to_affine();

    // Verify equation: C + ΣL' + ΣR' = a·G + r′·H + eval·U
    let rhs = (a_mul_g.to_curve() + r_prime_mul_h.to_curve() + ab_eval_mul_u.to_curve()).to_affine();
    let mut lhs = witness.commitment.to_curve();
    for pt in &l_scaled_pts {
        lhs = lhs + pt.to_curve();
    }
    for pt in &r_scaled_pts {
        lhs = lhs + pt.to_curve();
    }
    if lhs.to_affine() != rhs {
        return Err("precompute_ipa_witness: equation does not balance".into());
    }

    // Convert all curve points to PallasPoints.
    let p_com = ep_to_pallas_point(&witness.commitment);
    let p_l: Vec<PallasPoint> = l_scaled_pts.iter().map(ep_to_pallas_point).collect();
    let p_r: Vec<PallasPoint> = r_scaled_pts.iter().map(ep_to_pallas_point).collect();
    let p_a = ep_to_pallas_point(&a_mul_g);
    let p_rh = ep_to_pallas_point(&r_prime_mul_h);
    let p_ab = ep_to_pallas_point(&ab_eval_mul_u);

    // Compute LHS witnesses: for each round (L+R), then (C + sumLR).
    let mut lhs_witnesses = Vec::with_capacity(2 * k);
    let mut rhs_witnesses = Vec::with_capacity(2);

    for i in 0..k {
        let sum_lr = (l_scaled_pts[i].to_curve() + r_scaled_pts[i].to_curve()).to_affine();
        let p_sum_lr = ep_to_pallas_point(&sum_lr);
        lhs_witnesses.push(fp_add_witness(&p_l[i], &p_r[i]));
        if i == k - 1 {
            lhs_witnesses.push(fp_add_witness(&p_com, &p_sum_lr));
        }
    }

    // Compute RHS witnesses: (a·G + r′·H), then (tmp + eval·U).
    let rhs_gh = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
    let p_rhs_gh = ep_to_pallas_point(&rhs_gh);
    rhs_witnesses.push(fp_add_witness(&p_a, &p_rh));
    rhs_witnesses.push(fp_add_witness(&p_rhs_gh, &p_ab));

    Ok(IpaPrecomputedWitness {
        commitment: p_com,
        l_scaled: p_l,
        r_scaled: p_r,
        a_mul_gfinal: p_a,
        r_prime_mul_h: p_rh,
        ab_eval_mul_u: p_ab,
        lhs_witnesses,
        rhs_witnesses,
    })
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    };

    // ── Test circuit ──

    #[derive(Clone)]
    struct AccumTestConfig(PallasAccumulateConfig);

    struct AccumTestCircuit {
        commitment: PallasPoint,
        l_scaled: Vec<PallasPoint>,
        r_scaled: Vec<PallasPoint>,
        a_mul_gfinal: PallasPoint,
        r_prime_mul_h: PallasPoint,
        ab_eval_mul_u: PallasPoint,
        lhs_wit: Vec<(FpElement, FpElement, FpElement)>,
        rhs_wit: Vec<(FpElement, FpElement, FpElement)>,
    }

    impl Default for AccumTestCircuit {
        fn default() -> Self {
            let zero = FpElement::zero();
            Self {
                commitment: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                l_scaled: vec![], r_scaled: vec![],
                a_mul_gfinal: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                r_prime_mul_h: PallasPoint { x: zero.clone(), y: zero.clone(), x_cell: None, y_cell: None },
                ab_eval_mul_u: PallasPoint { x: zero.clone(), y: zero, x_cell: None, y_cell: None },
                lhs_wit: vec![], rhs_wit: vec![],
            }
        }
    }

    impl Circuit<Fq> for AccumTestCircuit {
        type Config = AccumTestConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self { Self::default() }
        fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
            AccumTestConfig(PallasAccumulateConfig::configure(meta))
        }
        fn synthesize(
            &self, config: Self::Config, mut layouter: impl Layouter<Fq>,
        ) -> Result<(), ErrorFront> {
            let acc = PallasAccumulateChip::new(&config.0);
            acc.verify_ipa_pallas(
                layouter.namespace(|| "verify_ipa"),
                &self.commitment, &self.l_scaled, &self.r_scaled,
                &self.a_mul_gfinal, &self.r_prime_mul_h, &self.ab_eval_mul_u,
                &self.lhs_wit, &self.rhs_wit,
            )
        }
    }

    #[test]
    fn test_accumulate_k1_valid() {
        let g = EpAffine::generator();
        let h = (g.to_curve() * Fq::from(2u64)).to_affine();
        let u = (g.to_curve() * Fq::from(3u64)).to_affine();
        let g_final = g;

        let a_mul_g = (g_final.to_curve() * Fq::from(11u64)).to_affine();
        let r_prime_mul_h = (h.to_curve() * Fq::from(13u64)).to_affine();
        let ab_eval_mul_u = (u.to_curve() * Fq::from(17u64)).to_affine();
        let rhs = (a_mul_g.to_curve() + r_prime_mul_h.to_curve() + ab_eval_mul_u.to_curve()).to_affine();

        let l_scaled = (g_final.to_curve() * Fq::from(2u64)).to_affine();
        let r_scaled = (h.to_curve() * Fq::from(3u64)).to_affine();
        let commitment = (rhs.to_curve() - l_scaled.to_curve() - r_scaled.to_curve()).to_affine();

        let lhs_check = (commitment.to_curve() + l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        assert_eq!(lhs_check, rhs, "host data must balance");

        let p_com = ep_to_pallas_point(&commitment);
        let p_l = ep_to_pallas_point(&l_scaled);
        let p_r = ep_to_pallas_point(&r_scaled);
        let p_a = ep_to_pallas_point(&a_mul_g);
        let p_rh = ep_to_pallas_point(&r_prime_mul_h);
        let p_ab = ep_to_pallas_point(&ab_eval_mul_u);

        let sum_lr = (l_scaled.to_curve() + r_scaled.to_curve()).to_affine();
        let p_sum_lr = ep_to_pallas_point(&sum_lr);
        let wit_lr = fp_add_witness(&p_l, &p_r);
        let wit_accum = fp_add_witness(&p_com, &p_sum_lr);

        let rhs_gh = (a_mul_g.to_curve() + r_prime_mul_h.to_curve()).to_affine();
        let p_rhs_gh = ep_to_pallas_point(&rhs_gh);
        let wit_gh = fp_add_witness(&p_a, &p_rh);
        let wit_u = fp_add_witness(&p_rhs_gh, &p_ab);

        let circuit = AccumTestCircuit {
            commitment: p_com,
            l_scaled: vec![p_l],
            r_scaled: vec![p_r],
            a_mul_gfinal: p_a,
            r_prime_mul_h: p_rh,
            ab_eval_mul_u: p_ab,
            lhs_wit: vec![wit_lr, wit_accum],
            rhs_wit: vec![wit_gh, wit_u],
        };

        let prover = MockProver::run(16, &circuit, vec![]).unwrap();
        let result = prover.verify();
        assert!(result.is_ok(), "accumulate k=1: {:?}", result.err());
    }

    #[test]
    fn test_precompute_ipa_witness_k1() {
        // Squeeze actual challenges from IPA stream prefix, then build data that matches.
        let g = EpAffine::generator();
        let h = (g.to_curve() * Fq::from(2u64)).to_affine();
        let u = (g.to_curve() * Fq::from(3u64)).to_affine();
        let g_final = g;

        // Use generator as the original L/R points (pre-scaling).
        let l_orig = g;
        let r_orig = h;
        let a_final = Fq::from(11u64);
        let r_prime = Fq::from(13u64);
        let eval = Fq::from(17u64);

        // Build the IPA stream and squeeze x from the round prefix using
        // raw Blake2b state (same approach as precompute_ipa_witness).
        let (_stream, prefixes) =
            crate::proof_import::build_ipa_transcript_stream(1, &[l_orig], &[r_orig]);
        let round_prefix = &prefixes[1];
        let mut state = Blake2bParams::new()
            .hash_length(64)
            .personal(b"Halo2-Transcript")
            .to_state();
        state.update(round_prefix);
        let hash = state.clone().finalize();
        let mut result = [0u8; 64];
        result.copy_from_slice(hash.as_bytes());
        let x: Fq = Challenge255::<EpAffine>::new(&result).get_scalar();

        // Compute scaled points using the real x.
        let x_inv = x.invert().unwrap();
        let l_scaled = (l_orig.to_curve() * x_inv).to_affine();
        let r_scaled = (r_orig.to_curve() * x).to_affine();

        // Compute commitment such that C + L' + R' = a·G + r′·H + eval·U.
        let rhs = {
            let a = (g_final.to_curve() * a_final).to_affine();
            let rh = (h.to_curve() * r_prime).to_affine();
            let eu = (u.to_curve() * eval).to_affine();
            (a.to_curve() + rh.to_curve() + eu.to_curve()).to_affine()
        };
        let commitment = (rhs.to_curve() - l_scaled.to_curve() - r_scaled.to_curve()).to_affine();

        let round_prefixes = if prefixes.len() > 1 { prefixes[1..].to_vec() } else { vec![] };

        let witness = IpaProofWitness {
            k: 1,
            commitment,
            eval,
            l_points: vec![l_orig],
            r_points: vec![r_orig],
            a_final,
            r_prime,
            challenge_prefixes: round_prefixes,
        };

        let pre = precompute_ipa_witness(&witness).expect("precompute_ipa_witness failed");
        assert_eq!(pre.l_scaled.len(), 1);
        assert_eq!(pre.r_scaled.len(), 1);
        assert_eq!(pre.lhs_witnesses.len(), 2);
        assert_eq!(pre.rhs_witnesses.len(), 2);
    }
}
