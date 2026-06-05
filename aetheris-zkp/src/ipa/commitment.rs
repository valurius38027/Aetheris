use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;

use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::halo2curves::group::Group;
use halo2_proofs::arithmetic::CurveExt;
use halo2_backend::poly::{Coeff, Guard, LagrangeCoeff, EvaluationDomain, Polynomial};
use halo2_backend::poly::commitment::{Blind, CommitmentScheme, MSM as MSMTrait, Params, ParamsProver, ParamsVerifier};
use halo2_middleware::ff::WithSmallOrderMulGroup;
use halo2_middleware::zal::traits::MsmAccel;
use rand_core::RngCore;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

/// IPA commitment scheme parameters.
///
/// Stores the SRS generators for the IPA commitment scheme.
/// Unlike KZG, IPA does not require `Engine` (no pairing).
/// Works with any curve implementing `CurveAffine`.
#[derive(Clone, Debug)]
pub struct ParamsIPA<C: CurveAffine> {
    k: u32,
    n: u64,
    /// SRS generators: one per polynomial coefficient
    g: Vec<C>,
    /// Blinding generator
    h: C,
    /// IPA challenge generator
    u: C,
}

pub(crate) fn derive_point<C: CurveAffine>(domain_prefix: &str, tag: &[u8]) -> C
where
    C::CurveExt: CurveExt,
{
    let hasher = <C::CurveExt as CurveExt>::hash_to_curve(domain_prefix);
    let proj = hasher(tag);
    C::from(proj)
}

impl<C: CurveAffine> ParamsIPA<C>
where
    C::CurveExt: CurveExt,
{
    /// Create new IPA parameters for a given domain size `k` (size = 2^k).
    pub fn setup<R: RngCore>(k: u32, _rng: &mut R) -> Self {
        // NOTE: The `where C::CurveExt: CurveExt` bound above is redundant
        // (guaranteed by `CurveAffine::CurveExt: CurveExt`) but required for
        // `hash_to_curve` calls within inherent methods.
        let n = 1 << k;
        let mut g = Vec::with_capacity(n);
        for i in 0..n {
            let mut tag = b"g-".to_vec();
            tag.extend_from_slice(&i.to_le_bytes());
            g.push(derive_point::<C>("aetheris-ipa-g", &tag));
        }
        let h = derive_point::<C>("aetheris-ipa-h", b"h");
        let u = derive_point::<C>("aetheris-ipa-u", b"u");
        ParamsIPA {
            k,
            n: n as u64,
            g,
            h,
            u,
        }
    }

    /// Create IPA parameters with a deterministic seed (for testing).
    pub fn setup_deterministic(k: u32) -> Self {
        Self::setup(k, &mut ChaCha20Rng::from_seed(*b"Aetheris IPA deterministic v0.00"))
    }

    /// Get the verifier parameters (clone of self, IPA doesn't separate prover/verifier params).
    pub fn verifier_params(&self) -> Self {
        self.clone()
    }

    /// Return the blinding generator.
    pub fn h(&self) -> &C {
        &self.h
    }

    /// Return the IPA challenge generator.
    pub fn u(&self) -> &C {
        &self.u
    }

    /// Return the SRS generators.
    pub fn g(&self) -> &[C] {
        &self.g
    }

    /// Domain size as power of two.
    pub fn k(&self) -> u32 {
        self.k
    }
}

impl<C: CurveAffine> Params<C> for ParamsIPA<C>
where
    C::CurveExt: CurveExt,
    C::ScalarExt: WithSmallOrderMulGroup<3>,
{
    fn k(&self) -> u32 {
        self.k
    }

    fn n(&self) -> u64 {
        self.n
    }

    fn downsize(&mut self, k: u32) {
        assert!(k <= self.k, "cannot downsize to larger k");
        self.k = k;
        self.n = (1 << k) as u64;
        self.g.truncate(self.n as usize);
    }

    fn commit_lagrange(
        &self,
        engine: &impl MsmAccel<C>,
        poly: &Polynomial<C::ScalarExt, LagrangeCoeff>,
        blinding: Blind<C::ScalarExt>,
    ) -> C::CurveExt {
        // Convert Lagrange (evaluation) form to coefficient form, then commit
        // using coefficient-basis generators. IPA generators are not structured
        // (no s-powers), so the polynomial must be in coefficient form for the
        // inner-product argument to produce a correct opening proof.
        let domain = EvaluationDomain::new(1, self.k());
        let coeff = domain.lagrange_to_coeff(poly.clone());
        let scalars = coeff.values;
        let size = scalars.len();
        assert!(self.g.len() >= size, "commit_lagrange: bases len {} < poly len {}", self.g.len(), size);
        let msm = engine.msm(&scalars, &self.g[..size]);
        // Add blinding factor: commitment = MSM(poly, g) + blind·H
        msm + (C::CurveExt::from(self.h) * blinding.0)
    }

    fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.k.to_le_bytes())?;
        for point in &self.g {
            writer.write_all(point.to_bytes().as_ref())?;
        }
        writer.write_all(self.h.to_bytes().as_ref())?;
        writer.write_all(self.u.to_bytes().as_ref())?;
        Ok(())
    }

    fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut k_buf = [0u8; 4];
        reader.read_exact(&mut k_buf)?;
        let k = u32::from_le_bytes(k_buf);
        let n = 1 << k;
        let mut g = Vec::with_capacity(n);
        for _ in 0..n {
            let mut compressed = C::Repr::default();
            reader.read_exact(compressed.as_mut())?;
            let point = Option::from(C::from_bytes(&compressed))
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid generator point in ParamsIPA"))?;
            g.push(point);
        }
        let h = {
            let mut compressed = C::Repr::default();
            reader.read_exact(compressed.as_mut())?;
            Option::from(C::from_bytes(&compressed))
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid h point in ParamsIPA"))?
        };
        let u = {
            let mut compressed = C::Repr::default();
            reader.read_exact(compressed.as_mut())?;
            Option::from(C::from_bytes(&compressed))
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid u point in ParamsIPA"))?
        };
        Ok(ParamsIPA {
            k,
            n: n as u64,
            g,
            h,
            u,
        })
    }
}

impl<C: CurveAffine> ParamsProver<C> for ParamsIPA<C>
where
    C::CurveExt: CurveExt,
{
    fn new(k: u32) -> Self {
        Self::setup_deterministic(k)
    }

    fn commit(
        &self,
        engine: &impl MsmAccel<C>,
        poly: &Polynomial<C::ScalarExt, Coeff>,
        blinding: Blind<C::ScalarExt>,
    ) -> C::CurveExt {
        let mut scalars = Vec::with_capacity(poly.len());
        scalars.extend(poly.iter());
        let bases = &self.g;
        let size = scalars.len();
        debug_assert!(
            size <= self.n as usize,
            "commit: polynomial length {} exceeds domain size {}",
            size,
            self.n
        );
        assert!(bases.len() >= size, "commit: bases len {} < poly len {}", bases.len(), size);
        let msm = engine.msm(&scalars, &bases[..size]);
        // Add blinding factor: commitment = MSM(poly, g) + blind·H
        msm + (C::CurveExt::from(self.h) * blinding.0)
    }

    fn get_g(&self) -> &[C] {
        &self.g
    }
}

impl<'params, C: CurveAffine> ParamsVerifier<'params, C> for ParamsIPA<C>
where
    C::CurveExt: CurveExt,
{
    type MSM = MSMIPA<C>;
    /// IPA uses the same params for prover and verifier (no separation),
    /// so verifier needs to compute commitments from instance column evaluations.
    /// Unlike KZG which sets false for ParamsVerifierKZG, IPA keeps true.
    /// IPA must commit instances (COMMIT_INSTANCE = true) because unlike KZG,
    /// IPA does not have a separation between prover and verifier params. The
    /// verifier needs the instance commitments to reconstruct the multi-open
    /// protocol's common input for challenge derivation. With COMMIT_INSTANCE,
    /// the multi-open protocol writes instance polynomial commitments to the
    /// transcript as common inputs before the prover/verifier run, ensuring
    /// Fiat-Shamir soundness (challenges bind to all instance data).
    const COMMIT_INSTANCE: bool = true;

    fn empty_msm(&'params self) -> MSMIPA<C> {
        MSMIPA::new()
    }
}

/// Multi-scalar multiplication accumulator for IPA.
///
/// Stores scalars and bases for batched MSM.
/// Unlike KZG's DualMSM, IPA does not need a pairing check.
#[derive(Clone, Debug, Default)]
pub struct MSMIPA<C: CurveAffine> {
    pub(crate) scalars: Vec<C::ScalarExt>,
    pub(crate) bases: Vec<C>,
}

impl<C: CurveAffine> MSMIPA<C> {
    pub fn new() -> Self {
        MSMIPA {
            scalars: Vec::new(),
            bases: Vec::new(),
        }
    }
}

impl<C: CurveAffine> MSMTrait<C> for MSMIPA<C> {
    fn append_term(&mut self, scalar: C::ScalarExt, point: C::CurveExt) {
        self.scalars.push(scalar);
        self.bases.push(C::from(point));
    }

    fn add_msm(&mut self, other: &Self) {
        self.scalars.extend(other.scalars.iter());
        self.bases.extend(other.bases.iter());
    }

    fn scale(&mut self, factor: C::ScalarExt) {
        for scalar in self.scalars.iter_mut() {
            *scalar *= factor;
        }
    }

    fn check(&self, engine: &impl MsmAccel<C>) -> bool {
        let result = self.eval(engine);
        bool::from(result.is_identity())
    }

    fn eval(&self, engine: &impl MsmAccel<C>) -> C::CurveExt {
        if self.scalars.is_empty() {
            return C::CurveExt::identity();
        }
        engine.msm(&self.scalars, &self.bases)
    }

    fn bases(&self) -> Vec<C::CurveExt> {
        self.bases.iter().map(|b| C::CurveExt::from(*b)).collect()
    }

    fn scalars(&self) -> Vec<C::ScalarExt> {
        self.scalars.clone()
    }
}

#[derive(Debug)]
pub struct GuardIPA<C: CurveAffine> {
    #[allow(dead_code)]
    pub(crate) msm_accumulator: MSMIPA<C>,
}

impl<C: CurveAffine> GuardIPA<C> {
    pub fn new(msm: MSMIPA<C>) -> Self {
        GuardIPA {
            msm_accumulator: msm,
        }
    }
}

impl<C: CurveAffine> Guard<CommitmentSchemeIPA<C>> for GuardIPA<C>
where
    C::CurveExt: CurveExt,
{
    type MSMAccumulator = MSMIPA<C>;
}

/// IPA CommitmentScheme implementation.
///
/// Uses `ParamsIPA` for both prover and verifier parameters.

/// Challenge brand for the point-combining step (theta).
pub(crate) struct ThetaChallenge;
/// Challenge brand for per-round IPA folding (x_i).
pub(crate) struct RoundChallenge;

// ----- Tests for Phase 1.1.0 -----

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::group::GroupEncoding;

    #[test]
    fn test_params_ipa_setup() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        assert_eq!(params.k(), 4);
        assert_eq!(params.n(), 16);
        assert_eq!(params.g().len(), 16);
    }

    #[test]
    fn test_params_ipa_serialization_roundtrip() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(5);
        let mut buf = Vec::new();
        params.write(&mut buf).expect("write failed");
        let params2 = ParamsIPA::<EpAffine>::read(&mut buf.as_slice()).expect("read failed");
        assert_eq!(params.k(), params2.k());
        assert_eq!(params.n(), params2.n());
        assert_eq!(params.g().len(), params2.g().len());
        for (a, b) in params.g().iter().zip(params2.g().iter()) {
            assert_eq!(a.to_bytes().as_ref(), b.to_bytes().as_ref());
        }
    }

    #[test]
    fn test_params_ipa_downsize() {
        let mut params = ParamsIPA::<EpAffine>::setup_deterministic(6);
        assert_eq!(params.n(), 64);
        params.downsize(4);
        assert_eq!(params.k(), 4);
        assert_eq!(params.n(), 16);
        assert_eq!(params.g().len(), 16);
    }

    #[test]
    fn test_msm_ipa_basic_eval() {
        let mut msm = MSMIPA::<EpAffine>::new();
        let one = Fq::ONE;
        let two = Fq::from(2u64);
        let params = ParamsIPA::<EpAffine>::setup_deterministic(3);
        let g0 = params.g()[0];
        let g1 = params.g()[1];

        msm.append_term(one, g0.into());
        msm.append_term(two, g1.into());

        let engine = halo2_middleware::zal::impls::H2cEngine;
        let result = msm.eval(&engine);
        // Check result is not identity (positive check)
        assert!(!bool::from(result.is_identity()));
    }

    #[test]
    fn test_msm_ipa_empty_is_identity() {
        let msm = MSMIPA::<EpAffine>::new();
        let engine = halo2_middleware::zal::impls::H2cEngine;
        assert!(bool::from(msm.eval(&engine).is_identity()));
    }

    #[test]
    fn test_msm_ipa_check_identity() {
        let msm = MSMIPA::<EpAffine>::new();
        let engine = halo2_middleware::zal::impls::H2cEngine;
        assert!(msm.check(&engine));
    }

    #[test]
    fn test_msm_ipa_accumulate() {
        let mut msm1 = MSMIPA::<EpAffine>::new();
        let mut msm2 = MSMIPA::<EpAffine>::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(3);
        let g0 = params.g()[0];
        let g1 = params.g()[1];

        msm1.append_term(Fq::from(3u64), g0.into());
        msm2.append_term(Fq::from(5u64), g1.into());
        msm1.add_msm(&msm2);

        let engine = halo2_middleware::zal::impls::H2cEngine;
        let result = msm1.eval(&engine);
        assert!(!bool::from(result.is_identity()));
    }

    #[test]
    fn test_msm_ipa_scale_zero() {
        let mut msm = MSMIPA::<EpAffine>::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(3);
        msm.append_term(Fq::from(7u64), params.g()[0].into());
        msm.scale(Fq::ZERO);
        let engine = halo2_middleware::zal::impls::H2cEngine;
        assert!(bool::from(msm.eval(&engine).is_identity()));
    }

    #[test]
    fn test_msm_ipa_add_msm_empty() {
        let mut msm = MSMIPA::<EpAffine>::new();
        let empty = MSMIPA::<EpAffine>::new();
        let params = ParamsIPA::<EpAffine>::setup_deterministic(3);
        msm.append_term(Fq::from(11u64), params.g()[0].into());

        let before = {
            let engine = halo2_middleware::zal::impls::H2cEngine;
            msm.eval(&engine).to_bytes()
        };
        msm.add_msm(&empty);
        let after = {
            let engine = halo2_middleware::zal::impls::H2cEngine;
            msm.eval(&engine).to_bytes()
        };
        assert_eq!(before.as_ref(), after.as_ref());
    }

    #[test]
    fn test_msm_ipa_accumulate_chain() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(3);
        let mut accumulated = MSMIPA::<EpAffine>::new();
        for i in 0..4 {
            let mut partial = MSMIPA::new();
            partial.append_term(Fq::from(i as u64 + 1), params.g()[i].into());
            accumulated.add_msm(&partial);
        }
        let engine = halo2_middleware::zal::impls::H2cEngine;
        let result: <EpAffine as CurveAffine>::CurveExt = accumulated.eval(&engine);
        assert!(!bool::from(result.is_identity()));
    }

    #[test]
    fn test_params_ipa_commit_blinding_active() {
        // Verify commit() actually uses the blind: commitment = MSM(poly, g) + blind·H.
        // Different blinds must produce different commitments.
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let engine = halo2_middleware::zal::impls::H2cEngine;
        let n = params.n() as usize;
        let mut values = vec![Fq::ZERO; n];
        values[0] = Fq::from(5u64);
        values[1] = Fq::from(7u64);
        values[2] = Fq::from(9u64);
        let poly = Polynomial::<Fq, LagrangeCoeff>::new_lagrange_from_vec(values);
        let c1 = params.commit_lagrange(&engine, &poly, Blind(Fq::ONE));
        let c2 = params.commit_lagrange(&engine, &poly, Blind(Fq::from(999u64)));
        // Different blinds must produce different commitments
        assert_ne!(c1.to_bytes().as_ref(), c2.to_bytes().as_ref());
    }

    #[test]
    fn test_params_ipa_commit_zero_poly_with_blind_not_identity() {
        // Regression test for Stage 32: commit of zero polynomial must NOT be identity,
        // otherwise transcript.write_point fails. The blind·H term ensures non-identity.
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let engine = halo2_middleware::zal::impls::H2cEngine;
        let n = params.n() as usize;
        let zero_poly = Polynomial::<Fq, LagrangeCoeff>::new_lagrange_from_vec(vec![Fq::ZERO; n]);
        let c = params.commit_lagrange(&engine, &zero_poly, Blind(Fq::from(42u64)));
        assert!(!bool::from(c.is_identity()));
    }

    #[test]
    fn test_params_ipa_commit_lagrange_consistent() {
        let params = ParamsIPA::<EpAffine>::setup_deterministic(4);
        let engine = halo2_middleware::zal::impls::H2cEngine;
        let n = params.n() as usize;

        // Create two identical polynomials
        let mut values = vec![Fq::ZERO; n];
        values[0] = Fq::from(1u64);
        values[1] = Fq::from(2u64);
        let poly = Polynomial::<Fq, LagrangeCoeff>::new_lagrange_from_vec(values);
        let poly2 = poly.clone();

        let c1 = params.commit_lagrange(&engine, &poly, Blind(Fq::ONE));
        let c2 = params.commit_lagrange(&engine, &poly2, Blind(Fq::ONE));

        assert_eq!(c1.to_bytes().as_ref(), c2.to_bytes().as_ref());
    }
}

#[derive(Debug)]
pub struct CommitmentSchemeIPA<C: CurveAffine> {
    _marker: PhantomData<C>,
}

impl<C: CurveAffine> CommitmentScheme for CommitmentSchemeIPA<C>
where
    C::CurveExt: CurveExt,
{
    type Scalar = C::ScalarExt;
    type Curve = C;
    type ParamsProver = ParamsIPA<C>;
    type ParamsVerifier = ParamsIPA<C>;

    fn new_params(k: u32) -> Self::ParamsProver {
        ParamsIPA::setup_deterministic(k)
    }

    fn read_params<R: io::Read>(reader: &mut R) -> io::Result<Self::ParamsProver> {
        ParamsIPA::read(reader)
    }
}
