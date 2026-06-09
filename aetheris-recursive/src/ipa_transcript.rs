//! Exact Halo2 IPA transcript scaffolding.
//!
//! `§1.12d1` starts by separating byte-level transcript semantics from the
//! older bounded Poseidon-based verifier prototype. This module does not yet
//! provide an in-circuit Blake2b gadget; it fixes the exact host/reference
//! transcript rules and the byte encodings that later circuit phases must
//! reproduce bit-for-bit.

use blake2b_simd::{Params as Blake2bParams, State as Blake2bState};
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::pasta::{EpAffine as PallasAffine, Fq};
use halo2_proofs::halo2curves::{Coordinates, CurveAffine};

pub const BLAKE2B_PREFIX_CHALLENGE: u8 = 0;
pub const BLAKE2B_PREFIX_POINT: u8 = 1;
pub const BLAKE2B_PREFIX_SCALAR: u8 = 2;
pub const HALO2_TRANSCRIPT_PERSONALIZATION: &[u8; 16] = b"Halo2-Transcript";

#[derive(Clone, Copy, Debug)]
pub enum PallasTranscriptEvent {
    CommonPoint(PallasAffine),
    CommonScalar(Fq),
    SqueezeChallenge,
}

pub fn point_transcript_bytes<C: CurveAffine>(point: C) -> Result<Vec<u8>, &'static str> {
    let coords: Coordinates<C> = Option::from(point.coordinates()).ok_or("point at infinity")?;
    let mut bytes = Vec::with_capacity(
        1 + coords.x().to_repr().as_ref().len() + coords.y().to_repr().as_ref().len(),
    );
    bytes.push(BLAKE2B_PREFIX_POINT);
    bytes.extend_from_slice(coords.x().to_repr().as_ref());
    bytes.extend_from_slice(coords.y().to_repr().as_ref());
    Ok(bytes)
}

pub fn scalar_transcript_bytes<F: PrimeField>(scalar: F) -> Vec<u8> {
    let repr = scalar.to_repr();
    let mut bytes = Vec::with_capacity(1 + repr.as_ref().len());
    bytes.push(BLAKE2B_PREFIX_SCALAR);
    bytes.extend_from_slice(repr.as_ref());
    bytes
}

pub fn challenge_prefix_bytes() -> [u8; 1] {
    [BLAKE2B_PREFIX_CHALLENGE]
}

pub fn pallas_event_bytes(event: PallasTranscriptEvent) -> Result<Vec<u8>, &'static str> {
    match event {
        PallasTranscriptEvent::CommonPoint(point) => point_transcript_bytes(point),
        PallasTranscriptEvent::CommonScalar(scalar) => Ok(scalar_transcript_bytes(scalar)),
        PallasTranscriptEvent::SqueezeChallenge => Ok(challenge_prefix_bytes().to_vec()),
    }
}

pub fn pallas_events_to_byte_stream(
    events: &[PallasTranscriptEvent],
) -> Result<Vec<u8>, &'static str> {
    let mut stream = Vec::new();
    for event in events {
        stream.extend_from_slice(&pallas_event_bytes(*event)?);
    }
    Ok(stream)
}

#[derive(Clone, Debug, Default)]
pub struct PallasPreIpaPrefixTrace {
    pub vk_transcript_repr: Option<Fq>,
    pub instance_scalars: Vec<Fq>,
    pub common_points: Vec<PallasAffine>,
    pub common_scalars: Vec<Fq>,
}

impl PallasPreIpaPrefixTrace {
    pub fn apply(&self, transcript: &mut Blake2bTranscriptRef) -> Result<(), &'static str> {
        if let Some(vk_repr) = self.vk_transcript_repr {
            transcript.common_scalar(vk_repr);
        }

        for scalar in &self.instance_scalars {
            transcript.common_scalar(*scalar);
        }

        for point in &self.common_points {
            transcript.common_point(*point)?;
        }

        for scalar in &self.common_scalars {
            transcript.common_scalar(*scalar);
        }

        Ok(())
    }

    pub fn to_events(&self) -> Vec<PallasTranscriptEvent> {
        let mut events = Vec::new();

        if let Some(vk_repr) = self.vk_transcript_repr {
            events.push(PallasTranscriptEvent::CommonScalar(vk_repr));
        }

        events.extend(
            self.instance_scalars
                .iter()
                .copied()
                .map(PallasTranscriptEvent::CommonScalar),
        );
        events.extend(
            self.common_points
                .iter()
                .copied()
                .map(PallasTranscriptEvent::CommonPoint),
        );
        events.extend(
            self.common_scalars
                .iter()
                .copied()
                .map(PallasTranscriptEvent::CommonScalar),
        );

        events
    }

    pub fn to_byte_stream(&self) -> Result<Vec<u8>, &'static str> {
        pallas_events_to_byte_stream(&self.to_events())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PallasIpaRoundTrace {
    pub l_point: PallasAffine,
    pub r_point: PallasAffine,
}

#[derive(Clone, Debug, Default)]
pub struct PallasIpaProofTrace {
    pub k: u32,
    pub rounds: Vec<PallasIpaRoundTrace>,
    pub a_final: Fq,
    pub r_prime: Fq,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PallasIpaDerivedChallenges {
    pub theta: Fq,
    pub round_challenges: Vec<Fq>,
    pub reject_counts: Vec<u32>,
}

pub fn pallas_k_as_scalar(k: u32) -> Fq {
    Fq::from(k as u64)
}

impl PallasIpaProofTrace {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.rounds.len() != self.k as usize {
            return Err("round count does not match k");
        }
        if self.k >= 32 {
            return Err("k must be < 32");
        }
        Ok(())
    }

    pub fn derive_challenges(
        &self,
        transcript: &mut Blake2bTranscriptRef,
    ) -> Result<PallasIpaDerivedChallenges, &'static str> {
        self.validate_shape()?;

        transcript.common_scalar(pallas_k_as_scalar(self.k));
        let theta = transcript.squeeze_challenge::<Fq>();

        let mut round_challenges = Vec::with_capacity(self.rounds.len());
        let mut reject_counts = Vec::with_capacity(self.rounds.len());

        for round in &self.rounds {
            transcript.common_point(round.l_point)?;
            transcript.common_point(round.r_point)?;
            let (challenge, reject_count) = challenge_scalar_after_rejections_halo2(transcript);
            round_challenges.push(challenge);
            reject_counts.push(reject_count);
        }

        transcript.common_scalar(self.a_final);
        transcript.common_scalar(self.r_prime);

        Ok(PallasIpaDerivedChallenges {
            theta,
            round_challenges,
            reject_counts,
        })
    }

    pub fn to_events(&self) -> Result<Vec<PallasTranscriptEvent>, &'static str> {
        self.validate_shape()?;

        let mut events = Vec::with_capacity(2 + 3 * self.rounds.len() + 2);
        events.push(PallasTranscriptEvent::CommonScalar(pallas_k_as_scalar(
            self.k,
        )));
        events.push(PallasTranscriptEvent::SqueezeChallenge);

        for round in &self.rounds {
            events.push(PallasTranscriptEvent::CommonPoint(round.l_point));
            events.push(PallasTranscriptEvent::CommonPoint(round.r_point));
            events.push(PallasTranscriptEvent::SqueezeChallenge);
        }

        events.push(PallasTranscriptEvent::CommonScalar(self.a_final));
        events.push(PallasTranscriptEvent::CommonScalar(self.r_prime));

        Ok(events)
    }

    pub fn to_byte_stream(&self) -> Result<Vec<u8>, &'static str> {
        pallas_events_to_byte_stream(&self.to_events()?)
    }
}

#[derive(Clone, Debug)]
pub struct Blake2bTranscriptRef {
    state: Blake2bState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake2bTranscriptSnapshot {
    pub challenge_bytes: [u8; 64],
}

impl Blake2bTranscriptRef {
    pub fn new() -> Self {
        Self {
            state: Blake2bParams::new()
                .hash_length(64)
                .personal(HALO2_TRANSCRIPT_PERSONALIZATION)
                .to_state(),
        }
    }

    pub fn common_point<C: CurveAffine>(&mut self, point: C) -> Result<(), &'static str> {
        self.state.update(&point_transcript_bytes(point)?);
        Ok(())
    }

    pub fn common_scalar<F: PrimeField>(&mut self, scalar: F) {
        self.state.update(&scalar_transcript_bytes(scalar));
    }

    pub fn apply_pallas_event(
        &mut self,
        event: &PallasTranscriptEvent,
    ) -> Result<Option<[u8; 64]>, &'static str> {
        match event {
            PallasTranscriptEvent::CommonPoint(point) => {
                self.common_point(*point)?;
                Ok(None)
            }
            PallasTranscriptEvent::CommonScalar(scalar) => {
                self.common_scalar(*scalar);
                Ok(None)
            }
            PallasTranscriptEvent::SqueezeChallenge => Ok(Some(self.squeeze_bytes())),
        }
    }

    pub fn apply_pallas_events(
        &mut self,
        events: &[PallasTranscriptEvent],
    ) -> Result<Vec<[u8; 64]>, &'static str> {
        let mut squeezed = Vec::new();
        for event in events {
            if let Some(bytes) = self.apply_pallas_event(event)? {
                squeezed.push(bytes);
            }
        }
        Ok(squeezed)
    }

    pub fn squeeze_bytes(&mut self) -> [u8; 64] {
        self.state.update(&challenge_prefix_bytes());
        self.state
            .clone()
            .finalize()
            .as_bytes()
            .try_into()
            .expect("64-byte Blake2b output")
    }

    pub fn snapshot_after_challenge(&self) -> Blake2bTranscriptSnapshot {
        let mut cloned = self.clone();
        Blake2bTranscriptSnapshot {
            challenge_bytes: cloned.squeeze_bytes(),
        }
    }

    pub fn squeeze_challenge<F>(&mut self) -> F
    where
        F: PrimeField + FromUniformBytes<64>,
    {
        F::from_uniform_bytes(&self.squeeze_bytes())
    }
}

impl Default for Blake2bTranscriptRef {
    fn default() -> Self {
        Self::new()
    }
}

pub fn challenge_scalar_after_rejections<F>(transcript: &mut Blake2bTranscriptRef) -> (F, u32)
where
    F: PrimeField + FromUniformBytes<64>,
{
    let mut challenge = transcript.squeeze_challenge::<F>();
    let mut reject_count = 0u32;
    while bool::from(challenge.is_zero()) || challenge == F::ONE {
        reject_count += 1;
        transcript.common_scalar(F::from(reject_count as u64));
        challenge = transcript.squeeze_challenge::<F>();
    }
    (challenge, reject_count)
}

pub fn challenge_scalar_after_rejections_halo2(transcript: &mut Blake2bTranscriptRef) -> (Fq, u32) {
    challenge_scalar_after_rejections::<Fq>(transcript)
}

pub fn pallas_reference_snapshot_from_prefix(
    prefix: &PallasPreIpaPrefixTrace,
) -> Result<Blake2bTranscriptSnapshot, &'static str> {
    let mut transcript = Blake2bTranscriptRef::new();
    prefix.apply(&mut transcript)?;
    Ok(transcript.snapshot_after_challenge())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
    use halo2_proofs::halo2curves::group::Curve;
    use halo2_proofs::transcript::{
        Blake2bWrite, Challenge255, Transcript, TranscriptWriterBuffer,
    };

    #[test]
    fn transcript_reference_is_deterministic() {
        let mut a = Blake2bTranscriptRef::new();
        let mut b = Blake2bTranscriptRef::new();

        a.common_scalar(Fq::from(7));
        b.common_scalar(Fq::from(7));

        let ca = a.squeeze_bytes();
        let cb = b.squeeze_bytes();
        assert_eq!(ca, cb);
    }

    #[test]
    fn transcript_reference_binds_points_and_scalars() {
        let mut a = Blake2bTranscriptRef::new();
        let mut b = Blake2bTranscriptRef::new();

        a.common_point(PallasAffine::generator())
            .expect("generator is affine");
        a.common_scalar(Fq::from(3));

        b.common_point((PallasAffine::generator() + PallasAffine::generator()).to_affine())
            .expect("double generator is affine");
        b.common_scalar(Fq::from(3));

        assert_ne!(a.squeeze_bytes(), b.squeeze_bytes());
    }

    #[test]
    fn transcript_reference_reject_loop_returns_nontrivial_challenge() {
        let mut transcript = Blake2bTranscriptRef::new();
        transcript.common_scalar(Fq::from(11));
        let (challenge, reject_count) = challenge_scalar_after_rejections::<Fq>(&mut transcript);
        assert!(!bool::from(challenge.is_zero()));
        assert_ne!(challenge, Fq::ONE);
        assert!(reject_count < 8, "unexpectedly many challenge rejections");
    }

    #[test]
    fn transcript_encoding_helpers_match_absorb_behavior() {
        let point = PallasAffine::generator();
        let scalar = Fq::from(9);

        let point_bytes = point_transcript_bytes(point).expect("generator is affine");
        let scalar_bytes = scalar_transcript_bytes(scalar);

        assert_eq!(point_bytes[0], BLAKE2B_PREFIX_POINT);
        assert_eq!(scalar_bytes[0], BLAKE2B_PREFIX_SCALAR);
        assert_eq!(point_bytes.len(), 1 + 32 + 32);
        assert_eq!(scalar_bytes.len(), 1 + 32);
    }

    #[test]
    fn transcript_event_trace_matches_manual_flow() {
        let point = PallasAffine::generator();
        let scalar = Fq::from(5);

        let mut manual = Blake2bTranscriptRef::new();
        manual.common_point(point).expect("generator is affine");
        manual.common_scalar(scalar);
        let manual_challenge = manual.squeeze_bytes();

        let mut traced = Blake2bTranscriptRef::new();
        let outputs = traced
            .apply_pallas_events(&[
                PallasTranscriptEvent::CommonPoint(point),
                PallasTranscriptEvent::CommonScalar(scalar),
                PallasTranscriptEvent::SqueezeChallenge,
            ])
            .expect("event trace should succeed");

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], manual_challenge);
    }

    #[test]
    fn transcript_reference_matches_halo2_blake2b_challenge() {
        let point = PallasAffine::generator();
        let scalar = Fq::from(13);

        let mut reference = Blake2bTranscriptRef::new();
        reference.common_point(point).expect("generator is affine");
        reference.common_scalar(scalar);
        let expected = reference.squeeze_challenge::<Fq>();

        let mut halo2 =
            Blake2bWrite::<Vec<u8>, PallasAffine, Challenge255<PallasAffine>>::init(Vec::new());
        halo2.common_point(point).expect("generator is affine");
        halo2
            .common_scalar(scalar)
            .expect("scalar absorb should succeed");
        let actual = *halo2.squeeze_challenge_scalar::<()>();

        assert_eq!(expected, actual);
    }

    #[test]
    fn transcript_reference_repeated_squeeze_matches_halo2_statefulness() {
        let scalar = Fq::from(21);

        let mut reference = Blake2bTranscriptRef::new();
        reference.common_scalar(scalar);
        let first_ref = reference.squeeze_challenge::<Fq>();
        let second_ref = reference.squeeze_challenge::<Fq>();

        let mut halo2 =
            Blake2bWrite::<Vec<u8>, PallasAffine, Challenge255<PallasAffine>>::init(Vec::new());
        halo2
            .common_scalar(scalar)
            .expect("scalar absorb should succeed");
        let first_halo2 = *halo2.squeeze_challenge_scalar::<()>();
        let second_halo2 = *halo2.squeeze_challenge_scalar::<()>();

        assert_eq!(first_ref, first_halo2);
        assert_eq!(second_ref, second_halo2);
        assert_ne!(first_ref, second_ref);
    }

    #[test]
    fn pre_ipa_prefix_trace_matches_manual_absorb_sequence() {
        let prefix = PallasPreIpaPrefixTrace {
            vk_transcript_repr: Some(Fq::from(17)),
            instance_scalars: vec![Fq::from(3), Fq::from(4)],
            common_points: vec![PallasAffine::generator()],
            common_scalars: vec![Fq::from(99)],
        };

        let mut manual = Blake2bTranscriptRef::new();
        manual.common_scalar(Fq::from(17));
        manual.common_scalar(Fq::from(3));
        manual.common_scalar(Fq::from(4));
        manual
            .common_point(PallasAffine::generator())
            .expect("generator is affine");
        manual.common_scalar(Fq::from(99));

        let mut traced = Blake2bTranscriptRef::new();
        prefix
            .apply(&mut traced)
            .expect("prefix apply should succeed");

        assert_eq!(manual.squeeze_bytes(), traced.squeeze_bytes());
    }

    #[test]
    fn ipa_proof_trace_derives_theta_and_rounds_in_order() {
        let trace = PallasIpaProofTrace {
            k: 2,
            rounds: vec![
                PallasIpaRoundTrace {
                    l_point: PallasAffine::generator(),
                    r_point: (PallasAffine::generator() + PallasAffine::generator()).to_affine(),
                },
                PallasIpaRoundTrace {
                    l_point: (PallasAffine::generator()
                        + PallasAffine::generator()
                        + PallasAffine::generator())
                    .to_affine(),
                    r_point: (PallasAffine::generator()
                        + PallasAffine::generator()
                        + PallasAffine::generator()
                        + PallasAffine::generator())
                    .to_affine(),
                },
            ],
            a_final: Fq::from(7),
            r_prime: Fq::from(8),
        };

        let mut transcript = Blake2bTranscriptRef::new();
        let derived = trace
            .derive_challenges(&mut transcript)
            .expect("trace should derive");

        assert_eq!(derived.round_challenges.len(), 2);
        assert_eq!(derived.reject_counts.len(), 2);
        assert!(!bool::from(derived.theta.is_zero()));
        assert!(derived
            .round_challenges
            .iter()
            .all(|x| !bool::from(x.is_zero()) && *x != Fq::ONE));
    }

    #[test]
    fn prefix_trace_byte_stream_matches_event_encoding() {
        let prefix = PallasPreIpaPrefixTrace {
            vk_transcript_repr: Some(Fq::from(17)),
            instance_scalars: vec![Fq::from(3), Fq::from(4)],
            common_points: vec![PallasAffine::generator()],
            common_scalars: vec![Fq::from(99)],
        };

        let event_bytes = pallas_events_to_byte_stream(&prefix.to_events()).expect("event stream");
        let trace_bytes = prefix.to_byte_stream().expect("trace stream");

        assert_eq!(event_bytes, trace_bytes);
        assert_eq!(event_bytes[0], BLAKE2B_PREFIX_SCALAR);
    }

    #[test]
    fn prefix_snapshot_matches_manual_transcript_state() {
        let prefix = PallasPreIpaPrefixTrace {
            vk_transcript_repr: Some(Fq::from(17)),
            instance_scalars: vec![Fq::from(3), Fq::from(4)],
            common_points: vec![PallasAffine::generator()],
            common_scalars: vec![Fq::from(99)],
        };

        let snapshot =
            pallas_reference_snapshot_from_prefix(&prefix).expect("snapshot should build");

        let mut manual = Blake2bTranscriptRef::new();
        prefix
            .apply(&mut manual)
            .expect("prefix apply should succeed");
        let manual_snapshot = manual.snapshot_after_challenge();

        assert_eq!(snapshot, manual_snapshot);
    }

    #[test]
    fn ipa_trace_byte_stream_includes_challenge_prefixes() {
        let trace = PallasIpaProofTrace {
            k: 1,
            rounds: vec![PallasIpaRoundTrace {
                l_point: PallasAffine::generator(),
                r_point: (PallasAffine::generator() + PallasAffine::generator()).to_affine(),
            }],
            a_final: Fq::from(7),
            r_prime: Fq::from(8),
        };

        let bytes = trace.to_byte_stream().expect("trace stream should build");
        let expected = [
            scalar_transcript_bytes(pallas_k_as_scalar(1)),
            challenge_prefix_bytes().to_vec(),
            point_transcript_bytes(PallasAffine::generator()).expect("generator is affine"),
            point_transcript_bytes(
                (PallasAffine::generator() + PallasAffine::generator()).to_affine(),
            )
            .expect("double generator is affine"),
            challenge_prefix_bytes().to_vec(),
            scalar_transcript_bytes(Fq::from(7)),
            scalar_transcript_bytes(Fq::from(8)),
        ]
        .concat();

        assert_eq!(bytes, expected);
    }
}
