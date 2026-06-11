use ff::{Field, PrimeField};
use halo2_proofs::halo2curves::pasta::{EpAffine, Fq};
use halo2_proofs::transcript::{Blake2bRead, Challenge255, Transcript, TranscriptRead, TranscriptReadBuffer};

/// Size of a scalar transcript encoding: 1 tag byte + 32 LE repr bytes.
const SCALAR_ENCODED_SIZE: usize = 33;
/// Size of a point transcript encoding: 1 tag byte + 64 coordinate bytes.
const POINT_ENCODED_SIZE: usize = 65;
/// Size of a challenge prefix: 1 byte (0x00 domain separator).
const CHALLENGE_PREFIX_SIZE: usize = 1;

/// Parsed IPA proof components ready for circuit input.
pub struct IpaProofWitness {
    pub k: u32,
    pub commitment: EpAffine,
    pub eval: Fq,
    pub l_points: Vec<EpAffine>,
    pub r_points: Vec<EpAffine>,
    pub a_final: Fq,
    pub r_prime: Fq,
    /// Transcript byte stream prefixes for the `k` round challenges (x_0..x_{k-1}).
    /// Each entry is the cumulative Blake2b absorb prefix up to and including
    /// the 0x00 challenge-marker byte.
    pub challenge_prefixes: Vec<Vec<u8>>,
}

/// Compute the index (in `stream`) of the 0x00 challenge-marker byte for the
/// i-th squeeze (0 = theta, 1..k = round challenges).
///
/// The IPA event stream is:
///   `CommonScalar(k) ++ SqueezeChallenge ++ (CommonPoint(L) ++ CommonPoint(R) ++ SqueezeChallenge)*`
/// Byte sizes: SCALAR_ENCODED_SIZE, CHALLENGE_PREFIX_SIZE, POINT_ENCODED_SIZE, POINT_ENCODED_SIZE, CHALLENGE_PREFIX_SIZE, ...
fn squeeze_position(idx: usize) -> usize {
    if idx == 0 {
        // k_scalar (33) + first challenge prefix byte (1) - 1
        SCALAR_ENCODED_SIZE + CHALLENGE_PREFIX_SIZE - 1
    } else {
        // prev_end + L(65) + R(65) + ch(1) - 1
        squeeze_position(idx - 1) + 1 + POINT_ENCODED_SIZE + POINT_ENCODED_SIZE + CHALLENGE_PREFIX_SIZE - 1
    }
}

/// Build the IPA transcript byte stream matching `PallasIpaProofTrace::to_events()`.
///
/// Events (from the Halo2 reference `ipa_transcript.rs:196-214`):
///   `CommonScalar(k), SqueezeChallenge, (CommonPoint(L), CommonPoint(R), SqueezeChallenge)*`
///
/// Byte stream:
///   `k_scalar(33) || 0x00(1) || (L_point(65) || R_point(65) || 0x00(1))*`
///
/// Returns `(full_byte_stream, all_prefixes)` where:
/// - `all_prefixes[0]` is the prefix for theta squeeze
/// - `all_prefixes[1..]` are prefixes for round challenges x_0..x_{k-1}
///
/// Unlike the old approach that searched for 0x00 bytes (which falsely matched
/// zero bytes inside scalar/point encodings), this computes prefix positions
/// directly from the fixed-length event encoding sizes.
pub fn build_ipa_transcript_stream(
    k: u32,
    l_points: &[EpAffine],
    r_points: &[EpAffine],
) -> (Vec<u8>, Vec<Vec<u8>>) {
    use crate::ipa_transcript::{
        challenge_prefix_bytes, point_transcript_bytes, scalar_transcript_bytes,
    };

    let mut stream = Vec::new();
    stream.extend_from_slice(&scalar_transcript_bytes(Fq::from(k as u64)));
    stream.extend_from_slice(&challenge_prefix_bytes());
    for i in 0..k as usize {
        stream.extend_from_slice(&point_transcript_bytes(l_points[i]).expect("L point bytes"));
        stream.extend_from_slice(&point_transcript_bytes(r_points[i]).expect("R point bytes"));
        stream.extend_from_slice(&challenge_prefix_bytes());
    }

    let total_chals = k as usize + 1;
    let prefixes: Vec<Vec<u8>> = (0..total_chals)
        .map(|i| {
            let pos = squeeze_position(i);
            stream[..=pos].to_vec()
        })
        .collect();

    (stream, prefixes)
}

/// Parse a full `prove_conservation` proof byte array using a
/// `Blake2bRead` transcript (same as the Halo2 verifier).
///
/// Wire format:
///   [0..19]  b"halo2_ipa_pasta_v1_"
///   [19..21] in_len as u16 LE
///   [21..23] out_len as u16 LE
///   [23..]   internal Halo2 IPA proof bytes
///
/// `commitment` and `eval` are the public inputs absorbed into the Halo2 transcript
/// *before* the IPA proof (the pre-IPA prefix). They are NOT stored in the proof bytes
/// and must be supplied from the outer context.
///
/// Returns `IpaProofWitness` where `challenge_prefixes` contains the `k` round-challenge
/// prefixes (indices `all_prefixes[1..]`). Theta (index 0) is not included.
pub fn parse_proof_bytes(
    proof: &[u8],
    commitment: &EpAffine,
    eval: Fq,
    k_expected: u32,
) -> Result<IpaProofWitness, String> {
    const PREFIX: &[u8] = b"halo2_ipa_pasta_v1_";
    if !proof.starts_with(PREFIX) {
        return Err("proof bytes must start with halo2_ipa_pasta_v1_ prefix".into());
    }
    if proof.len() < 23 {
        return Err("proof too short (need at least 23 bytes for prefix + shape)".into());
    }

    let internal = &proof[23..];
    let mut transcript =
        Blake2bRead::<&[u8], EpAffine, Challenge255<EpAffine>>::init(internal);

    let k_raw: Fq = transcript
        .read_scalar()
        .map_err(|e| format!("read k: {:?}", e))?;
    let repr = k_raw.to_repr();
    let k = u32::from_le_bytes([
        repr.as_ref()[0],
        repr.as_ref()[1],
        repr.as_ref()[2],
        repr.as_ref()[3],
    ]);
    if k != k_expected {
        return Err(format!("proof k={} != expected k={}", k, k_expected));
    }

    let _theta: Fq = *transcript.squeeze_challenge_scalar::<()>();

    let k_usize = k as usize;
    let mut l_points = Vec::with_capacity(k_usize);
    let mut r_points = Vec::with_capacity(k_usize);

    for _ in 0..k {
        let l: EpAffine = transcript
            .read_point()
            .map_err(|e| format!("read L: {:?}", e))?;
        let r: EpAffine = transcript
            .read_point()
            .map_err(|e| format!("read R: {:?}", e))?;
        let x_val: Fq = *transcript.squeeze_challenge_scalar::<()>();
        let mut x = x_val;
        let mut reject_count = 0u32;
        while bool::from(x.is_zero()) || x == Fq::ONE {
            reject_count += 1;
            transcript
                .common_scalar(Fq::from(reject_count as u64))
                .map_err(|e| format!("reject scalar: {:?}", e))?;
            x = *transcript.squeeze_challenge_scalar::<()>();
        }
        l_points.push(l);
        r_points.push(r);
    }

    let a_final: Fq = transcript
        .read_scalar()
        .map_err(|e| format!("read a_final: {:?}", e))?;
    let r_prime: Fq = transcript
        .read_scalar()
        .map_err(|e| format!("read r_prime: {:?}", e))?;

    let (_, all_prefixes) = build_ipa_transcript_stream(k, &l_points, &r_points);
    let round_prefixes: Vec<Vec<u8>> = if all_prefixes.len() > 1 {
        all_prefixes[1..].to_vec()
    } else {
        Vec::new()
    };

    Ok(IpaProofWitness {
        k,
        commitment: *commitment,
        eval,
        l_points,
        r_points,
        a_final,
        r_prime,
        challenge_prefixes: round_prefixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ipa_transcript_stream_produces_prefixes() {
        let k = 2;
        let gen = <EpAffine as group::prime::PrimeCurveAffine>::generator();
        let l_points = vec![gen, gen];
        let r_points = vec![gen, gen];

        let (_stream, prefixes) = build_ipa_transcript_stream(k, &l_points, &r_points);

        assert_eq!(prefixes.len(), k as usize + 1, "should have k+1 prefixes (theta + k rounds)");
        for (i, p) in prefixes.iter().enumerate() {
            assert!(!p.is_empty(), "prefix {} should not be empty", i);
            assert_eq!(p[p.len() - 1], 0x00, "prefix {} should end with 0x00", i);
        }
        assert_eq!(
            prefixes[0].len(),
            SCALAR_ENCODED_SIZE + CHALLENGE_PREFIX_SIZE,
            "theta prefix = k_scalar(33) + 0x00(1)"
        );
        assert_eq!(
            prefixes[1].len(),
            SCALAR_ENCODED_SIZE + CHALLENGE_PREFIX_SIZE + 2 * POINT_ENCODED_SIZE + CHALLENGE_PREFIX_SIZE,
            "x_0 prefix adds L(65) + R(65) + 0x00(1)"
        );
    }

    #[test]
    fn test_squeeze_position_computation() {
        // k=0: only theta squeeze
        assert_eq!(squeeze_position(0), 33);
        // k=1: theta + x_0
        assert_eq!(squeeze_position(1), 164);
        // k=2: theta + x_0 + x_1
        assert_eq!(squeeze_position(2), 295);
    }
}
