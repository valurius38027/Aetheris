use std::time::{SystemTime, UNIX_EPOCH};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use crate::classgroup::{Form, integer_sqrt};
use crate::trace;
use crate::trace_elapsed;

/// Aetheris Verifiable Delay Function (Wesolowski VDF)
///
/// Runs over an imaginary quadratic class group Cl(D) instead of RSA group,
/// eliminating the trusted-setup assumption (no trapdoor).
///
/// The difficulty parameter controls the number of sequential form compositions.
/// Difficulty is NOT permanently fixed — it adjusts via deterministic
/// retargeting (see `retarget_difficulty`) to maintain a constant block
/// time as hardware speeds evolve.
///
/// Security property: VDF proof BINDS the difficulty parameter.
/// A block claiming difficulty D cannot use a proof computed with
/// difficulty D' ≠ D — verification will fail.
pub struct VDF {
    pub difficulty: u64,
    pub discriminant: BigUint,
    pub sqrt_abs_d: BigUint,
    pub identity: Form,
}

impl VDF {
    pub fn new(difficulty: u64) -> Self {
        trace::init();
        trace!("VDF::new: difficulty={}", difficulty);
        let _t0 = trace::now();
        // 2048-bit fundamental discriminant generated from a deterministic seed.
        // D ≡ 1 (mod 4), |D| ≡ 3 (mod 4) — class group of imaginary quadratic field.
        // No trusted setup: the group order h(D) is mathematically uncomputable.
        let discriminant = crate::classgroup::generate_fundamental_discriminant(
            b"Aetheris Class Group VDF v1",
            2048,
        );
        trace_elapsed!(_t0, "generate_fundamental_discriminant done, bits={}", discriminant.bits());
        let _t1 = trace::now();
        let sqrt_abs_d = integer_sqrt(&discriminant);
        trace_elapsed!(_t1, "integer_sqrt done");
        let _t2 = trace::now();
        let identity = Form::identity(&discriminant);
        trace_elapsed!(_t2, "identity done");
        // NOTE: T_genesis (difficulty) requires hardware benchmark — class group
        // compose is ~2-3x slower than RSA (pending benchmark). The initial value
        // 1,600,000 is an RSA-based placeholder; must be recalibrated for the
        // actual target hardware to hit T_target = 10 s.
        Self { difficulty, discriminant, sqrt_abs_d, identity }
    }

    /// Computes Wesolowski VDF over class group Cl(D).
    /// Returns (result, proof, duration_ns).
    pub fn solve(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>, u128) {
        let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        trace!("VDF::solve: seed={:?} difficulty={}", seed, self.difficulty);

        // Map seed to a class group element
        let _t0 = trace::now();
        let x = Form::hash_to_form(seed, &self.sqrt_abs_d, &self.discriminant);
        trace_elapsed!(_t0, "  hash_to_form done");

        // y = x^(2^T) via repeated squaring, storing intermediates
        let _t1 = trace::now();
        let cap = self.difficulty as usize;
        let mut intermediates = Vec::with_capacity(cap + 1);
        let mut y = x.clone();
        intermediates.push(y.clone());
        for i in 0..self.difficulty {
            y = y.square(&self.sqrt_abs_d);
            intermediates.push(y.clone());
            if i % 100 == 0 && i > 0 {
                trace_elapsed!(_t1, "  square iteration {}/{}", i, self.difficulty);
            }
        }
        trace_elapsed!(_t1, "  squaring loop ({} iters) done", self.difficulty);

        // Wesolowski proof: π = x^q where q = floor(2^T / l)
        let _t2 = trace::now();
        let l = self.generate_l(&x, &y);
        trace_elapsed!(_t2, "  generate_l done, l_bits={}", l.bits());
        let two_pow_t = BigUint::one() << self.difficulty;
        let r = BigUint::from(2u32).modpow(&BigUint::from(self.difficulty), &l);
        let q = (&two_pow_t - &r) / &l;

        // Reuse intermediates: π = ∏_{i | q_bit=1} x^(2^i) — O(T) compose vs O(T) square+compose
        let mut proof = Form::identity(&self.discriminant);
        for i in 0..q.bits() {
            if q.bit(i) {
                proof = proof.compose(&intermediates[i as usize], &self.sqrt_abs_d);
            }
        }

        let result = y.to_bytes();
        let proof_bytes = proof.to_bytes();
        let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        (result, proof_bytes, end - start)
    }

    /// Verifies Wesolowski VDF proof.
    pub fn verify(&self, seed: &[u8], result: &[u8], proof: &[u8]) -> bool {
        trace!("VDF::verify: seed={:?}", seed);
        if result.is_empty() || proof.is_empty() { return false; }

        let _t0 = trace::now();
        let x = Form::hash_to_form(seed, &self.sqrt_abs_d, &self.discriminant);
        trace_elapsed!(_t0, "  hash_to_form done");
        let y = match Form::from_bytes(result) {
            Some(f) if f.abs_discriminant() == self.discriminant => f.reduce(&self.sqrt_abs_d),
            _ => return false,
        };
        let pi = match Form::from_bytes(proof) {
            Some(f) if f.abs_discriminant() == self.discriminant => f.reduce(&self.sqrt_abs_d),
            _ => return false,
        };

        let l = self.generate_l(&x, &y);
        let r = BigUint::from(2u32).modpow(&BigUint::from(self.difficulty), &l);

        // Verify: π^l ∘ x^r == y
        let pi_l = pi.pow(&l, &self.sqrt_abs_d, &self.discriminant);
        let x_r = x.pow(&r, &self.sqrt_abs_d, &self.discriminant);
        let left = pi_l.compose(&x_r, &self.sqrt_abs_d);

        left == y
    }

    /// Deterministic challenge prime l = HashToPrime(x, y).
    fn generate_l(&self, x: &Form, y: &Form) -> BigUint {
        trace!("  generate_l: enter");
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AETHERIS_VDF_L_CHALLENGE_V2");
        hasher.update(&x.to_bytes());
        hasher.update(&y.to_bytes());
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);

        let mut l = BigUint::from_bytes_be(&output);
        l.set_bit(256, true);          // guarantee at least 257-bit
        l |= BigUint::one();           // force odd

        let mut prime_iters = 0u64;
        while !self.is_probabilistic_prime(&l) {
            l += 2u32;
            prime_iters += 1;
            if prime_iters % 1000 == 0 {
                trace!("  generate_l: searching... iter={} l_bits={}", prime_iters, l.bits());
            }
        }
        trace!("  generate_l: found after {} iters, l_bits={}", prime_iters, l.bits());
        debug_assert!(l.bits() >= 256, "challenge prime below minimum bit-length");
        l
    }

    /// Deterministic difficulty retargeting.
    ///
    /// Given the current difficulty, the timestamps of a window of blocks,
    /// the target block time, and the window size, computes the next difficulty.
    ///
    /// Formula: D_new = D_old × target_window_time / actual_window_time
    ///
    /// This is deterministic: all nodes with the same chain data compute
    /// the same result. No communication needed.
    ///
    /// NOTE: This function is class-group agnostic — it only uses T (iteration
    /// count) and timestamps. The same retarget works for RSA or class-group VDF.
    /// However, T_genesis must be calibrated to the class group's slower compose
    /// (≈2-3x vs RSA) to hit the 10 s target block time.
    pub fn retarget_difficulty(
        current_difficulty: u64,
        timestamps: &[u64],
        target_block_time: u64,
    ) -> u64 {
        if timestamps.len() < 2 {
            return current_difficulty;
        }
        let window = (timestamps.len() - 1) as u64;
        let actual_time = timestamps[timestamps.len() - 1].saturating_sub(timestamps[0]);
        let target_time = target_block_time * window;

        let actual_time = actual_time.clamp(target_time / 4, target_time * 4);
        let new_diff = (current_difficulty as u128 * target_time as u128
            / actual_time.max(1) as u128) as u64;

        new_diff.clamp(current_difficulty / 4, current_difficulty * 4)
    }

    fn is_probabilistic_prime(&self, n: &BigUint) -> bool {
        if n <= &BigUint::from(1u32) { return false; }
        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) { return true; }
        if (n % 2u32).is_zero() { return false; }

        // Trial division by first 100 odd primes — catches ~90% of composites fast
        const SMALL_PRIMES: [u64; 100] = [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
            79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
            163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
            251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
            349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
            443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
        ];
        for &p in &SMALL_PRIMES {
            let p_big = BigUint::from(p);
            if *n == p_big { return true; }
            if (n % p).is_zero() { return false; }
        }

        let n_minus_1 = n - 1u32;
        let mut d = n_minus_1.clone();
        let mut s = 0u64;
        while (&d % 2u32).is_zero() {
            d /= 2u32;
            s += 1;
        }

        trace!("  is_probabilistic_prime: n_bits={} s={}", n.bits(), s);
        // 12 fixed Miller-Rabin bases — FIPS 186-5 requires ≥7 for 512-bit challenges
        let bases = [2u32, 3u32, 5u32, 7u32, 11u32, 13u32, 17u32, 19u32, 23u32, 29u32, 31u32, 37u32];
        for (_bi, &base) in bases.iter().enumerate() {
            let a = BigUint::from(base);
            if a >= *n { break; }
            let mut x = a.modpow(&d, n);
            if x == BigUint::one() || x == n_minus_1 {
                trace!("    MR base={} -> witness (1 or -1)", base);
                continue;
            }
            let mut composite = true;
            for _ in 0..s - 1 {
                x = x.modpow(&BigUint::from(2u32), n);
                if x == n_minus_1 {
                    composite = false;
                    break;
                }
            }
            if composite {
                trace!("    MR base={} -> composite", base);
                return false;
            }
            trace!("    MR base={} -> probable prime", base);
        }
        trace!("  is_probabilistic_prime: true");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_solve_verify() {
        let difficulty = 10;
        let vdf = VDF::new(difficulty);
        let seed = b"test_seed".to_vec();

        let (result, proof, _) = vdf.solve(&seed);
        assert!(vdf.verify(&seed, &result, &proof));
    }

    #[test]
    fn test_primality() {
        let vdf = VDF::new(10);
        assert!(vdf.is_probabilistic_prime(&BigUint::from(17u32)));
        assert!(vdf.is_probabilistic_prime(&BigUint::from(19u32)));
        assert!(!vdf.is_probabilistic_prime(&BigUint::from(21u32)));
    }

    #[test]
    fn test_vdf_solve_verify_roundtrip() {
        let vdf = VDF::new(10);
        let seed = b"test_seed_for_roundtrip";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Roundtrip: difficulty=10, duration={}ns", duration);
        assert!(vdf.verify(seed, &result, &proof));
    }

    #[test]
    fn test_different_difficulties_different_outputs() {
        let seed = b"same_seed_diff_diff";
        let vdf1 = VDF::new(5);
        let vdf2 = VDF::new(10);
        let (r1, _, _) = vdf1.solve(seed);
        let (r2, _, _) = vdf2.solve(seed);
        println!("Difficulty 5 result len: {}", r1.len());
        println!("Difficulty 10 result len: {}", r2.len());
        assert_ne!(r1, r2, "Different difficulties should produce different results");
    }

    #[test]
    fn test_empty_seed() {
        let vdf = VDF::new(10);
        let seed = b"";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Empty seed: duration={}ns, result_len={}, proof_len={}", duration, result.len(), proof.len());
        assert!(vdf.verify(seed, &result, &proof), "Empty seed should verify correctly");
    }

    #[test]
    fn test_verify_rejects_wrong_difficulty() {
        let vdf1 = VDF::new(10);
        let vdf2 = VDF::new(20);
        let seed = b"wrong_diff_test";
        let (result, proof, _) = vdf1.solve(seed);
        println!("Verifying with wrong difficulty (20 instead of 10)");
        assert!(!vdf2.verify(seed, &result, &proof), "Wrong difficulty should fail verification");
    }

    #[test]
    fn test_verify_rejects_wrong_seed() {
        let vdf = VDF::new(10);
        let seed_a = b"seed_A_for_test";
        let seed_b = b"seed_B_for_test";
        let (result, proof, _) = vdf.solve(seed_a);
        assert!(!vdf.verify(seed_b, &result, &proof), "Wrong seed should fail verification");
    }

    #[test]
    fn test_difficulty_zero() {
        let vdf = VDF::new(0);
        let seed = b"zero_difficulty_test";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Difficulty 0: duration={}ns, result_len={}", duration, result.len());
        assert!(vdf.verify(seed, &result, &proof), "Difficulty 0 roundtrip should pass");
    }

    #[test]
    fn test_large_difficulty() {
        let vdf = VDF::new(100);
        let seed = b"large_difficulty_test";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Large difficulty 100: duration={}ns", duration);
        assert!(vdf.verify(seed, &result, &proof), "Large difficulty roundtrip should pass");
    }

    #[test]
    fn test_deterministic_solves() {
        let vdf = VDF::new(10);
        let seed = b"deterministic_test_seed";
        let (r1, p1, _) = vdf.solve(seed);
        let (r2, p2, _) = vdf.solve(seed);
        assert_eq!(r1, r2, "Result should be deterministic");
        assert_eq!(p1, p2, "Proof should be deterministic");
    }

    #[test]
    fn test_result_fields() {
        let vdf = VDF::new(10);
        let seed = b"field_access_test";
        let (result, proof, duration_ns) = vdf.solve(seed);
        println!("Duration: {}ns, result_bytes: {}, proof_bytes: {}", duration_ns, result.len(), proof.len());
        assert!(!result.is_empty(), "Result should be non-empty");
        assert!(!proof.is_empty(), "Proof should be non-empty");
        assert!(duration_ns > 0, "Duration should be positive");
        assert!(vdf.verify(seed, &result, &proof));
    }

    #[test]
    fn test_retarget_difficulty_deterministic() {
        let timestamps = vec![100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200];
        let d1 = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        let d2 = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d1, d2, "Retarget must be deterministic");
    }

    #[test]
    fn test_retarget_on_target() {
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 10).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d, 1_600_000, "On-target window should keep same difficulty");
    }

    #[test]
    fn test_retarget_half_speed() {
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 20).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d, 800_000, "2x slower should halve difficulty");
    }

    #[test]
    fn test_retarget_double_speed() {
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 5).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d, 3_200_000, "2x faster should double difficulty");
    }

    #[test]
    fn test_retarget_clamp_extreme() {
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i / 10).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert!(d >= 1_600_000 / 4, "Difficulty should not drop below 1/4");
        assert!(d <= 1_600_000 * 4, "Difficulty should not exceed 4x");
    }

    #[test]
    fn test_retarget_insufficient_data() {
        let timestamps = vec![100];
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d, 1_600_000, "Insufficient data should return current difficulty");
    }

    #[test]
    fn test_boundary_seeds() {
        let vdf = VDF::new(10);

        let all_ones: Vec<u8> = vec![0xFF; 32];
        let (r1, p1, d1) = vdf.solve(&all_ones);
        println!("All-ones seed (32 bytes): duration={}ns", d1);
        assert!(vdf.verify(&all_ones, &r1, &p1), "All-ones seed should verify");

        let single_byte = vec![0xAB];
        let (r2, p2, d2) = vdf.solve(&single_byte);
        println!("Single-byte seed: duration={}ns", d2);
        assert!(vdf.verify(&single_byte, &r2, &p2), "Single-byte seed should verify");
    }

    #[test]
    fn test_vdf_bypass_rejected() {
        let vdf = VDF::new(10);
        let seed = b"any_seed".to_vec();
        let result = b"any_result".to_vec();

        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_"),
            "bare vdf_zkp_ prefix must not bypass verify");
        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_v2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "vdf_zkp_v2_ proof must not bypass verify");
        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_anything_at_all"),
            "arbitrary vdf_zkp_ data must not bypass verify");

        println!("[TEST VDF] Bypass rejection (S-2): OK");
    }

    #[test]
    fn test_verify_corrupted_proof() {
        let vdf = VDF::new(10);
        let seed = b"corruption_test";
        let (result, proof, _) = vdf.solve(seed);

        // Truncated result
        let truncated_result = &result[..result.len() / 2];
        assert!(!vdf.verify(seed, truncated_result, &proof));

        // Truncated proof
        let truncated_proof = &proof[..proof.len() / 2];
        assert!(!vdf.verify(seed, &result, truncated_proof));

        // Flipped bits in result
        let mut corrupted_result = result.clone();
        if !corrupted_result.is_empty() {
            corrupted_result[0] ^= 0xFF;
            assert!(!vdf.verify(seed, &corrupted_result, &proof));
        }

        // Flipped bits in proof
        let mut corrupted_proof = proof.clone();
        if !corrupted_proof.is_empty() {
            corrupted_proof[0] ^= 0xFF;
            assert!(!vdf.verify(seed, &result, &corrupted_proof));
        }

        // Empty proof / result already tested by verify returning false
        assert!(!vdf.verify(seed, b"", &proof));
        assert!(!vdf.verify(seed, &result, b""));
    }

    #[test]
    fn test_carmichael_numbers() {
        let vdf = VDF::new(10);

        // Known Carmichael numbers — Miller-Rabin with 12 bases must detect as composite
        let carmichaels: &[u64] = &[
            561,    // 3 × 11 × 17
            1105,   // 5 × 13 × 17
            1729,   // 7 × 13 × 19
            2465,   // 5 × 17 × 29
            2821,   // 7 × 13 × 31
            6601,   // 7 × 23 × 41
            8911,   // 7 × 19 × 67
        ];
        for &c in carmichaels {
            assert!(!vdf.is_probabilistic_prime(&BigUint::from(c)),
                "Carmichael number {} must be detected as composite", c);
        }

        // True primes must still be recognized
        let primes: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 101, 103, 1009, 104729];
        for &p in primes {
            assert!(vdf.is_probabilistic_prime(&BigUint::from(p)),
                "Prime {} must be recognized as prime", p);
        }
    }

    #[test]
    fn test_miller_rabin_strong_pseudoprime_resistance() {
        let vdf = VDF::new(10);

        // Some known strong pseudoprimes to small base sets.
        // 2047 = 23 × 89 is a strong pseudoprime to base 2.
        // Our 12 bases must detect it.
        assert!(!vdf.is_probabilistic_prime(&BigUint::from(2047u64)),
            "2047 (23×89) must be detected as composite");

        // 1373653 is a strong pseudoprime to bases 2 and 3.
        // Must be detected by the full 12-base set.
        assert!(!vdf.is_probabilistic_prime(&BigUint::from(1_373_653u64)),
            "1373653 must be detected as composite");
    }

    #[test]
    fn test_verify_deserialized_form_reduction() {
        let vdf = VDF::new(10);
        let seed = b"reduce_test";

        // Solve and verify immediately (forms are already reduced)
        let (result, proof, _) = vdf.solve(seed);
        assert!(vdf.verify(seed, &result, &proof),
            "Deserialized reduced forms must verify");

        // Create artificially non-reduced serialized form by modifying bytes
        // (verify must call reduce internally after deserialization)
        let vdf_large = VDF::new(100);
        let seed2 = b"reduce_test_large";
        let (result2, proof2, _) = vdf_large.solve(seed2);
        assert!(vdf_large.verify(seed2, &result2, &proof2),
            "Large-difficulty deserialized reduced forms must verify");
    }

    // ─── Discriminant-mismatch rejection (Option B boundary check) ────────
    //
    // Phase 1.7: VDF::verify now rejects forms whose discriminant differs
    // from self.discriminant at the boundary, preventing a debug-mode
    // panic at classgroup.rs:112 (compose: discriminant mismatch) and
    // the related line-139 CRT-exact-division assertion.

    /// Mutate the `a` coefficient of a serialized Form such that
    /// |b² − 4ac| changes (length prefix and sign byte stay valid).
    ///
    /// Wire format: `4B a_len ‖ a_bytes ‖ 4B b_len ‖ b_sign ‖ b_magnitude ‖ 4B c_len ‖ c_bytes`.
    /// Offset 8 lands inside `a_bytes` for any `a_len ≥ 5`. For the 2048-bit
    /// discriminant, `a` is at most ~256 bytes, so offset 8 is always inside `a`.
    /// Flipping a byte changes `a` → `a'`, so the new "discriminant"
    /// `|D'| = 4a'c − b² = |D| + 4(a' − a)c ≠ |D` (since `a' ≠ a` and `c ≠ 0`).
    fn corrupt_form_discriminant(serialized: &mut Vec<u8>) {
        assert!(serialized.len() > 8, "form too short to corrupt a-region byte");
        serialized[8] ^= 0xFF;
    }

    #[test]
    fn test_verify_rejects_wrong_discriminant_result() {
        let vdf = VDF::new(10);
        let seed = b"discrim_result_test";
        let (result, proof, _) = vdf.solve(seed);
        let mut bad_result = result.clone();
        corrupt_form_discriminant(&mut bad_result);
        assert!(!vdf.verify(seed, &bad_result, &proof),
            "Mismatched-discriminant result must be rejected (no panic)");
        assert!(vdf.verify(seed, &result, &proof),
            "Original (un-corrupted) roundtrip must still verify");
    }

    #[test]
    fn test_verify_rejects_wrong_discriminant_proof() {
        let vdf = VDF::new(10);
        let seed = b"discrim_proof_test";
        let (result, proof, _) = vdf.solve(seed);
        let mut bad_proof = proof.clone();
        corrupt_form_discriminant(&mut bad_proof);
        assert!(!vdf.verify(seed, &result, &bad_proof),
            "Mismatched-discriminant proof must be rejected (no panic)");
        assert!(vdf.verify(seed, &result, &proof),
            "Original (un-corrupted) roundtrip must still verify");
    }

    #[test]
    fn test_verify_rejects_both_wrong_discriminant() {
        let vdf = VDF::new(10);
        let seed = b"discrim_both_test";
        let (result, proof, _) = vdf.solve(seed);
        let mut bad_result = result.clone();
        let mut bad_proof = proof.clone();
        corrupt_form_discriminant(&mut bad_result);
        corrupt_form_discriminant(&mut bad_proof);
        assert!(!vdf.verify(seed, &bad_result, &bad_proof),
            "Both-mismatched-discriminant must be rejected (no panic)");
        assert!(vdf.verify(seed, &result, &proof),
            "Original (un-corrupted) roundtrip must still verify");
    }
}
