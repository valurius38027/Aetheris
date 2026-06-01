use std::time::{SystemTime, UNIX_EPOCH};
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Aetheris Verifiable Delay Function (Wesolowski VDF)
///
/// The difficulty parameter controls the number of sequential squarings.
/// Difficulty is NOT permanently fixed — it adjusts via deterministic
/// retargeting (see `retarget_difficulty`) to maintain a constant block
/// time as hardware speeds evolve.
///
/// Security property: VDF proof BINDS the difficulty parameter.
/// A block claiming difficulty D cannot use a proof computed with
/// difficulty D' ≠ D — verification will fail.
pub struct VDF {
    pub difficulty: u64,
    pub modulus: BigUint,
}

impl VDF {
    pub fn new(difficulty: u64) -> Self {
        // RSA-2048 modulus from the RSA Factoring Challenge.
        // Source: https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
        // This is a well-known 2048-bit semiprime whose factors remain unknown.
        // Using this modulus ensures the VDF's sequentiality assumption holds.
        let modulus_str = concat!(
            "2519590847565789349402718324004839857142928212620403202777713783",
            "6043662020707595556264018525880716693393707690092433928669523162",
            "1332113167977740145143660241128128651571318133663015990925279534",
            "5406284763226658279999462176041112592934961523336169032395877292",
            "6130294440921183066020676656179588964424509327536664341607522675",
            "4334299293812742815218786148813520482179060066302435573282461334",
            "0760155423783273639098298109486195567697671388867587690641355365",
            "1444138621425171645214235838290586186493241498687868279016866673",
            "4609276567802507039061963056051027353524999690195908612605481897",
            "3283558255789369892939182183030431930850067754886497555323946874",
            "1239892405911210382547473295930826764832780375316692653445122202",
            "3520180924988787360509903391423534377035476077752761150740331089",
            "2498574749247168578578024926265177224310762270793261738762005598",
            "5308707937836026885223751528942314622246870065618379740976068165",
            "5290897776987020778630041458519388624101429259641233475669593367",
            "7555641150086904467380988630860537883679845043173371133263114727",
            "729747503354668607179890"
        );
        let modulus = BigUint::parse_bytes(modulus_str.as_bytes(), 10).unwrap();
        Self { difficulty, modulus }
    }

    /// Computes Wesolowski VDF
    /// Returns (result, proof, duration_ns)
    pub fn solve(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>, u128) {
        let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        
        let x = BigUint::from_bytes_be(seed) % &self.modulus;
        let x = if x < BigUint::from(2u32) { BigUint::from(2u32) } else { x };

        let two = BigUint::from(2u32);
        let mut y = x.clone();

        for _ in 0..self.difficulty {
            y = y.modpow(&two, &self.modulus);
        }

        let l = self.generate_l(&x, &y);

        // r = 2^T mod l  (modpow with exponent T ~21 bits, very fast)
        
        let l = self.generate_l(&x, &y);
        
        // r = 2^T mod l  (modpow with exponent T ~21 bits, very fast)
        let r = BigUint::from(2u32).modpow(&BigUint::from(self.difficulty), &l);
        // q = (2^T - r) / l  (one shift + sub + div, avoids T-iteration loop)
        let two_pow_t = BigUint::one() << self.difficulty;
        let q = (&two_pow_t - &r) / &l;
        
        let proof = x.modpow(&q, &self.modulus);

        let result = y.to_bytes_be();
        let proof_bytes = proof.to_bytes_be();
        let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        (result, proof_bytes, end - start)
    }

    /// Verifies Wesolowski VDF proof
    pub fn verify(&self, seed: &[u8], result: &[u8], proof: &[u8]) -> bool {
        if result.is_empty() || proof.is_empty() { return false; }

        let x = BigUint::from_bytes_be(seed) % &self.modulus;
        let x = if x < BigUint::from(2u32) { BigUint::from(2u32) } else { x };
        let y = BigUint::from_bytes_be(result);
        let pi = BigUint::from_bytes_be(proof);
        
        let l = self.generate_l(&x, &y);
        let r = BigUint::from(2u32).modpow(&BigUint::from(self.difficulty), &l);
        
        let pi_l = pi.modpow(&l, &self.modulus);
        let x_r = x.modpow(&r, &self.modulus);
        let left = (&pi_l * &x_r) % &self.modulus;
        
        left == y
    }

    fn generate_l(&self, x: &BigUint, y: &BigUint) -> BigUint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AETHERIS_VDF_L_CHALLENGE_V2");
        hasher.update(&x.to_bytes_be());
        hasher.update(&y.to_bytes_be());
        let mut hash_bytes = hasher.finalize().as_bytes().to_vec();
        
        hasher.update(b"EXTEND");
        hash_bytes.extend_from_slice(hasher.finalize().as_bytes());
        
        let mut l = BigUint::from_bytes_be(&hash_bytes);
        l |= BigUint::one();
        
        while !self.is_probabilistic_prime(&l) {
            l += 2u32;
        }
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
        
        let n_minus_1 = n - 1u32;
        let mut d = n_minus_1.clone();
        let mut s = 0u64;
        while (&d % 2u32).is_zero() {
            d /= 2u32;
            s += 1;
        }

        // Increased security: Use more bases for Miller-Rabin primality test
        // These bases provide a very high degree of certainty for primes up to 2^128 and beyond
        let bases = [2u32, 3u32, 5u32, 7u32, 11u32, 13u32, 17u32, 19u32, 23u32, 29u32, 31u32, 37u32];
        for &base in &bases {
            let a = BigUint::from(base);
            if a >= *n { break; }
            let mut x = a.modpow(&d, n);
            if x == BigUint::one() || x == n_minus_1 {
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
            if composite { return false; }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_solve_verify() {
        let difficulty = 100;
        let vdf = VDF::new(difficulty);
        let seed = b"test_seed".to_vec();

        let (result, proof, _) = vdf.solve(&seed);
        assert!(vdf.verify(&seed, &result, &proof));
    }

    #[test]
    fn test_primality() {
        let vdf = VDF::new(100);
        assert!(vdf.is_probabilistic_prime(&BigUint::from(17u32)));
        assert!(vdf.is_probabilistic_prime(&BigUint::from(19u32)));
        assert!(!vdf.is_probabilistic_prime(&BigUint::from(21u32)));
    }

    #[test]
    fn test_vdf_solve_verify_roundtrip() {
        let vdf = VDF::new(100);
        let seed = b"test_seed_for_roundtrip";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Roundtrip: difficulty=100, duration={}ns", duration);
        assert!(vdf.verify(seed, &result, &proof));
    }

    #[test]
    fn test_different_difficulties_different_outputs() {
        let seed = b"same_seed_diff_diff";
        let vdf1 = VDF::new(50);
        let vdf2 = VDF::new(100);
        let (r1, _, _) = vdf1.solve(seed);
        let (r2, _, _) = vdf2.solve(seed);
        println!("Difficulty 50 result: {:?}", r1);
        println!("Difficulty 100 result: {:?}", r2);
        assert_ne!(r1, r2, "Different difficulties should produce different results");
    }

    #[test]
    fn test_empty_seed() {
        let vdf = VDF::new(100);
        let seed = b"";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Empty seed: duration={}ns, result_len={}, proof_len={}", duration, result.len(), proof.len());
        assert!(vdf.verify(seed, &result, &proof), "Empty seed should verify correctly");
    }

    #[test]
    fn test_verify_rejects_wrong_difficulty() {
        let vdf1 = VDF::new(100);
        let vdf2 = VDF::new(200);
        let seed = b"wrong_diff_test";
        let (result, proof, _) = vdf1.solve(seed);
        println!("Verifying with wrong difficulty (200 instead of 100)");
        assert!(!vdf2.verify(seed, &result, &proof), "Wrong difficulty should fail verification");
    }

    #[test]
    fn test_verify_rejects_wrong_seed() {
        let vdf = VDF::new(100);
        let seed_a = b"seed_A_for_test";
        let seed_b = b"seed_B_for_test";
        let (result, proof, _) = vdf.solve(seed_a);
        println!("Verifying with wrong seed");
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
        let vdf = VDF::new(1000);
        let seed = b"large_difficulty_test";
        let (result, proof, duration) = vdf.solve(seed);
        println!("Large difficulty 1000: duration={}ns", duration);
        assert!(vdf.verify(seed, &result, &proof), "Large difficulty roundtrip should pass");
    }

    #[test]
    fn test_deterministic_solves() {
        let vdf = VDF::new(100);
        let seed = b"deterministic_test_seed";
        let (r1, p1, _) = vdf.solve(seed);
        let (r2, p2, _) = vdf.solve(seed);
        assert_eq!(r1, r2, "Result should be deterministic");
        assert_eq!(p1, p2, "Proof should be deterministic");
    }

    #[test]
    fn test_result_fields() {
        let vdf = VDF::new(50);
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
        // 10 blocks × 10s target = 100s. Our window is exactly 100s → no change.
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 10).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        assert_eq!(d, 1_600_000, "On-target window should keep same difficulty");
    }

    #[test]
    fn test_retarget_half_speed() {
        // Hardware is 2x slower: 20s per block instead of 10s.
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 20).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        // Actual = 200s, Target = 100s → difficulty should halve
        assert_eq!(d, 800_000, "2x slower should halve difficulty");
    }

    #[test]
    fn test_retarget_double_speed() {
        // Hardware is 2x faster: 5s per block instead of 10s.
        let timestamps: Vec<u64> = (0..=10).map(|i| 1000 + i * 5).collect();
        let d = VDF::retarget_difficulty(1_600_000, &timestamps, 10);
        // Actual = 50s, Target = 100s → difficulty should double
        assert_eq!(d, 3_200_000, "2x faster should double difficulty");
    }

    #[test]
    fn test_retarget_clamp_extreme() {
        // Extreme: 0.1s per block (100x faster). Clamping limits to 4x max.
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
        let vdf = VDF::new(100);

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
        // S-2 regression: vdf_zkp_ prefix must NOT bypass Wesolowski verification.
        // The old bypass (removed from main.rs:390) let arbitrary proofs through.
        // Here we verify VDF.verify rejects any vdf_zkp_ prefixed data.
        let vdf = VDF::new(100);
        let seed = b"any_seed".to_vec();
        let result = b"any_result".to_vec();

        // A trivial vdf_zkp_ prefixed proof must be rejected
        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_"),
            "bare vdf_zkp_ prefix must not bypass verify");
        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_v2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "vdf_zkp_v2_ proof must not bypass verify");
        assert!(!vdf.verify(&seed, &result, b"vdf_zkp_anything_at_all"),
            "arbitrary vdf_zkp_ data must not bypass verify");

        println!("[TEST VDF] Bypass rejection (S-2): OK");
    }
}
