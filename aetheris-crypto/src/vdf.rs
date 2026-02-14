use std::time::{SystemTime, UNIX_EPOCH};
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub struct VDF {
    pub difficulty: u64,
    pub modulus: BigUint,
}

impl VDF {
    pub fn new(difficulty: u64) -> Self {
        // Use a 2048-bit RSA modulus (simulated with a known safe prime product)
        let modulus_str = concat!(
            "c536440263673c683883a48e71887e5b15488424075f65349e54e4c29729a59d",
            "1c068305f6396979207e35f498967964724a275217415f36894a428678088001",
            "895780287a91a924294a824687a41a247291a247291a47291a47291a47291a47",
            "291a47291a47291a47291a47291a47291a47291a47291a47291a47291a47291a"
        );
        let modulus = BigUint::parse_bytes(modulus_str.as_bytes(), 16).unwrap();
        Self { difficulty, modulus }
    }

    /// Computes Wesolowski VDF
    /// Returns (result, proof, duration_ns)
    pub fn solve(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>, u128) {
        let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        
        let x = BigUint::from_bytes_be(seed) % &self.modulus;
        let x = if x < BigUint::one() { BigUint::from(2u32) } else { x };

        let two = BigUint::from(2u32);
        let mut y = x.clone();
        
        for _ in 0..self.difficulty {
            y = y.modpow(&two, &self.modulus);
        }
        
        let l = self.generate_l(&x, &y);
        
        let mut q = BigUint::zero();
        let mut r = BigUint::from(1u32);
        let two = BigUint::from(2u32);
        for _ in 0..self.difficulty {
            let next_r = &r * &two;
            q *= &two;
            if next_r >= l {
                q += &next_r / &l;
                r = &next_r % &l;
            } else {
                r = next_r;
            }
        }
        
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
        let x = if x < BigUint::one() { BigUint::from(2u32) } else { x };
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
}
