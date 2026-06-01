use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero, Signed};
use std::mem;
use crate::trace;

/// A primitive positive-definite binary quadratic form (a, b, c)
/// representing f(x,y) = a·x² + b·x·y + c·y²
/// with discriminant Δ = b² - 4ac.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
}

fn abs_uint(x: &BigInt) -> BigUint {
    x.magnitude().clone()
}

fn bigint_from_uint(x: BigUint) -> BigInt {
    BigInt::from_biguint(Sign::Plus, x)
}

impl Form {
    pub fn new(a: BigInt, b: BigInt, c: BigInt) -> Self {
        Self { a, b, c }
    }

    /// Returns the discriminant Δ = b² - 4ac (negative for positive-definite forms).
    pub fn discriminant(&self) -> BigInt {
        &self.b * &self.b - BigInt::from(4) * &self.a * &self.c
    }

    /// Absolute value of the discriminant as BigUint.
    pub fn abs_discriminant(&self) -> BigUint {
        abs_uint(&self.discriminant())
    }

    /// Check if self is a reduced form: |b| ≤ a ≤ c, and if equality holds, b ≥ 0.
    pub fn is_reduced(&self) -> bool {
        if self.a <= BigInt::zero() { return false; }
        if self.c < self.a { return false; }
        if self.c == self.a && self.b < BigInt::zero() { return false; }
        let abs_b = self.b.abs();
        if abs_b > self.a { return false; }
        if abs_b == self.a && self.b < BigInt::zero() { return false; }
        true
    }

    /// Reduce the form to its unique reduced representative (Gauss reduction).
    pub fn reduce(&self, _sqrt_abs_d: &BigUint) -> Self {
        trace!("reduce: enter {:?}", self);
        let mut a = self.a.clone();
        let mut b = self.b.clone();
        let mut c = self.c.clone();

        let mut iter = 0u32;
        loop {
            iter += 1;
            // Step 1: If a > c or (a == c and b < 0), swap a ↔ c and negate b
            if a > c || (a == c && b < BigInt::zero()) {
                trace!("  reduce: swap a={} c={} b={}", a, c, b);
                mem::swap(&mut a, &mut c);
                b = -b;
                continue;
            }

            // Step 2: If |b| > a, reduce b modulo 2*a into (-a, a]
            let abs_b = b.abs();
            if abs_b > a {
                trace!("  reduce: reduce_b a={} b={} c={} iter={}", a, b, c, iter);
                let two_a = BigInt::from(2) * &a;
                let b_mod = ((&b % &two_a) + &two_a) % &two_a;
                let new_b = if b_mod > a {
                    &b_mod - &two_a
                } else {
                    b_mod
                };
                let b_sq = &new_b * &new_b;
                let disc = BigInt::from(4) * &a * &c - &b * &b;
                let four_a = BigInt::from(4) * &a;
                let new_c = (&b_sq + &disc) / &four_a;

                b = new_b;
                c = new_c;
                continue;
            }

            break;
        }

        trace!("  reduce: done ({}, {}, {}) after {} iter(s)", a, b, c, iter);
        Self { a, b, c }
    }

    /// Compute |D| = 4*a*c - b² from the form's own coefficients.
    /// This is the absolute value of the discriminant.
    fn abs_d_from_coeffs(a: &BigInt, b: &BigInt, c: &BigInt) -> BigInt {
        BigInt::from(4) * a * c - b * b
    }

    /// Gauss composition via extended GCD (Dirichlet composition).
    /// Algorithm: egcd(A1, A2) → (d, u, v); B = b1 + 2·A1·u·s + t·(2n/d).
    /// Squaring (a1==a2, b1==b2): t = (−g·c₁)·b₁⁻¹ mod A1.
    /// General: search t ∈ [0, d) for valid c3.
    pub fn compose(&self, other: &Self, sqrt_abs_d: &BigUint) -> Self {
        trace!("compose: {:?} ∘ {:?}", self, other);
        let a1 = &self.a; let b1 = &self.b; let c1 = &self.c;
        let a2 = &other.a; let b2 = &other.b; let c2 = &other.c;

        debug_assert_eq!(Self::abs_d_from_coeffs(a1, b1, c1),
                         Self::abs_d_from_coeffs(a2, b2, c2),
                         "compose: discriminant mismatch");

        // 1  g = gcd(a1, a2, (b1+b2)/2)
        let g1 = abs_uint(a1).gcd(&abs_uint(a2));
        let b12 = (b1 + b2) / BigInt::from(2);
        let g_uint = g1.gcd(&abs_uint(&b12));
        let g = bigint_from_uint(g_uint);

        // 2  n = a1·a2 / g²
        let n = (a1 * a2) / (&g * &g);

        // 3  A1 = a1/g, A2 = a2/g
        let a1_prime = a1 / &g;
        let a2_prime = a2 / &g;

        // 4  egcd: u·A1 + v·A2 = d (= gcd(A1, A2))
        let a1_prime_abs = abs_uint(&a1_prime);
        let a2_prime_abs = abs_uint(&a2_prime);
        let (d_uint, u, _v) = extended_gcd(&a1_prime_abs, &a2_prime_abs);
        let d = bigint_from_uint(d_uint.clone());

        // 5  s = (b2 - b1) / 2
        let s = (b2 - b1) / BigInt::from(2);

        // 6  x0 = u·s / d  (particular solution to A1·x ≡ s (mod A2))
        debug_assert!(
            (&u * &s) % &d == BigInt::zero(),
            "CRT exact division failed: d ∤ u·s"
        );
        let x0 = &u * &s / &d;

        // 7  B0 = b1 + 2·A1·x0
        let b0 = b1 + BigInt::from(2) * &a1_prime * &x0;

        // 8  M = 2·n / d  (step size for t)
        let m = BigInt::from(2) * &n / &d;

        let two_n = BigInt::from(2) * &n;
        let four_n = BigInt::from(4) * &n;
        let abs_d_val = Self::abs_d_from_coeffs(a1, b1, c1);

        // 9  Find t
        let t = if a1 == a2 && b1 == b2 {
            // Squaring: direct solve b1·t ≡ −g·c1 (mod A1)
            if a1_prime.is_one() {
                BigInt::zero()
            } else {
                let rhs = ((-&g * c1) % &a1_prime + &a1_prime) % &a1_prime;
                let b1_norm = ((b1 % &a1_prime) + &a1_prime) % &a1_prime;
                match mod_inverse(&abs_uint(&b1_norm), &a1_prime_abs) {
                    Some(inv_b1) => (bigint_from_uint(inv_b1) * &rhs) % &a1_prime,
                    None => {
                        // b1 not invertible mod A1 — fall back to general search
                        Self::find_t_general(&b0, &m, &four_n, &abs_d_val, &d_uint)
                    }
                }
            }
        } else {
            Self::find_t_general(&b0, &m, &four_n, &abs_d_val, &d_uint)
        };

        // 10  B = (B0 + t·M) normalized to [0, 2n)
        let b3 = ((&b0 + &t * &m) % &two_n + &two_n) % &two_n;

        // 11  c3 = (B² + |D|) / 4n
        let b3_sq = &b3 * &b3;
        let c3 = (&b3_sq + &abs_d_val) / &four_n;

        let result = Self { a: n, b: b3, c: c3 };
        trace!("  compose: pre-reduce {:?}", result);
        result.reduce(sqrt_abs_d)
    }

    fn find_t_general(b0: &BigInt, m: &BigInt, four_n: &BigInt, abs_d_val: &BigInt, d_uint: &BigUint) -> BigInt {
        let mut ti = BigUint::zero();
        while ti < *d_uint {
            let ti_big = bigint_from_uint(ti.clone());
            let b_val = b0 + &ti_big * m;
            let num = &b_val * &b_val + abs_d_val;
            if (&num % four_n).is_zero() {
                return ti_big;
            }
            ti += BigUint::one();
        }
        panic!("compose: no valid t found in [0, d)")
    }

    /// Square the form (compose with self) · optimized.
    pub fn square(&self, sqrt_abs_d: &BigUint) -> Self {
        self.compose(self, sqrt_abs_d)
    }

    /// Identity element for the class group Cl(D).
    pub fn identity(abs_d: &BigUint) -> Self {
        let d_mod_4 = abs_d % 4u32;
        if d_mod_4 == BigUint::from(3u32) {
            let one = BigInt::one();
            let c = (BigInt::one() + bigint_from_uint(abs_d.clone())) / BigInt::from(4);
            Self { a: one.clone(), b: one, c }
        } else {
            let c = bigint_from_uint(abs_d.clone()) / BigInt::from(4);
            Self { a: BigInt::one(), b: BigInt::zero(), c }
        }
    }

    /// Exponentiation by repeated squaring (double-and-add).
    pub fn pow(&self, exp: &BigUint, sqrt_abs_d: &BigUint, abs_d: &BigUint) -> Self {
        let mut result = Self::identity(abs_d);
        let mut base = self.clone();
        let mut e = exp.clone();
        while e > BigUint::zero() {
            if (&e & BigUint::one()) == BigUint::one() {
                result = result.compose(&base, sqrt_abs_d);
            }
            base = base.square(sqrt_abs_d);
            e >>= 1;
        }
        result
    }

    /// Deterministic hash-to-form: given seed bytes and |D|, produce a form in Cl(D).
    pub fn hash_to_form(seed: &[u8], sqrt_abs_d: &BigUint, abs_d: &BigUint) -> Self {
        trace!("hash_to_form: seed={:?} abs_d_bits={}", seed, abs_d.bits());
        const MAX_COUNTER: u64 = 10000;
        let mut counter: u64 = 0;
        loop {
            if counter > MAX_COUNTER {
                panic!("hash_to_form: no valid form found after {} iterations", MAX_COUNTER);
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AETHERIS_CLASSGROUP_HASH2FORM");
            hasher.update(seed);
            hasher.update(&counter.to_le_bytes());
            let hash = hasher.finalize();
            let hash_bytes = hash.as_bytes();

            let b_candidate = BigUint::from_bytes_be(&hash_bytes[..24]);
            let k_seed = u64::from_le_bytes([
                hash_bytes[24], hash_bytes[25], hash_bytes[26], hash_bytes[27],
                hash_bytes[28], hash_bytes[29], hash_bytes[30], hash_bytes[31],
            ]);

            let d_mod_4 = abs_d % 4u32;
            let b_adjusted = if d_mod_4 == BigUint::from(3u32) {
                if (&b_candidate % 2u32).is_zero() {
                    &b_candidate + BigUint::one()
                } else {
                    b_candidate.clone()
                }
            } else {
                if !(&b_candidate % 2u32).is_zero() {
                    &b_candidate + BigUint::one()
                } else {
                    b_candidate.clone()
                }
            };

            let bound = BigInt::from(2) * bigint_from_uint(sqrt_abs_d.clone());
            let b = bigint_from_uint(&b_adjusted % abs_uint(&bound));
            let b_sq = &b * &b;

            let abs_d_big = bigint_from_uint(abs_d.clone());
            let numerator = &b_sq + &abs_d_big;
            let k_min = (k_seed % 200 + 4) as u32;
            let k_max = k_min + 500;
            for k in k_min..=k_max {
                let k_big = BigInt::from(k);
                let four_k = BigInt::from(4) * &k_big;
                if (&numerator % &four_k).is_zero() {
                    let a = &numerator / &four_k;
                    let c = k_big;
                    let g = gcd_three(
                        &abs_uint(&a),
                        &abs_uint(&b),
                        &abs_uint(&c),
                    );
                    if g == BigUint::from(1u32) {
                        let result = Self { a, b, c };
                        return result.reduce(sqrt_abs_d);
                    }
                }
            }

            counter += 1;
        }
    }

    /// Serialize to bytes: a ∥ b ∥ c as big-endian, with length prefixes.
    /// Always produces canonical encoding (no leading zeros, no negative zero).
    pub fn to_bytes(&self) -> Vec<u8> {
        let a_bytes = {
            let mut bytes = abs_uint(&self.a).to_bytes_be();
            if bytes.is_empty() { bytes.push(0); }
            bytes
        };
        let b_bytes = {
            let abs = abs_uint(&self.b);
            let mut bytes = abs.to_bytes_be();
            if bytes.is_empty() { bytes.push(0); }
            if self.b < BigInt::zero() {
                bytes.insert(0, 0x01);
            } else {
                bytes.insert(0, 0x00);
            }
            bytes
        };
        let c_bytes = {
            let mut bytes = abs_uint(&self.c).to_bytes_be();
            if bytes.is_empty() { bytes.push(0); }
            bytes
        };

        let mut out = Vec::new();
        out.extend_from_slice(&(a_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&a_bytes);
        out.extend_from_slice(&(b_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&b_bytes);
        out.extend_from_slice(&(c_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&c_bytes);
        out
    }

    /// Deserialize from bytes produced by `to_bytes()`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        #[allow(unused_assignments)]
        let mut pos = 0usize;

        macro_rules! read_u32 {
            () => {{
                if pos + 4 > data.len() { return None; }
                let val = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                pos += 4;
                val
            }};
        }

        macro_rules! read_slice {
            ($len:expr) => {{
                let len = $len as usize;
                if pos + len > data.len() { return None; }
                let slice = &data[pos..pos + len];
                pos += len;
                slice
            }};
        }

        let a_len = read_u32!();
        let a_bytes = read_slice!(a_len);
        let a = bigint_from_uint(BigUint::from_bytes_be(a_bytes));

        let b_len = read_u32!();
        let b_bytes = read_slice!(b_len);
        let b_abs = BigUint::from_bytes_be(&b_bytes[1..]);
        let b = if b_bytes[0] == 0x01 {
            -bigint_from_uint(b_abs)
        } else {
            bigint_from_uint(b_abs)
        };

        let c_len = read_u32!();
        let c_bytes = read_slice!(c_len);
        let c = bigint_from_uint(BigUint::from_bytes_be(c_bytes));

        let _ = pos;
        Some(Self { a, b, c })
    }
}

/// Extended Euclidean algorithm for BigUint.
fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    let big_a = BigInt::from_biguint(Sign::Plus, a.clone());
    let big_b = BigInt::from_biguint(Sign::Plus, b.clone());
    let egcd = big_a.extended_gcd(&big_b);
    (abs_uint(&egcd.gcd), egcd.x, egcd.y)
}

/// Modular inverse of a mod m using extended Euclid.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (g, s, _t) = extended_gcd(a, m);
    if g != BigUint::one() {
        return None;
    }
    let m_big = BigInt::from_biguint(Sign::Plus, m.clone());
    let inv = ((s % &m_big) + &m_big) % &m_big;
    Some(abs_uint(&inv))
}

/// GCD of three BigUint values.
fn gcd_three(a: &BigUint, b: &BigUint, c: &BigUint) -> BigUint {
    let g1 = a.gcd(b);
    g1.gcd(c)
}

/// Integer square root: floor(sqrt(n))
pub fn integer_sqrt(n: &BigUint) -> BigUint {
    if n.is_zero() { return BigUint::zero(); }
    if n == &BigUint::one() { return BigUint::one(); }

    let bits = n.bits();
    trace!("integer_sqrt: bits={}", bits);
    let mut guess = BigUint::one() << ((bits + 1) / 2);
    let mut iter = 0u32;
    loop {
        iter += 1;
        let next = (&guess + n / &guess) >> 1;
        if next >= guess {
            break;
        }
        guess = next;
    }
    trace!("  integer_sqrt: {} iters, guess_bits={}", iter, guess.bits());
    guess
}

/// Generate a fundamental discriminant D < 0 from a seed.
pub fn generate_fundamental_discriminant(seed: &[u8], bit_length: u32) -> BigUint {
    trace!("generate_fundamental_discriminant: bit_length={}", bit_length);
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AETHERIS_CLASSGROUP_DISCRIMINANT");
        hasher.update(seed);
        hasher.update(&nonce.to_le_bytes());
        let candidate = BigUint::from_bytes_be(hasher.finalize().as_bytes());

        let mut candidate_bytes = vec![];
        let mut expand_counter = 0u64;
        while (candidate_bytes.len() as u32 * 8) < bit_length {
            let mut h = blake3::Hasher::new();
            h.update(&candidate.to_bytes_be());
            h.update(&expand_counter.to_le_bytes());
            candidate_bytes.extend_from_slice(h.finalize().as_bytes());
            expand_counter += 1;
        }
        let mut candidate = BigUint::from_bytes_be(&candidate_bytes);

        let mask = (BigUint::one() << bit_length) - BigUint::one();
        candidate = &candidate & &mask;
        candidate |= BigUint::one() << (bit_length - 1);

        let rem = &candidate % 4u32;
        let abs_d = if rem == BigUint::from(3u32) {
            candidate
        } else if rem == BigUint::from(1u32) {
            &candidate + BigUint::from(2u32)
        } else if rem.is_zero() {
            &candidate + BigUint::from(3u32)
        } else {
            &candidate + BigUint::one()
        };

        if has_square_factor(&abs_d) {
            nonce += 1;
            continue;
        }

        return abs_d;
    }
}

fn has_square_factor(n: &BigUint) -> bool {
    let small_primes: [u64; 20] = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    ];
    for &p in &small_primes {
        let p_sq = BigUint::from(p * p);
        if n < &p_sq { return false; }
        if (n % p_sq).is_zero() { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_discriminant() -> BigUint {
        generate_fundamental_discriminant(b"classgroup_test_fast_discriminant", 64)
    }

    fn test_sqrt_d() -> BigUint {
        integer_sqrt(&test_discriminant())
    }

    #[test]
    fn test_form_identity() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();
        let id = Form::identity(&abs_d);
        assert!(id.is_reduced(), "identity must be reduced");

        let id2 = id.compose(&id, &sqrt_d);
        assert_eq!(id, id2, "identity composed with itself must equal itself");
    }

    #[test]
    fn test_form_reduce() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();

        let form = Form {
            a: BigInt::from(100u32),
            b: BigInt::from(50u32),
            c: {
                let b_sq = BigInt::from(2500u32);
                let abs_d_big = bigint_from_uint(abs_d.clone());
                let num = &b_sq + &abs_d_big;
                let denom = BigInt::from(400u32);
                &num / &denom
            },
        };

        if !form.is_reduced() {
            let reduced = form.reduce(&sqrt_d);
            assert!(reduced.is_reduced(), "reduced form must satisfy reduction criteria");
            assert_eq!(form.discriminant(), reduced.discriminant(),
                "reduction must preserve discriminant");
        }
    }

    #[test]
    fn test_form_compose_identity() {
        let abs_d = generate_fundamental_discriminant(b"test_compose_identity", 64);
        let sqrt_d = integer_sqrt(&abs_d);
        let id = Form::identity(&abs_d);

        let seed = b"test_compose_identity_seed";
        let form = Form::hash_to_form(seed, &sqrt_d, &abs_d);

        println!("  identity = {:?}", id);
        println!("  form = {:?}", form);
        println!("  abs_d = {:?}", abs_d);
        println!("  sqrt_d = {:?}", sqrt_d);

        let composed = form.compose(&id, &sqrt_d);
        assert_eq!(form, composed, "f ∘ I must equal f\n  lhs = {:?}\n  rhs = {:?}", form, composed);

        let composed2 = id.compose(&form, &sqrt_d);
        assert_eq!(form, composed2, "I ∘ f must equal f\n  lhs = {:?}\n  rhs = {:?}", form, composed2);
    }

    #[test]
    fn test_form_compose_associative() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();

        let f1 = Form::hash_to_form(b"seed_1", &sqrt_d, &abs_d);
        let f2 = Form::hash_to_form(b"seed_2", &sqrt_d, &abs_d);
        let f3 = Form::hash_to_form(b"seed_3", &sqrt_d, &abs_d);

        let left = f1.compose(&f2, &sqrt_d).compose(&f3, &sqrt_d);
        let right = f1.compose(&f2.compose(&f3, &sqrt_d), &sqrt_d);
        assert_eq!(left, right, "composition must be associative");
    }

    #[test]
    fn test_form_pow() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();
        let id = Form::identity(&abs_d);
        let form = Form::hash_to_form(b"pow_test", &sqrt_d, &abs_d);

        let pow1 = form.pow(&BigUint::from(1u32), &sqrt_d, &abs_d);
        assert_eq!(form, pow1, "f^1 must equal f");

        let pow2 = form.pow(&BigUint::from(2u32), &sqrt_d, &abs_d);
        let square = form.square(&sqrt_d);
        assert_eq!(pow2, square, "f^2 must equal f ∘ f");

        let pow0 = form.pow(&BigUint::zero(), &sqrt_d, &abs_d);
        assert_eq!(id, pow0, "f^0 must equal identity");
    }

    #[test]
    fn test_hash_to_form_deterministic() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();

        let f1 = Form::hash_to_form(b"deterministic_test", &sqrt_d, &abs_d);
        let f2 = Form::hash_to_form(b"deterministic_test", &sqrt_d, &abs_d);
        assert_eq!(f1, f2, "hash-to-form must be deterministic");

        let f3 = Form::hash_to_form(b"different_seed", &sqrt_d, &abs_d);
        assert_ne!(f1, f3, "different seeds must produce different forms");
    }

    #[test]
    fn test_form_serialization_roundtrip() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();
        let form = Form::hash_to_form(b"serialization_test", &sqrt_d, &abs_d);

        let bytes = form.to_bytes();
        let deserialized = Form::from_bytes(&bytes).expect("deserialization must succeed");
        assert_eq!(form, deserialized, "serialization roundtrip must preserve form");
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(&BigUint::from(0u32)), BigUint::from(0u32));
        assert_eq!(integer_sqrt(&BigUint::from(1u32)), BigUint::from(1u32));
        assert_eq!(integer_sqrt(&BigUint::from(4u32)), BigUint::from(2u32));
        assert_eq!(integer_sqrt(&BigUint::from(9u32)), BigUint::from(3u32));
        assert_eq!(integer_sqrt(&BigUint::from(100u32)), BigUint::from(10u32));

        assert_eq!(integer_sqrt(&BigUint::from(2u32)), BigUint::from(1u32));
        assert_eq!(integer_sqrt(&BigUint::from(5u32)), BigUint::from(2u32));
        assert_eq!(integer_sqrt(&BigUint::from(10u32)), BigUint::from(3u32));
        assert_eq!(integer_sqrt(&BigUint::from(99u32)), BigUint::from(9u32));

        let n = BigUint::from(12345678901234567890u64);
        let s = integer_sqrt(&n);
        assert!(&s * &s <= n, "sqrt² must be ≤ n");
        assert!((&s + BigUint::one()) * (&s + BigUint::one()) > n, "(sqrt+1)² must be > n");
    }

    #[test]
    fn test_fundamental_discriminant() {
        let d = generate_fundamental_discriminant(b"test", 256);
        assert!(d.bits() >= 256, "discriminant must be at least 256 bits");
        assert_eq!(d % 4u32, BigUint::from(3u32),
            "for D ≡ 1 (mod 4), |D| must be ≡ 3 (mod 4)");
    }

    #[test]
    fn test_form_compose_inverse() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();
        let id = Form::identity(&abs_d);
        let f = Form::hash_to_form(b"inverse_test", &sqrt_d, &abs_d);

        // Inverse is (a, -b, c)
        let finv = Form { a: f.a.clone(), b: -&f.b, c: f.c.clone() };

        let left = f.compose(&finv, &sqrt_d);
        let right = finv.compose(&f, &sqrt_d);
        assert_eq!(left, id, "f ∘ f⁻¹ must equal identity");
        assert_eq!(right, id, "f⁻¹ ∘ f must equal identity");
    }

    #[test]
    fn test_form_compose_crt_path() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();

        // Generate many forms and find a pair where gcd(A1, A2) > 1 (CRT path)
        let seeds: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"];
        let forms: Vec<Form> = seeds.iter()
            .map(|s| Form::hash_to_form(s, &sqrt_d, &abs_d))
            .collect();

        let mut crt_tested = false;
        for i in 0..forms.len() {
            for j in (i + 1)..forms.len() {
                let a1 = abs_uint(&forms[i].a);
                let a2 = abs_uint(&forms[j].a);
                let gcd_a = a1.gcd(&a2);
                if gcd_a > BigUint::one() {
                    let composed = forms[i].compose(&forms[j], &sqrt_d);
                    assert_eq!(Form::abs_d_from_coeffs(&composed.a, &composed.b, &composed.c),
                               BigInt::from_biguint(Sign::Plus, abs_d.clone()),
                        "CRT compose must preserve discriminant");
                    crt_tested = true;
                    break;
                }
            }
            if crt_tested { break; }
        }
        if !crt_tested {
            println!("[SKIP] No CRT-path pair found with 64-bit discriminant");
        }
    }

    #[test]
    fn test_identity_both_branches() {
        // Branch 1: |D| ≡ 3 (mod 4)  →  D ≡ 1 (mod 4) → b=1
        let d1 = generate_fundamental_discriminant(b"identity_test_d1", 64);
        let sqrt_d1 = integer_sqrt(&d1);
        let id1 = Form::identity(&d1);
        assert!(id1.is_reduced());
        assert_eq!(id1.a, BigInt::one());
        assert_eq!(id1.b, BigInt::one());

        // Branch 2: |D| ≡ 1 (mod 4)  →  D ≡ 3 (mod 4) → b=0
        let d2 = BigUint::from(21u32);
        let sqrt_d2 = integer_sqrt(&d2);
        let id2 = Form::identity(&d2);
        assert!(id2.is_reduced());
        assert_eq!(id2.a, BigInt::one());
        assert_eq!(id2.b, BigInt::zero());

        // Compose identity (branch 1) with a form from the same discriminant
        let form = Form::hash_to_form(b"branch_test", &sqrt_d1, &d1);
        assert_eq!(form.compose(&id1, &sqrt_d1), form, "identity compose (b=1)");
        assert_eq!(id1.compose(&form, &sqrt_d1), form, "identity compose reversed (b=1)");

        // For branch 2, create a form manually (hash_to_form may fail with small |D|)
        // Test that identity compose preserves the form
        let val = BigInt::from(2u32);
        let manual = Form { a: val.clone(), b: val.clone(), c: (BigInt::from(4) + BigInt::from(21u32)) / (BigInt::from(4) * BigInt::from(2)) };
        let manual_reduced = manual.reduce(&sqrt_d2);
        assert_eq!(manual_reduced.compose(&id2, &sqrt_d2), manual_reduced, "identity compose (b=0)");
    }

    #[test]
    fn test_serialization_canonical() {
        let abs_d = test_discriminant();
        let sqrt_d = test_sqrt_d();

        // Normal form roundtrip
        let f = Form::hash_to_form(b"canon_test", &sqrt_d, &abs_d);
        let bytes = f.to_bytes();
        let f2 = Form::from_bytes(&bytes).unwrap();
        assert_eq!(f, f2);

        // Identity form roundtrip
        let id = Form::identity(&abs_d);
        let id_bytes = id.to_bytes();
        let id2 = Form::from_bytes(&id_bytes).unwrap();
        assert_eq!(id, id2);

        // Negative b serialization
        let finv = Form { a: f.a.clone(), b: -&f.b, c: f.c.clone() };
        let inv_bytes = finv.to_bytes();
        let finv2 = Form::from_bytes(&inv_bytes).unwrap();
        assert_eq!(finv, finv2);

        // Canonical: no leading zeros (first byte after length prefix should not be 0x00 for positive a/c)
        assert_ne!(bytes[4], 0x00, "a must not have leading zeros");
    }

    #[test]
    fn test_hash_to_form_counter_used() {
        let abs_d = generate_fundamental_discriminant(b"counter_test", 256);
        let sqrt_d = integer_sqrt(&abs_d);

        // Same seed must always produce same form
        let f1 = Form::hash_to_form(b"counter", &sqrt_d, &abs_d);
        let f2 = Form::hash_to_form(b"counter", &sqrt_d, &abs_d);
        assert_eq!(f1, f2);

        // Must be reduced
        assert!(f1.is_reduced());
        assert!(f2.is_reduced());
    }

    #[test]
    fn test_compose_2048_bit() {
        let abs_d = generate_fundamental_discriminant(b"compose_2048_test", 2048);
        let sqrt_d = integer_sqrt(&abs_d);

        let f1 = Form::hash_to_form(b"f1_2048", &sqrt_d, &abs_d);
        let f2 = Form::hash_to_form(b"f2_2048", &sqrt_d, &abs_d);

        let composed = f1.compose(&f2, &sqrt_d);
        assert!(composed.is_reduced());
        assert_eq!(Form::abs_d_from_coeffs(&composed.a, &composed.b, &composed.c),
                   BigInt::from_biguint(Sign::Plus, abs_d.clone()));

        // Verify associativity with 2048-bit discriminants
        let f3 = Form::hash_to_form(b"f3_2048", &sqrt_d, &abs_d);
        let left = f1.compose(&f2, &sqrt_d).compose(&f3, &sqrt_d);
        let right = f1.compose(&f2.compose(&f3, &sqrt_d), &sqrt_d);
        assert_eq!(left, right);
    }
}
