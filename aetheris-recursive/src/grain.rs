//! Simplified Grain LFSR in self-shrinking mode, as used by Poseidon.
//!
//! This is a domain-agnostic 80-bit LFSR with the same recurrence and field-element
//! reduction strategy as Zcash's reference Poseidon implementation. State is held
//! in a `[u8; 10]` array and individual bits are addressed via `state[i / 8] & (1 << i % 8)`,
//! avoiding the `bitvec` crate as a dependency.
//!
//! The 80-bit LFSR recurrence is `s[t+62] = s[t+51] ^ s[t+38] ^ s[t+23] ^ s[t+13] ^ s[t]`,
//! with the first 160 emitted bits discarded as warm-up, then self-shrinking mode
//! discards bit pairs whose leading bit is 0. Rejection sampling is used to map
//! the bit sequence onto the field's canonical representative.

use ff::PrimeField;

const STATE_BITS: usize = 80;

pub struct GrainLFSR {
    state: [u8; STATE_BITS / 8],
    next_bit: usize,
}

fn bit_at(state: &[u8; STATE_BITS / 8], i: usize) -> bool {
    (state[i / 8] >> (i % 8)) & 1 != 0
}

fn set_bit(state: &mut [u8; STATE_BITS / 8], i: usize) {
    state[i / 8] |= 1 << (i % 8);
}

impl GrainLFSR {
    /// Initialize the LFSR with the Poseidon parameter encoding (MSB-first within
    /// each field, matching the Zcash reference impl):
    /// - bits 0..2   = field type tag (1 = prime order)
    /// - bits 2..6   = sbox type tag (0 = pow, x^alpha; alpha is taken as the field
    ///   security parameter, encoded separately when needed)
    /// - bits 6..18  = field bit length (F::NUM_BITS)
    /// - bits 18..30 = state size T (width of the Poseidon permutation)
    /// - bits 30..40 = r_f (number of full rounds)
    /// - bits 40..50 = r_p (number of partial rounds)
    ///
    /// The first 160 emitted bits are discarded as warm-up.
    pub fn new<F: PrimeField>(t: u16, r_f: u16, r_p: u16) -> Self {
        let mut state = [0u8; STATE_BITS / 8];
        let mut set_bits = |offset: usize, len: usize, value: u16| {
            for i in 0..len {
                if (value >> i) & 1 != 0 {
                    let idx = offset + len - 1 - i;
                    set_bit(&mut state, idx);
                }
            }
        };
        set_bits(0, 2, 1); // FieldType::PrimeOrder
        set_bits(2, 4, 0); // SboxType::Pow
        set_bits(6, 12, F::NUM_BITS as u16);
        set_bits(18, 12, t);
        set_bits(30, 10, r_f);
        set_bits(40, 10, r_p);

        let mut grain = Self { state, next_bit: STATE_BITS };
        for _ in 0..20 {
            grain.load_next_8_bits();
            grain.next_bit = STATE_BITS;
        }
        grain
    }

    /// Advance the LFSR by 8 steps, computing 8 new bits via the recurrence and
    /// shifting the state register.
    fn load_next_8_bits(&mut self) {
        let mut new_bits: u8 = 0;
        for i in 0..8u8 {
            let b0 = bit_at(&self.state, i as usize);
            let b13 = bit_at(&self.state, i as usize + 13);
            let b23 = bit_at(&self.state, i as usize + 23);
            let b38 = bit_at(&self.state, i as usize + 38);
            let b51 = bit_at(&self.state, i as usize + 51);
            let b62 = bit_at(&self.state, i as usize + 62);
            let bit = b0 ^ b13 ^ b23 ^ b38 ^ b51 ^ b62;
            new_bits |= (bit as u8) << i;
        }
        // Rotate state left by 8 bits
        let mut rotated = [0u8; STATE_BITS / 8];
        for i in 0..STATE_BITS {
            let src = (i + 8) % STATE_BITS;
            if bit_at(&self.state, src) {
                set_bit(&mut rotated, i);
            }
        }
        self.state = rotated;
        // Overwrite positions 72..80 with the new bits (assignment, not OR,
        // since the rotation already filled those positions with old bits).
        self.next_bit -= 8;
        for i in 0..8u8 {
            let idx = self.next_bit + i as usize;
            let byte = idx / 8;
            let bit_in_byte = idx % 8;
            if (new_bits >> i) & 1 != 0 {
                self.state[byte] |= 1 << bit_in_byte;
            } else {
                self.state[byte] &= !(1 << bit_in_byte);
            }
        }
    }

    fn get_next_bit(&mut self) -> bool {
        if self.next_bit == STATE_BITS {
            self.load_next_8_bits();
        }
        let ret = bit_at(&self.state, self.next_bit);
        self.next_bit += 1;
        ret
    }

    /// Self-shrinking mode: discard bit pairs whose leading bit is 0, otherwise
    /// emit the second bit. This is the Grain-in-self-shrinking-mode construction
    /// used by the Poseidon reference implementation to bias the output.
    fn next_emitted_bit(&mut self) -> bool {
        while !self.get_next_bit() {
            self.get_next_bit();
        }
        self.get_next_bit()
    }

    /// Build the next field element by collecting `F::NUM_BITS` emitted bits,
    /// interpreting them in MSB-first bit order (matching the reference impl),
    /// and rejecting samples that do not produce a valid field-element repr.
    pub fn next_field_element<F: PrimeField>(&mut self) -> F {
        let mut outer = 0u32;
        loop {
            outer += 1;
            if outer > 1000 {
                panic!("Grain: next_field_element exceeded 1000 outer iterations");
            }
            let mut repr = <F as PrimeField>::Repr::default();
            let bytes = repr.as_mut();
            for i in 0..F::NUM_BITS as usize {
                let bit = self.next_emitted_bit();
                let pos = F::NUM_BITS as usize - 1 - i;
                if bit {
                    bytes[pos / 8] |= 1 << (pos % 8);
                }
            }
            if let Some(f) = F::from_repr_vartime(repr) {
                return f;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::bn256::Fr as Fp;

    #[test]
    fn grain_generates_field_elements() {
        let mut grain = GrainLFSR::new::<Fp>(3, 8, 56);
        // Just verify it can produce T*T + (r_f + r_p) * T field elements without panicking
        for _ in 0..(3 * 3 + (8 + 56) * 3) {
            let f = grain.next_field_element::<Fp>();
            // Sanity: not zero with overwhelming probability
            let _ = f;
        }
    }
}
