use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::halo2curves::pasta::Fq;

const STATE_BITS: usize = 80;

struct GrainLFSR {
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
    fn new<F: PrimeField>(t: u16, r_f: u16, r_p: u16) -> Self {
        let mut state = [0u8; STATE_BITS / 8];
        let mut set_bits = |offset: usize, len: usize, value: u16| {
            for i in 0..len {
                if (value >> i) & 1 != 0 {
                    let idx = offset + len - 1 - i;
                    set_bit(&mut state, idx);
                }
            }
        };
        set_bits(0, 2, 1);
        set_bits(2, 4, 0);
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
        let mut rotated = [0u8; STATE_BITS / 8];
        for i in 0..STATE_BITS {
            let src = (i + 8) % STATE_BITS;
            if bit_at(&self.state, src) {
                set_bit(&mut rotated, i);
            }
        }
        self.state = rotated;
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

    fn next_emitted_bit(&mut self) -> bool {
        while !self.get_next_bit() {
            self.get_next_bit();
        }
        self.get_next_bit()
    }

    fn next_field_element<F: PrimeField>(&mut self) -> F {
        let mut outer = 0u32;
        loop {
            outer += 1;
            if outer > 1000 {
                panic!("Grain: next_field_element exceeded 1000 iterations");
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

#[derive(Clone, Debug)]
pub struct PoseidonFqSpec {
    pub r_f: usize,
    pub r_p: usize,
    pub mds: [[Fq; 3]; 3],
    pub constants: Vec<[Fq; 3]>,
}

impl PoseidonFqSpec {
    pub fn new(r_f: usize, r_p: usize) -> Self {
        let mut grain = GrainLFSR::new::<Fq>(3, r_f as u16, r_p as u16);
        let mut mds = [[Fq::ZERO; 3]; 3];
        for i in 0..3 {
            for j in 0..3 {
                mds[i][j] = grain.next_field_element::<Fq>();
            }
        }
        let mut constants = vec![[Fq::ZERO; 3]; r_f + r_p];
        for i in 0..(r_f + r_p) {
            for j in 0..3 {
                constants[i][j] = grain.next_field_element::<Fq>();
            }
        }
        Self { r_f, r_p, mds, constants }
    }
}

pub fn poseidon_permute(spec: &PoseidonFqSpec, state: &mut [Fq; 3]) {
    for r in 0..spec.r_f / 2 {
        for i in 0..3 {
            state[i] = add_rc(state[i], spec.constants[r][i]);
            state[i] = pow5(state[i]);
        }
        apply_mds(state, &spec.mds);
    }
    for r in spec.r_f / 2..spec.r_f / 2 + spec.r_p {
        for i in 0..3 {
            state[i] = add_rc(state[i], spec.constants[r][i]);
        }
        state[0] = pow5(state[0]);
        apply_mds(state, &spec.mds);
    }
    for r in spec.r_f / 2 + spec.r_p..spec.r_f + spec.r_p {
        for i in 0..3 {
            state[i] = add_rc(state[i], spec.constants[r][i]);
            state[i] = pow5(state[i]);
        }
        apply_mds(state, &spec.mds);
    }
}

fn add_rc(a: Fq, rc: Fq) -> Fq {
    a + rc
}

fn pow5(x: Fq) -> Fq {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

fn apply_mds(state: &mut [Fq; 3], mds: &[[Fq; 3]; 3]) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    state[0] = mds[0][0] * s0 + mds[0][1] * s1 + mds[0][2] * s2;
    state[1] = mds[1][0] * s0 + mds[1][1] * s1 + mds[1][2] * s2;
    state[2] = mds[2][0] * s0 + mds[2][1] * s1 + mds[2][2] * s2;
}

pub fn poseidon_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let spec = PoseidonFqSpec::new(8, 56);
    let mut state = [
        Fq::from_repr(*left).expect("poseidon_hash: left is canonical Fq"),
        Fq::from_repr(*right).expect("poseidon_hash: right is canonical Fq"),
        Fq::ZERO,
    ];
    poseidon_permute(&spec, &mut state);
    state[0].to_repr()
}

pub fn poseidon_nullifier(sk: &[u8; 32], index: u64) -> [u8; 32] {
    let spec = PoseidonFqSpec::new(8, 56);
    let sk_fq = Fq::from_repr(*sk).expect("poseidon_nullifier: sk is canonical Fq");
    let index_fq = Fq::from(index);
    let mut state = [sk_fq, index_fq, Fq::ZERO];
    poseidon_permute(&spec, &mut state);
    state[0].to_repr()
}

static POSEIDON_SPEC: std::sync::OnceLock<PoseidonFqSpec> = std::sync::OnceLock::new();

pub fn ensure_poseidon_spec() -> &'static PoseidonFqSpec {
    POSEIDON_SPEC.get_or_init(|| PoseidonFqSpec::new(8, 56))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fq_repr(val: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        bytes
    }

    #[test]
    fn test_poseidon_deterministic() {
        let left = make_fq_repr(1);
        let right = make_fq_repr(2);
        let h1 = poseidon_hash(&left, &right);
        let h2 = poseidon_hash(&left, &right);
        assert_eq!(h1, h2, "Poseidon hash must be deterministic");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = poseidon_hash(&make_fq_repr(1), &make_fq_repr(2));
        let b = poseidon_hash(&make_fq_repr(1), &make_fq_repr(3));
        assert_ne!(a, b, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon_nullifier_deterministic() {
        let sk = make_fq_repr(0xDE);
        let nf1 = poseidon_nullifier(&sk, 42);
        let nf2 = poseidon_nullifier(&sk, 42);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_poseidon_nullifier_different_index() {
        let sk = make_fq_repr(0xDE);
        let nf1 = poseidon_nullifier(&sk, 1);
        let nf2 = poseidon_nullifier(&sk, 2);
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_poseidon_permute_identity() {
        let spec = PoseidonFqSpec::new(8, 56);
        let state = [Fq::ZERO, Fq::ZERO, Fq::ZERO];
        let mut out = state;
        poseidon_permute(&spec, &mut out);
        assert_ne!(out, state, "Zero input should NOT produce zero output");
    }
}
