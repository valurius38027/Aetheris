use crate::{EqAffine, Fq};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{ConstraintSystem, ErrorFront},
};
use halo2curves::CurveAffine;
use aetheris_zkp::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};
use aetheris_zkp::poseidon_fq::{PoseidonFqSpec, ensure_poseidon_spec, poseidon_permute};
use ff::Field;


/// Protocol domain separator for transcript init.
pub(crate) fn transcript_domain() -> Fq {
    Fq::from(42u64)
}

/// Capacity lane filler (state[2] is always 0).
fn capacity_fill() -> Fq {
    Fq::ZERO
}

#[derive(Clone, Debug)]
pub struct PoseidonTranscriptConfig {
    pub poseidon: PoseidonFqConfig,
}

impl PoseidonTranscriptConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fq>) -> Self {
        Self {
            poseidon: PoseidonFqChip::configure(meta),
        }
    }
}

pub struct PoseidonTranscriptChip {
    poseidon: PoseidonFqChip,
}

impl PoseidonTranscriptChip {
    pub fn new(config: &PoseidonTranscriptConfig) -> Self {
        Self {
            poseidon: PoseidonFqChip::new(config.poseidon.clone()),
        }
    }

    /// Host-side IPA challenge derivation using the same Poseidon chain protocol.
    pub fn host_derive_ipa_challenges(
        k: usize,
        l_x: &[Fq],
        l_y: &[Fq],
        r_x: &[Fq],
        r_y: &[Fq],
    ) -> Vec<Fq> {
        let (_theta, chals) = Self::host_derive_ipa_theta_and_challenges(k, l_x, l_y, r_x, r_y);
        chals
    }

    /// Host-side Poseidon transcript replay for IPA: returns (theta, round_challenges).
    ///
    /// Protocol (matching `VestaAccumulateChip::squeeze_challenges`):
    ///   state = Poseidon(TRANSCRIPT_DOMAIN, CAPACITY)
    ///   absorb(k)
    ///   theta = state[0]                      ← squeeze BEFORE first L/R
    ///   for each round i:
    ///       absorb(L_i.x, L_i.y, R_i.x, R_i.y)
    ///       x_i = state[0]                    ← squeeze before advance
    ///       state = Poseidon(state, CAPACITY)  ← advance permutation
    pub fn host_derive_ipa_theta_and_challenges(
        k: usize,
        l_x: &[Fq],
        l_y: &[Fq],
        r_x: &[Fq],
        r_y: &[Fq],
    ) -> (Fq, Vec<Fq>) {
        let spec = ensure_poseidon_spec();
        let mut state = host_poseidon(transcript_domain(), capacity_fill(), spec);

        state = host_poseidon(state, Fq::from(k as u64), spec);
        let theta = state;
        let mut chals = Vec::with_capacity(k);
        for i in 0..k {
            state = host_poseidon(state, l_x[i], spec);
            state = host_poseidon(state, l_y[i], spec);
            state = host_poseidon(state, r_x[i], spec);
            state = host_poseidon(state, r_y[i], spec);
            chals.push(state);
            state = host_poseidon(state, capacity_fill(), spec);
        }
        (theta, chals)
    }

    /// Circuit-side init: state = Poseidon(transcript_domain(), capacity_fill()).
    pub fn assign_init(
        &self,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<AssignedCell<Fq, Fq>, ErrorFront> {
        self.poseidon.assign_hash(
            layouter.namespace(|| "poseidon_init"),
            Value::known(transcript_domain()),
            Value::known(capacity_fill()),
            None,
            None,
        )
    }

    /// Circuit-side absorb scalar: state = Poseidon(state[0], scalar).
    pub fn assign_absorb_scalar(
        &self,
        mut layouter: impl Layouter<Fq>,
        state: &AssignedCell<Fq, Fq>,
        scalar: Value<Fq>,
    ) -> Result<AssignedCell<Fq, Fq>, ErrorFront> {
        let v = state.value().map(|&v| v);
        self.poseidon.assign_hash(
            layouter.namespace(|| "poseidon_absorb_scalar"),
            v,
            scalar,
            Some(state.cell()),
            None,
        )
    }

    /// Circuit-side absorb point coordinate: state = Poseidon(state[0], coord).
    pub fn assign_absorb_coord(
        &self,
        mut layouter: impl Layouter<Fq>,
        state: &AssignedCell<Fq, Fq>,
        coord: Value<Fq>,
    ) -> Result<AssignedCell<Fq, Fq>, ErrorFront> {
        let v = state.value().map(|&v| v);
        self.poseidon.assign_hash(
            layouter.namespace(|| "poseidon_absorb_coord"),
            v,
            coord,
            Some(state.cell()),
            None,
        )
    }

    /// Circuit-side squeeze: return challenge (pre-permutation state[0]) + advanced state.
    pub fn assign_squeeze(
        &self,
        mut layouter: impl Layouter<Fq>,
        state: &AssignedCell<Fq, Fq>,
    ) -> Result<(AssignedCell<Fq, Fq>, AssignedCell<Fq, Fq>), ErrorFront> {
        let v = state.value().map(|&v| v);
        let new_state = self.poseidon.assign_hash(
            layouter.namespace(|| "poseidon_squeeze"),
            v,
            Value::known(capacity_fill()),
            Some(state.cell()),
            None,
        )?;
        Ok((state.clone(), new_state))
    }
}

/// Host-side Poseidon hash chain: Poseidon(left, right, 0) → state[0].
fn host_poseidon(left: Fq, right: Fq, spec: &PoseidonFqSpec) -> Fq {
    let mut state = [left, right, Fq::ZERO];
    poseidon_permute(spec, &mut state);
    state[0]
}

/// Incremental host-side transcript for IPA challenge derivation.
/// Manages a mutable state for sequential absorb/squeeze operations.
pub struct HostTranscript {
    state: Fq,
    spec: &'static PoseidonFqSpec,
}

impl HostTranscript {
    pub fn new() -> Self {
        let spec = ensure_poseidon_spec();
        let state = host_poseidon(transcript_domain(), capacity_fill(), spec);
        Self { state, spec }
    }

    pub fn absorb_scalar(&mut self, s: Fq) {
        self.state = host_poseidon(self.state, s, self.spec);
    }

    pub fn absorb_point(&mut self, p: &EqAffine) {
        let coords = p.coordinates().unwrap();
        self.state = host_poseidon(self.state, *coords.x(), self.spec);
        self.state = host_poseidon(self.state, *coords.y(), self.spec);
    }

    pub fn squeeze(&mut self) -> Fq {
        let chal = self.state;
        self.state = host_poseidon(self.state, capacity_fill(), self.spec);
        chal
    }

    pub fn current(&self) -> Fq {
        self.state
    }
}
