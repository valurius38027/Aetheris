use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, ErrorFront, Expression, Instance, Selector,
    },
    poly::Rotation,
};
use halo2_proofs::halo2curves::pasta::Fq;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::arithmetic::Field;

use crate::poseidon_fq_chip::{PoseidonFqChip, PoseidonFqConfig};

/// Maximum Merkle-tree depth supported by the membership circuit.
/// Set to 16 ⇒ supports up to 2^16 = 65536 leaves.
pub const MEMBERSHIP_DEPTH: usize = 16;

/// K value for the membership circuit (must be large enough for DEPTH+1 Poseidon hashes)
/// Each Poseidon hash = 65 rows. With DEPTH=16: 17*65 = 1105 rows. K=11 gives 2048.
pub const MEMBERSHIP_K: u32 = 11;

#[derive(Clone, Debug)]
pub struct MembershipConfig {
    pub poseidon: PoseidonFqConfig,
    pub leaf: Column<Advice>,
    pub siblings: Column<Advice>,
    pub sk: Column<Advice>,
    pub index: Column<Advice>,
    pub bit: Column<Advice>,
    pub s_bool: Selector,
    pub instance: Column<Instance>,
}

#[derive(Clone)]
pub struct MembershipCircuit {
    /// Private witness: leaf (note commitment)
    pub leaf: [u8; 32],
    /// Private witness: Merkle path siblings
    pub path_siblings: Vec<[u8; 32]>,
    /// Private witness: path position bits
    pub position_bits: Vec<bool>,
    /// Private witness: nullifier secret key
    pub sk: [u8; 32],
    /// Private witness: commitment index
    pub index: u64,
    /// Public input: expected merkle root
    pub merkle_root: [u8; 32],
    /// Public input: expected nullifier
    pub nullifier: [u8; 32],
}

impl MembershipCircuit {
    pub fn dummy(depth: usize) -> Self {
        Self {
            leaf: [0u8; 32],
            path_siblings: vec![[0u8; 32]; depth],
            position_bits: vec![false; depth],
            sk: [0u8; 32],
            index: 0,
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
        }
    }

    pub fn without_witnesses(&self) -> Self {
        Self {
            leaf: [0u8; 32],
            path_siblings: vec![[0u8; 32]; self.path_siblings.len()],
            position_bits: self.position_bits.clone(),
            sk: [0u8; 32],
            index: 0,
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
        }
    }
}

impl halo2_proofs::plonk::Circuit<Fq> for MembershipCircuit {
    type Config = MembershipConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.without_witnesses()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let poseidon = PoseidonFqChip::configure(meta);
        let leaf = meta.advice_column();
        let siblings = meta.advice_column();
        let sk = meta.advice_column();
        let index = meta.advice_column();
        let bit = meta.advice_column();
        let s_bool = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(leaf);
        meta.enable_equality(siblings);
        meta.enable_equality(sk);
        meta.enable_equality(index);
        meta.enable_equality(bit);
        meta.enable_equality(instance);

        meta.create_gate("bool_check", |meta| {
            let s = meta.query_selector(s_bool);
            let b = meta.query_advice(bit, Rotation::cur());
            vec![s * b.clone() * (Expression::Constant(Fq::one()) - b)]
        });

        MembershipConfig {
            poseidon,
            leaf,
            siblings,
            sk,
            index,
            bit,
            s_bool,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let depth = self.path_siblings.len();
        let chip = PoseidonFqChip::new(config.poseidon.clone());

        let leaf_fq = Fq::from_repr(self.leaf).expect("leaf is canonical Fq");
        let sk_fq = Fq::from_repr(self.sk).expect("sk is canonical Fq");
        let index_fq = Fq::from(self.index);

        let sibling_fqs: Vec<Fq> = self
            .path_siblings
            .iter()
            .map(|s| Fq::from_repr(*s).expect("sibling is canonical Fq"))
            .collect();

        // Witness assignments (cells for copy-constraining)
        let leaf_cell: Cell;
        let sibling_cells: Vec<Cell>;
        let sk_cell: Cell;
        let index_cell: Cell;

        // We wire up witness cells in one region
        let witness_result = layouter.assign_region(
            || "witnesses",
            |mut region| {
                let mut offset = 0;

                let lc = region.assign_advice(
                    || "leaf", config.leaf, offset,
                    || Value::known(leaf_fq),
                )?;

                let mut sc = Vec::new();
                for i in 0..depth {
                    offset += 1;
                    let c = region.assign_advice(
                        || format!("sibling_{}", i),
                        config.siblings, offset,
                        || Value::known(sibling_fqs[i]),
                    )?;
                    sc.push(c);
                }

                offset += 1;
                for (i, &b) in self.position_bits.iter().enumerate() {
                    config.s_bool.enable(&mut region, offset)?;
                    let bit_val = if b { Fq::one() } else { Fq::ZERO };
                    region.assign_advice(
                        || format!("bit_{}", i),
                        config.bit, offset,
                        || Value::known(bit_val),
                    )?;
                    offset += 1;
                }

                offset += 1;
                let skc = region.assign_advice(
                    || "sk", config.sk, offset,
                    || Value::known(sk_fq),
                )?;
                offset += 1;
                let ic = region.assign_advice(
                    || "index", config.index, offset,
                    || Value::known(index_fq),
                )?;

                Ok((lc.cell(), sc.iter().map(|a| a.cell()).collect::<Vec<_>>(), skc.cell(), ic.cell()))
            },
        )?;

        leaf_cell = witness_result.0;
        sibling_cells = witness_result.1;
        sk_cell = witness_result.2;
        index_cell = witness_result.3;

        // ── Merkle path verification ──────────────────────────────────────
        let mut current_val = leaf_fq;
        let mut current_cell = leaf_cell;

        for i in 0..depth {
            let sibling_val = sibling_fqs[i];

            let (first_val, second_val, first_cell, second_cell, next_val) = if !self.position_bits[i] {
                let next = chip.native_hash(current_val, sibling_val);
                (Value::known(current_val), Value::known(sibling_val), Some(current_cell), Some(sibling_cells[i]), next)
            } else {
                let next = chip.native_hash(sibling_val, current_val);
                (Value::known(sibling_val), Value::known(current_val), Some(sibling_cells[i]), Some(current_cell), next)
            };

            let hash_cell = chip.assign_hash(
                layouter.namespace(|| format!("merkle_level_{}", i)),
                first_val,
                second_val,
                first_cell,
                second_cell,
            )?;

            current_val = next_val;
            current_cell = hash_cell.cell();
        }

        // Constrain computed root to instance[0]

        layouter.assign_region(|| "constrain_root", |mut region| {
            let instance_cell = region.assign_advice_from_instance(
                || "root_instance", config.instance, 0, config.poseidon.state[0], 0,
            )?;
            region.constrain_equal(current_cell, instance_cell.cell())?;
            Ok(())
        })?;

        // ── Nullifier derivation ──────────────────────────────────────────
        let nullifier_cell = chip.assign_hash(
            layouter.namespace(|| "nullifier"),
            Value::known(sk_fq),
            Value::known(index_fq),
            Some(sk_cell),
            Some(index_cell),
        )?;

        layouter.assign_region(|| "constrain_nullifier", |mut region| {
            let instance_cell = region.assign_advice_from_instance(
                || "nf_instance", config.instance, 1, config.poseidon.state[0], 1,
            )?;
            region.constrain_equal(nullifier_cell.cell(), instance_cell.cell())?;
            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree::IncrementalMerkleTree;
    use crate::poseidon_fq;
    use halo2_proofs::dev::MockProver;

    fn make_leaf(val: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&val.to_le_bytes());
        b
    }

    fn run_membership_test(depth: usize, leaf_index: usize, expect_valid: bool) {
        // Build a tree with 2^depth leaves (power-of-two for clean paths)
        let n_leaves = 1 << depth;
        let leaves: Vec<[u8; 32]> = (0..n_leaves).map(|i| make_leaf(i as u64)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }

        let path = tree.path(leaf_index).unwrap();
        let merkle_root = *tree.root();

        let sk = make_leaf(0xCAFE);
        let index = leaf_index as u64;
        let nullifier = poseidon_fq::poseidon_nullifier(&sk, index);

        let circuit = MembershipCircuit {
            leaf: leaves[leaf_index],
            path_siblings: path.siblings.clone(),
            position_bits: path.position_bits.clone(),
            sk,
            index,
            merkle_root: if expect_valid { merkle_root } else { make_leaf(0xFF) },
            nullifier,
        };

        let instances = vec![vec![
            Fq::from_repr(if expect_valid { merkle_root } else { make_leaf(0xFF) }).unwrap(),
            Fq::from_repr(nullifier).unwrap(),
        ]];

        let prover = MockProver::run(MEMBERSHIP_K, &circuit, instances).unwrap();
        if expect_valid {
            assert_eq!(prover.verify(), Ok(()));
        } else {
            assert!(prover.verify().is_err(), "should be rejected");
        }
    }

    /// Sanity: path length must match depth
    #[test]
    fn test_path_has_correct_length() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| make_leaf(i)).collect();
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let path = tree.path(3).unwrap();
        // For 8 leaves, depth = 3 (not 4), path has 3 siblings
        assert_eq!(path.siblings.len(), 3);
    }

    #[test]
    fn test_membership_depth_3_leaf_0() {
        run_membership_test(3, 0, true);
    }

    #[test]
    fn test_membership_depth_3_leaf_3() {
        run_membership_test(3, 3, true);
    }

    #[test]
    fn test_membership_depth_3_leaf_7() {
        run_membership_test(3, 7, true);
    }

    #[test]
    fn test_membership_depth_4_leaf_5() {
        run_membership_test(4, 5, true);
    }

    #[test]
    fn test_membership_rejects_wrong_root() {
        run_membership_test(3, 2, false);
    }
}
