use crate::poseidon_fq;

#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>,
    pub position_bits: Vec<bool>,
}

/// Append-only binary Merkle tree using Poseidon hash over Fq.
/// Maintains a frontier of `Option<[u8; 32]>` one per level.
/// Frontier[l] = the sibling-left-open node at level l (the left child
/// waiting for a right sibling to complete a 2^(l+1) subtree).
///
/// On each append:
///   1. current = leaf, count = number of leaves BEFORE this one.
///   2. For level = 0, 1, ... while count has bits:
///      - if count & 1 == 1: hash(frontier[level], current) → current,
///        clear frontier[level], count >>= 1.
///      - else: store current at frontier[level], break.
///   3. root = combine all non-None frontier entries from high to low.
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree {
    leaves: Vec<[u8; 32]>,
    frontier: Vec<Option<[u8; 32]>>,
    root: [u8; 32],
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: vec![],
            frontier: vec![],
            root: [0u8; 32],
        }
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut current = leaf;
        let mut count = self.leaves.len();

        for level in 0.. {
            if count & 1 == 1 {
                let left = self.frontier[level]
                    .expect("frontier must have left sibling at set bit");
                current = poseidon_fq::poseidon_hash(&left, &current);
                self.frontier[level] = None;
                count >>= 1;
            } else {
                if level >= self.frontier.len() {
                    self.frontier.push(None);
                }
                self.frontier[level] = Some(current);
                break;
            }
        }

        self.leaves.push(leaf);
        self.root = self.compute_root();
    }

    /// Recompute root by merging frontier entries bottom-up (level 0 upward).
    /// At each level, the frontier entry is a left sibling — hash it with the
    /// accumulated right side.
    fn compute_root(&self) -> [u8; 32] {
        let mut root: Option<[u8; 32]> = None;
        for level in 0..self.frontier.len() {
            if let Some(node) = self.frontier[level] {
                root = Some(match root {
                    None => node,
                    Some(r) => poseidon_fq::poseidon_hash(&node, &r),
                });
            }
        }
        root.unwrap_or([0u8; 32])
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Generate the Merkle path for leaf at `index`.
    /// Walks up the tree, collecting siblings at each level.
    /// Stops when we've reached the highest level where the leaf's
    /// parent-subtree has a valid sibling (non-empty leaf range).
    pub fn path(&self, index: usize) -> Option<MerklePath> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut position_bits = Vec::new();

        // Tree capacity = smallest power of two ≥ leaf count.
        let capacity = self.leaves.len().next_power_of_two();

        for level in 0.. {
            if (1 << level) >= capacity {
                break;
            }

            let is_right = (index >> level) & 1 == 1;
            let sibling_pos = if is_right { (index >> level) - 1 } else { (index >> level) + 1 };
            let subtree_size = 1 << level;
            let sibling_leaf_start = sibling_pos * subtree_size;

            // Skip levels where the sibling doesn't exist yet (incomplete tree).
            if sibling_leaf_start >= self.leaves.len() {
                continue;
            }

            position_bits.push(is_right);
            let sibling = self.compute_node_at(level, sibling_pos);
            siblings.push(sibling);
        }

        Some(MerklePath { siblings, position_bits })
    }

    /// Compute the node at (level, position) by simulating incremental
    /// Merkle tree folding over the leaf range.  Guaranteed consistent
    /// with `compute_root` because both use the same accumulation logic.
    /// Uses a fixed-size stack array (max 16 levels) to avoid heap allocation.
    fn compute_node_at(&self, level: usize, pos: usize) -> [u8; 32] {
        let leaf_start = pos << level;
        let leaf_end = ((pos + 1) << level).min(self.leaves.len());

        if leaf_start >= leaf_end {
            return [0u8; 32];
        }

        let mut frontier = [None; 16];
        for i in leaf_start..leaf_end {
            let mut cur = self.leaves[i];
            let mut k = 0;
            while k < level {
                match frontier[k] {
                    None => {
                        frontier[k] = Some(cur);
                        break;
                    }
                    Some(left) => {
                        frontier[k] = None;
                        cur = poseidon_fq::poseidon_hash(&left, &cur);
                        k += 1;
                    }
                }
            }
            if k == level {
                return cur;
            }
        }

        let mut root: Option<[u8; 32]> = None;
        for k in 0..level {
            if let Some(node) = frontier[k] {
                root = Some(match root {
                    None => node,
                    Some(r) => poseidon_fq::poseidon_hash(&node, &r),
                });
            }
        }
        root.unwrap_or(self.leaves[leaf_start])
    }

    /// Verify a Merkle path against a root.
    pub fn verify_path(root: &[u8; 32], leaf: &[u8; 32], path: &MerklePath) -> bool {
        let mut current = *leaf;
        for (i, sibling) in path.siblings.iter().enumerate() {
            let is_right = i < path.position_bits.len() && path.position_bits[i];
            current = if is_right {
                poseidon_fq::poseidon_hash(sibling, &current)
            } else {
                poseidon_fq::poseidon_hash(&current, sibling)
            };
        }
        current == *root
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(val: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        bytes
    }

    #[test]
    fn test_append_and_root() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.leaf_count(), 0);
        tree.append(leaf(1));
        assert_ne!(*tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = IncrementalMerkleTree::new();
        tree.append(leaf(0));
        tree.append(leaf(1));
        let l0 = leaf(0);
        let l1 = leaf(1);
        let expected_root = poseidon_fq::poseidon_hash(&l0, &l1);
        assert_eq!(*tree.root(), expected_root);
        let path = tree.path(0).unwrap();
        assert_eq!(path.siblings.len(), 1);
        assert!(IncrementalMerkleTree::verify_path(tree.root(), &l0, &path));
        let path1 = tree.path(1).unwrap();
        assert!(IncrementalMerkleTree::verify_path(tree.root(), &l1, &path1));
    }

    #[test]
    fn test_three_leaves() {
        let mut tree = IncrementalMerkleTree::new();
        tree.append(leaf(0));
        tree.append(leaf(1));
        tree.append(leaf(2));
        let l0 = leaf(0);
        let l1 = leaf(1);
        let l2 = leaf(2);
        let h01 = poseidon_fq::poseidon_hash(&l0, &l1);
        let expected_root = poseidon_fq::poseidon_hash(&h01, &l2);
        assert_eq!(*tree.root(), expected_root);
        // Leaf 0 path: siblings = [l1, l2]
        let path0 = tree.path(0).unwrap();
        assert!(IncrementalMerkleTree::verify_path(tree.root(), &l0, &path0));
        // Leaf 1 path: siblings = [l0, l2]
        let path1 = tree.path(1).unwrap();
        assert!(IncrementalMerkleTree::verify_path(tree.root(), &l1, &path1));
        // Leaf 2 path: siblings = [h01]
        let path2 = tree.path(2).unwrap();
        assert!(IncrementalMerkleTree::verify_path(tree.root(), &l2, &path2));
    }

    #[test]
    fn test_power_of_two() {
        for count in [1usize, 2, 4, 8, 16, 32] {
            let mut tree = IncrementalMerkleTree::new();
            for i in 0..count {
                tree.append(leaf(i as u64));
            }
            for i in 0..count {
                let path = tree.path(i).expect("path should exist");
                assert!(
                    IncrementalMerkleTree::verify_path(tree.root(), &leaf(i as u64), &path),
                    "failed for leaf {} in {}-leaf tree", i, count
                );
            }
        }
    }

    #[test]
    fn test_non_power_of_two() {
        for count in [3usize, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 17] {
            let mut tree = IncrementalMerkleTree::new();
            for i in 0..count {
                tree.append(leaf(i as u64));
            }
            for i in 0..count {
                let path = tree.path(i).expect("path should exist");
                assert!(
                    IncrementalMerkleTree::verify_path(tree.root(), &leaf(i as u64), &path),
                    "failed for leaf {} in {}-leaf tree", i, count
                );
            }
        }
    }

    #[test]
    fn test_wrong_leaf_rejected() {
        let mut tree = IncrementalMerkleTree::new();
        tree.append(leaf(1));
        tree.append(leaf(2));
        let path = tree.path(0).unwrap();
        assert!(!IncrementalMerkleTree::verify_path(tree.root(), &leaf(0xFF), &path));
    }

    #[test]
    fn test_path_out_of_range() {
        let tree = IncrementalMerkleTree::new();
        assert!(tree.path(0).is_none());
    }

    #[test]
    fn test_incremental_consistency() {
        let mut tree = IncrementalMerkleTree::new();
        let mut roots = Vec::new();
        for i in 0..50u64 {
            tree.append(leaf(i));
            roots.push(*tree.root());
        }
        for n in 0..50usize {
            let mut full_tree = IncrementalMerkleTree::new();
            for i in 0..=n as u64 {
                full_tree.append(leaf(i));
            }
            assert_eq!(*full_tree.root(), roots[n], "Root mismatch at leaf {}", n);
        }
    }
}
