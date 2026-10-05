//! A Merkle tree over one column's per-bin fingerprint commitments.
//!
//! The data owner commits every bin as its own column, but publishes only
//! the root of a tree whose leaf `b` is bin `b`'s commitment. A query opens
//! just the bins the prover chose: their commitments travel in the proof,
//! with one multiproof (the sibling hashes the opened leaves do not already
//! determine) that the verifier checks against the root. So the oracle stays
//! one hash per column however wide the rule, and a proof grows only with
//! the bins it tests.
//!
//! Leaves hash their bin index with the commitment bytes, and leaves and
//! inner nodes carry distinct domain tags, so an opening binds each
//! commitment to its bin.

use sha2::{Digest, Sha256};

/// A node of the tree.
pub type Hash = [u8; 32];

/// The hash of leaf `bin`, over the commitment's canonical bytes.
fn leaf_hash(bin: usize, commitment: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update((bin as u64).to_le_bytes());
    h.update(commitment);
    h.finalize().into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Levels of a tree over `num_leaves` leaves, padded to a power of two.
fn depth(num_leaves: usize) -> usize {
    num_leaves.next_power_of_two().trailing_zeros() as usize
}

/// Hash the known nodes up to the root, level by level. `known` holds the
/// opened leaves, sorted by index and distinct; `sibling(level, index)`
/// supplies each node the known ones do not determine, in the order a
/// multiproof lists them.
fn fold_to_root(
    levels: usize,
    mut known: Vec<(usize, Hash)>,
    mut sibling: impl FnMut(usize, usize) -> Option<Hash>,
) -> Option<Hash> {
    for level in 0..levels {
        let mut next = Vec::with_capacity(known.len());
        let mut i = 0;
        while i < known.len() {
            let (index, hash) = known[i];
            let (left, right) = if index % 2 == 0 {
                match known.get(i + 1) {
                    Some(&(j, right)) if j == index + 1 => {
                        i += 1;
                        (hash, right)
                    }
                    _ => (hash, sibling(level, index + 1)?),
                }
            } else {
                (sibling(level, index - 1)?, hash)
            };
            next.push((index / 2, node_hash(&left, &right)));
            i += 1;
        }
        known = next;
    }
    known.first().map(|&(_, root)| root)
}

/// The tree over one column's bin commitments.
pub struct BinTree {
    /// `levels[0]` are the leaves padded with zero hashes; the last level is
    /// the root.
    levels: Vec<Vec<Hash>>,
}

impl BinTree {
    /// The tree over `leaves`, bin `b`'s commitment bytes at position `b`.
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        assert!(!leaves.is_empty(), "a bin tree needs at least one leaf");
        let mut level: Vec<Hash> = leaves
            .iter()
            .enumerate()
            .map(|(bin, bytes)| leaf_hash(bin, bytes))
            .collect();
        level.resize(leaves.len().next_power_of_two(), [0u8; 32]);
        let mut levels = vec![level];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|pair| node_hash(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// The multiproof opening `bins` (sorted, distinct, in range).
    pub fn open(&self, bins: &[usize]) -> Vec<Hash> {
        let known = bins.iter().map(|&bin| (bin, self.levels[0][bin])).collect();
        let mut siblings = Vec::new();
        fold_to_root(self.levels.len() - 1, known, |level, index| {
            let hash = self.levels[level][index];
            siblings.push(hash);
            Some(hash)
        });
        siblings
    }
}

/// Check that `opened` (bin, commitment bytes) pairs are leaves of the tree
/// with `root` over `num_leaves` leaves, given the multiproof `siblings`.
/// The bins must be sorted, distinct and in range, and the multiproof must
/// be exactly as long as it needs.
pub fn verify(
    root: &Hash,
    num_leaves: usize,
    opened: &[(usize, &[u8])],
    siblings: &[Hash],
) -> bool {
    if opened.is_empty()
        || opened.windows(2).any(|w| w[0].0 >= w[1].0)
        || opened.last().is_some_and(|&(bin, _)| bin >= num_leaves)
    {
        return false;
    }
    let known = opened
        .iter()
        .map(|&(bin, bytes)| (bin, leaf_hash(bin, bytes)))
        .collect();
    let mut rest = siblings.iter();
    let folded = fold_to_root(depth(num_leaves), known, |_, _| rest.next().copied());
    folded.as_ref() == Some(root) && rest.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 3 + i % 5]).collect()
    }

    #[test]
    fn every_subset_opens_and_verifies() {
        for n in [1, 2, 3, 8, 13] {
            let data = leaves(n);
            let tree = BinTree::new(&data);
            for mask in 1u32..(1 << n.min(8)) {
                let bins: Vec<usize> = (0..n).filter(|b| mask >> b & 1 == 1).collect();
                let proof = tree.open(&bins);
                let opened: Vec<_> = bins.iter().map(|&b| (b, &data[b][..])).collect();
                assert!(
                    verify(&tree.root(), n, &opened, &proof),
                    "n={n} bins={bins:?}"
                );
            }
        }
    }

    #[test]
    fn a_multiproof_shares_siblings() {
        let tree = BinTree::new(&leaves(512));
        // Two adjacent leaves need one path's worth of siblings, not two.
        assert_eq!(tree.open(&[6]).len(), 9);
        assert_eq!(tree.open(&[6, 7]).len(), 8);
    }

    #[test]
    fn forgeries_are_rejected() {
        let data = leaves(16);
        let tree = BinTree::new(&data);
        let root = tree.root();
        let proof = tree.open(&[3, 9]);
        let ok = [(3, &data[3][..]), (9, &data[9][..])];
        assert!(verify(&root, 16, &ok, &proof));
        // Another commitment at an opened bin.
        assert!(!verify(
            &root,
            16,
            &[(3, &data[4][..]), (9, &data[9][..])],
            &proof
        ));
        // The right commitments claimed at other bins.
        assert!(!verify(
            &root,
            16,
            &[(4, &data[3][..]), (9, &data[9][..])],
            &proof
        ));
        // A truncated or padded multiproof.
        assert!(!verify(&root, 16, &ok, &proof[1..]));
        let mut longer = proof.clone();
        longer.push([7u8; 32]);
        assert!(!verify(&root, 16, &ok, &longer));
        // Unsorted, repeated, out-of-range or no bins.
        assert!(!verify(&root, 16, &[ok[1], ok[0]], &proof));
        assert!(!verify(&root, 16, &[ok[0], ok[0]], &proof));
        assert!(!verify(&root, 16, &[(16, &data[3][..])], &proof));
        assert!(!verify(&root, 16, &[], &proof));
    }
}
