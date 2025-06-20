use crate::merkle_tree::ct_merkle_vendored::{InternalIdx, LeafIdx};

/// Given a tree size and number of additions, produces a list of tree node indices whose values in
/// the new tree (i.e., including the additions) are needed to build the consistency proof.
///
/// # Panics
/// Panics if `num_oldtree_leaves == 0` or `num_oldtree_leaves + num_additions > ⌊u64::MAX / 2⌋ + 1`.
pub fn indices_for_consistency_proof(num_oldtree_leaves: u64, num_additions: u64) -> Vec<u64> {
    if num_oldtree_leaves == 0 {
        panic!("cannot produce a consistency proof starting from an empty tree");
    }
    if num_oldtree_leaves
        .checked_add(num_additions)
        .is_some_and(|s| s > u64::MAX / 2 + 1)
    {
        panic!("too many leaves")
    }

    let num_newtree_leaves = num_oldtree_leaves + num_additions;

    if num_oldtree_leaves == num_newtree_leaves {
        return Vec::new();
    }

    subproof(num_oldtree_leaves, num_newtree_leaves, true)
}

/// RFC 6962 SUBPROOF algorithm
pub(crate) fn subproof(m: u64, n: u64, b: bool) -> Vec<u64> {
    subproof_with_offset(m, n, b, 0)
}

/// RFC 6962 SUBPROOF algorithm with offset tracking to handle slices correctly
fn subproof_with_offset(m: u64, n: u64, b: bool, offset: u64) -> Vec<u64> {
    if m == n {
        return if b {
            vec![]
        } else {
            vec![compute_subtree_root(offset, offset + m).as_u64()]
        };
    }

    let k = largest_power_of_two_less_than(n);

    if m <= k {
        // SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        let mut result = subproof_with_offset(m, k, b, offset);
        let subtree_root = compute_subtree_root(offset + k, offset + n);
        result.push(subtree_root.as_u64());
        result
    } else {
        // SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
        let mut result = subproof_with_offset(m - k, n - k, false, offset + k);
        let subtree_root = compute_subtree_root(offset, offset + k);
        result.push(subtree_root.as_u64());
        result
    }
}

/// Compute the root of a subtree containing leaves [start, end)
pub fn compute_subtree_root(start: u64, end: u64) -> InternalIdx {
    let size = end - start;

    if size == 1 {
        return LeafIdx::new(start).into();
    }

    let k = largest_power_of_two_less_than(size);

    let left_root = compute_subtree_root(start, start + k);
    let right_root = compute_subtree_root(start + k, end);

    debug_assert_eq!(
        left_root.sibling(end),
        right_root,
        "Left and right roots should be siblings"
    );

    left_root.parent(end)
}

pub(crate) fn largest_power_of_two_less_than(n: u64) -> u64 {
    if n <= 1 {
        panic!("No power of two less than {}", n);
    }

    let mut power = 1u64;
    while power * 2 < n {
        power *= 2;
    }
    power
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree::ct_merkle_vendored::LeafIdx;

    // Utility function tests
    #[test]
    fn test_largest_power_of_two_less_than() {
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(7), 4);
        assert_eq!(largest_power_of_two_less_than(8), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
    }

    #[test]
    #[should_panic(expected = "No power of two less than 1")]
    fn test_largest_power_of_two_less_than_one() {
        largest_power_of_two_less_than(1);
    }

    #[test]
    #[should_panic(expected = "No power of two less than 0")]
    fn test_largest_power_of_two_less_than_zero() {
        largest_power_of_two_less_than(0);
    }

    // Error case tests
    #[test]
    #[should_panic(expected = "cannot produce a consistency proof starting from an empty tree")]
    fn test_indices_for_consistency_proof_empty_tree() {
        indices_for_consistency_proof(0, 5);
    }

    #[test]
    fn test_rfc6962_subproof_examples() {
        // Test the SUBPROOF algorithm with examples from RFC 6962

        // SUBPROOF(m, D[m], true) = {}
        let result = subproof(3, 3, true);
        assert!(result.is_empty(), "SUBPROOF(3, D[3], true) should be empty");

        // SUBPROOF(m, D[m], false) = {MTH(D[m])}
        let result = subproof(3, 3, false);
        assert_eq!(
            result.len(),
            1,
            "SUBPROOF(3, D[3], false) should have one element"
        );
        assert_eq!(result[0], compute_subtree_root(0, 3).as_u64());

        // RFC 6962 example: PROOF(3, D[7]) = [c, d, g, l]
        let indices = indices_for_consistency_proof(3, 4); // 3 -> 7
        assert_eq!(indices.len(), 4, "PROOF(3, D[7]) should have 4 nodes");

        // PROOF(4, D[8]) - power of 2 case
        let indices = indices_for_consistency_proof(4, 4); // 4 -> 8
        assert_eq!(indices.len(), 1, "PROOF(4, D[8]) should have 1 node");

        // PROOF(1, D[2]) - single leaf extension
        let indices = indices_for_consistency_proof(1, 1); // 1 -> 2
        assert_eq!(indices.len(), 1, "PROOF(1, D[2]) should have 1 node");
    }

    #[test]
    fn test_rfc6962_consistency_proof_bounds() {
        // RFC 6962 section 2.1.2: proof size bounded by ceil(log2(n)) + 1

        struct BoundTest {
            old_size: u64,
            new_size: u64,
        }

        let test_cases = vec![
            BoundTest {
                old_size: 1,
                new_size: 2,
            },
            BoundTest {
                old_size: 1,
                new_size: 8,
            },
            BoundTest {
                old_size: 3,
                new_size: 7,
            },
            BoundTest {
                old_size: 4,
                new_size: 8,
            },
            BoundTest {
                old_size: 6,
                new_size: 10,
            },
            BoundTest {
                old_size: 10,
                new_size: 20,
            },
            BoundTest {
                old_size: 100,
                new_size: 200,
            },
        ];

        for tc in test_cases {
            let indices = indices_for_consistency_proof(tc.old_size, tc.new_size - tc.old_size);
            let max_proof_size = ((tc.new_size as f64).log2().ceil() as usize) + 1;

            assert!(
                indices.len() <= max_proof_size,
                "Consistency proof from {} to {} has {} nodes, exceeds bound of {}",
                tc.old_size,
                tc.new_size,
                indices.len(),
                max_proof_size
            );
        }
    }

    #[test]
    fn test_subproof_recursive_cases() {
        // Test the recursive cases of SUBPROOF

        // m <= k: SUBPROOF(2, D[4], true) where k=2
        let result = subproof(2, 4, true);
        assert!(
            !result.is_empty(),
            "SUBPROOF(2, D[4], true) should not be empty"
        );
        let last = result.last().unwrap();
        assert_eq!(*last, compute_subtree_root(2, 4).as_u64());

        // m > k: SUBPROOF(3, D[4], true) where k=2
        let result = subproof(3, 4, true);
        assert!(
            !result.is_empty(),
            "SUBPROOF(3, D[4], true) should not be empty"
        );
        let last = result.last().unwrap();
        assert_eq!(*last, compute_subtree_root(0, 2).as_u64());
    }

    #[test]
    fn test_compute_subtree_root_rfc_compliance() {
        // Single leaf subtrees
        let root = compute_subtree_root(0, 1);
        assert_eq!(root, LeafIdx::new(0).into());

        let root = compute_subtree_root(5, 6);
        assert_eq!(root, LeafIdx::new(5).into());

        // Power-of-2 sized subtrees
        let root_0_2 = compute_subtree_root(0, 2);
        let root_2_4 = compute_subtree_root(2, 4);
        assert_eq!(root_0_2.sibling(4), root_2_4);

        // Non-power-of-2 sized subtrees
        let root_0_3 = compute_subtree_root(0, 3);
        let left_child = compute_subtree_root(0, 2);
        assert_eq!(left_child.parent(3), root_0_3);
    }

    #[test]
    fn test_rfc6962_example_tree_consistency() {
        // RFC 6962 Section 2.1.3 example tree with 7 leaves
        // The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c, d, g, l]

        let indices = indices_for_consistency_proof(3, 4); // 3 -> 7
        assert_eq!(
            indices.len(),
            4,
            "PROOF(3, D[7]) should have exactly 4 nodes"
        );

        let g = compute_subtree_root(0, 2); // Root of [d0, d1]
        let l = compute_subtree_root(4, 7); // Root of [d4, d5, d6]

        let c_idx: InternalIdx = LeafIdx::new(2).into();
        let d_idx: InternalIdx = LeafIdx::new(3).into();
        assert!(indices.contains(&c_idx.as_u64())); // c (d2)
        assert!(indices.contains(&d_idx.as_u64())); // d (d3)
        assert!(indices.contains(&g.as_u64())); // g
        assert!(indices.contains(&l.as_u64())); // l
    }

    #[test]
    fn test_rfc6962_proof_verification_algorithm() {
        // Consistency from size 1 to size 4
        let indices = indices_for_consistency_proof(1, 3);

        // Need d1 and root of [d2, d3] to verify consistency
        let d1_idx: InternalIdx = LeafIdx::new(1).into();
        assert!(indices.contains(&d1_idx.as_u64()));
        assert!(indices.contains(&compute_subtree_root(2, 4).as_u64()));
    }
}
