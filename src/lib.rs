/*

Building a simple Merkle Tree

Exercise 1:
    Given a set of data D, construct a Merkle Tree.

Assume that D is a power of 2 (the binary tree is perfect).

Example input:
    D = [A1, A2, A3, A4]

Example output:

                               Root
                           ┌──────────┐
                           │    H7    │
                           │ H(H5|H6) │
                  ┌────────┴──────────┴──────────┐
                  │                              │
                  │                              │
             ┌────┴─────┐                  ┌─────┴────┐
             │    H5    │                  │    H6    │
             │ H(H1|H2) │                  │ H(H3|H4) │
             └─┬─────┬──┘                  └─┬──────┬─┘
               │     │                       │      │
     ┌─────────┴┐   ┌┴─────────┐    ┌────────┴─┐  ┌─┴────────┐
     │   H1     │   │    H2    │    │    H3    │  │    H4    │
     │  H(A1)   │   │   H(A2)  │    │   H(A3)  │  │   H(A4)  │
     └───┬──────┘   └────┬─────┘    └────┬─────┘  └────┬─────┘
         │               │               │             │
         A1              A2              A3            A4


Exercise 1b:
    Write a function that will verify a given set of data with a given root hash.

Exercise 2:
    Write a function that will use a proof like the one in Exercise 3 to verify that the proof is indeed correct.

Exercise 3 (Hard):
    Write a function that returns a proof that a given data is in the tree.

    Hints:
        -   The proof should be a set of ordered data hashes and their positions (left 0 or right 1).
        -   Let's say we are asked to prove that H3 (A3) is in this tree. We have the entire tree so we can traverse it and find H3.
            Then we only need to return the hashes that can be used to calculate with the hash of the given data to calculate the root hash.
            i.e Given a data H3, a proof [(1, H4), (0, H5)] and a root:
                H3|H4 => H6 => H5|H6 => H7 = root

*/

use sha2::Digest;


pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

pub struct MerkleTree {
    data: Option<Data>,
    hash: Hash,
    left: Option<Box<MerkleTree>>,
    right: Option<Box<MerkleTree>>,
}

/// Which side to put Hash on when concatenating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

pub type HashStorage<'a> = Vec<(HashDirection, &'a Hash)>;

#[derive(Debug, Default, PartialEq)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatenating
    hashes: HashStorage<'a>,
}

impl MerkleTree {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.hash.clone()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        debug_assert!(input.len() > 0);
        if input.len() == 0 { // In case there is no constraint for data to be present
            MerkleTree {
                data: None,
                hash: Hash::new(),
                left: None,
                right: None,
            }
        } else if input.len() > 1 {
            let lhs = MerkleTree::construct(&input[..(input.len() + 1) / 2]);
            let rhs = MerkleTree::construct(&input[(input.len() + 1) / 2..]);
            MerkleTree {
                data: None,
                hash: hash_concat(&lhs.hash, &rhs.hash),
                left: Some(Box::new(lhs)),
                right: Some(Box::new(rhs)),
            }
        } else {
            MerkleTree {
                data: Some(input[0].clone()),
                hash: hash_data(&input[0]),
                left: None,
                right: None,
            }
        }
    }

    // Evaluates root hash only, without storing any data
    fn evaluate_root_hash(input: &[Data]) -> Hash {
        debug_assert!(input.len() > 0);
        if input.len() == 0 { // In case there is no constraint for data to be present
            Hash::new()
        } else if input.len() > 1 {
            let lhs = MerkleTree::evaluate_root_hash(&input[..(input.len() + 1) / 2]);
            let rhs = MerkleTree::evaluate_root_hash(&input[(input.len() + 1) / 2..]);
            hash_concat(&lhs, &rhs)
        } else {
            hash_data(&input[0])
        }
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        // Can be just `&MerkleTree::construct(input).hash == root_hash`, though will consume more memory
        &MerkleTree::evaluate_root_hash(input) == root_hash
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut buffer_hash = hash_data(data);
        for (direction, hash) in &proof.hashes {
            buffer_hash = match direction {
                HashDirection::Left => hash_concat(hash, &buffer_hash),
                HashDirection::Right => hash_concat(&buffer_hash, hash)
            };
        }
        &buffer_hash == root_hash
    }

    fn _prove(&self, data: &Data) -> Option<HashStorage> {
        // here we need to find a correct child node and return its sibling hash,
        // and then push to the existing Proof vector
        if self.left.as_ref()?.data.as_ref() == Some(data) {
            return Some(Vec::from([(HashDirection::Right, &self.right.as_ref()?.hash)]));
        } else if self.right.as_ref()?.data.as_ref() == Some(data) {
            return Some(Vec::from([(HashDirection::Left, &self.left.as_ref()?.hash)]));
        } else if let Some(mut hashes) = self.left.as_ref()?._prove(data) {
            hashes.push((HashDirection::Right, &self.right.as_ref()?.hash));
            return Some(hashes);
        } else if let Some(mut hashes) = self.right.as_ref()?._prove(data) {
            hashes.push((HashDirection::Left, &self.left.as_ref()?.hash));
            return Some(hashes);
        };

        None
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        Some(Proof { hashes: self._prove(data)? })
    }
}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify() {
        let data = example_data(4);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert!(MerkleTree::verify(&data, &hex::decode(expected_root).unwrap()));

        let data = example_data(3);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert!(MerkleTree::verify(&data, &hex::decode(expected_root).unwrap()));

        let data = example_data(8);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert!(MerkleTree::verify(&data, &hex::decode(expected_root).unwrap()));
    }

    #[test]
    fn test_proof() {
        // Data generated via simple python script (see generate_mtree_proof.py file)
        let data = example_data(4);
        let mal_data = example_data(5);
        let tree = MerkleTree::construct(&data);
        assert_eq!(tree.prove(&mal_data[4]), None);

        assert_eq!(tree.prove(&data[0]), Some(Proof{
            hashes: vec![(HashDirection::Right,
                      &hex::decode("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap()),
                      (HashDirection::Right,
                      &hex::decode("c2768b34413548c2a4cca10af5c71d399d9e70975a8fd428c1dc27cc0282f273").unwrap())]
        }));
        assert_eq!(tree.prove(&data[1]), Some(Proof{
            hashes: vec![(HashDirection::Left,
                          &hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").unwrap()),
                         (HashDirection::Right,
                          &hex::decode("c2768b34413548c2a4cca10af5c71d399d9e70975a8fd428c1dc27cc0282f273").unwrap())]
        }));

        assert_eq!(tree.prove(&data[2]), Some(Proof{
            hashes: vec![(HashDirection::Right,
                          &hex::decode("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5").unwrap()),
                         (HashDirection::Left,
                          &hex::decode("30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab").unwrap())]
        }));
        assert_eq!(tree.prove(&data[3]), Some(Proof{
            hashes: vec![(HashDirection::Left,
                          &hex::decode("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986").unwrap()),
                         (HashDirection::Left,
                          &hex::decode("30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab").unwrap())]
        }));


        let data = example_data(3);
        let mal_data = example_data(4);
        let tree = MerkleTree::construct(&data);
        assert!(tree.prove(&mal_data[3]).is_none());

        assert_eq!(tree.prove(&data[0]), Some(Proof{
            hashes: vec![(HashDirection::Right,
                          &hex::decode("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap()),
                         (HashDirection::Right,
                          &hex::decode("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986").unwrap())]
        }));
        assert_eq!(tree.prove(&data[1]), Some(Proof{
            hashes: vec![(HashDirection::Left,
                          &hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").unwrap()),
                         (HashDirection::Right,
                          &hex::decode("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986").unwrap())]
        }));

        assert_eq!(tree.prove(&data[2]), Some(Proof{
            hashes: vec![(HashDirection::Left,
                          &hex::decode("30e1867424e66e8b6d159246db94e3486778136f7e386ff5f001859d6b8484ab").unwrap())]
        }));
    }


    #[test]
    fn test_verify_proof() {
        // Since MerkleTree::prove() and ::root() outputs are verified, we can safely use their
        // outputs for testing the ::verify_proof()
        let data = example_data(4);
        let mal_data = example_data(5);
        let tree = MerkleTree::construct(&data);
        assert!(MerkleTree::verify_proof(&data[0], &tree.prove(&data[0]).unwrap(), &tree.root()));
        assert!(MerkleTree::verify_proof(&data[1], &tree.prove(&data[1]).unwrap(), &tree.root()));
        assert!(MerkleTree::verify_proof(&data[2], &tree.prove(&data[2]).unwrap(), &tree.root()));
        assert!(MerkleTree::verify_proof(&data[3], &tree.prove(&data[3]).unwrap(), &tree.root()));
        assert!(!MerkleTree::verify_proof(&mal_data[4], &tree.prove(&data[3]).unwrap(), &tree.root()));

        let data = example_data(3);
        let mal_data = example_data(4);
        let tree = MerkleTree::construct(&data);
        assert!(MerkleTree::verify_proof(&data[0], &tree.prove(&data[0]).unwrap(), &tree.root()));
        assert!(MerkleTree::verify_proof(&data[1], &tree.prove(&data[1]).unwrap(), &tree.root()));
        assert!(MerkleTree::verify_proof(&data[2], &tree.prove(&data[2]).unwrap(), &tree.root()));
        assert!(!MerkleTree::verify_proof(&mal_data[3], &tree.prove(&data[2]).unwrap(), &tree.root()));
    }
}