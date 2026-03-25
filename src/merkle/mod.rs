use crate::core::credential::Credential;
use crate::encoding::{Hash, MerklePath};
use plonky2::{field::types::Field, hash::hash_types::RichField};
use thiserror::Error;
// Poseidon hash outputs 4 elments
// FIXME: add tags in hash
pub mod hash;

pub type Proof<const D: usize, F> = MerklePath<D, F, bool>;

pub type Root<F> = Hash<F>;

pub enum Leaf {
    Credential(Credential),
    Empty, // hashes to 0
}

// TODO: richer error messages
#[derive(Error, Debug)]
pub enum Error {
    #[error("Credential not in tree")]
    MissingCredential,
    #[error("Credential already in tree")]
    DuplicateCredential,
    #[error("Tree is full")]
    CapacityExceeded,
}

pub type Result<T> = std::result::Result<T, Error>;

// D = log₂(nb leaves) = nb levels - 1
pub struct Tree<const D: usize, F: Field> {
    leaves: Vec<Leaf>,
    // contains D + 1 vectors, stored from leaves to root
    nodes: Vec<Vec<Hash<F>>>,
}

impl Leaf {
    fn hash<F: RichField>(&self) -> Hash<F> {
        match self {
            Self::Empty => hash::empty(),
            Self::Credential(credential) => hash::credential(credential),
        }
    }
    // FIXME: right now, in credential, equality of credential is equivalent to
    // equality of the public keys. The consistency has to be checked everywhere,
    // and we might want to use the private key to search /  prove in the tree
    // instead of the whole credential
    fn equals(&self, credential: &Credential) -> bool {
        match self {
            Leaf::Empty => false,
            Leaf::Credential(leaf) => leaf == credential,
        }
    }
}

impl<const D: usize, F: RichField> Tree<D, F> {
    /// Assumes there is no duplicate.
    /// No duplicate should be ensured in the Tree to maintain consistency
    /// among functions
    fn from_no_duplicate(mut leaves: Vec<Leaf>) -> Self {
        let k = leaves.len();
        let n = 2_i32.pow(D as u32) as usize;
        assert!(k <= n);
        for _ in k..(n - k) {
            leaves.push(Leaf::Empty)
        }
        leaves.resize_with(n, || Leaf::Empty);
        let mut nodes = Vec::with_capacity(D + 1);
        let leaves_hash: Vec<Hash<F>> = leaves.iter().map(|l| l.hash()).collect();
        nodes.push(leaves_hash);
        for i in 0..D {
            nodes.push(hash::hash_vec(&nodes[i]))
        }
        Self { leaves, nodes }
    }

    pub fn empty() -> Self {
        Self::from_no_duplicate(Vec::new())
    }

    /// TODO: This is O(n²) to check credentials has no duplicates.
    /// This can be improved if Hash or Ord is implemented for Credential
    pub fn from(credentials: &[Credential]) -> Result<Self> {
        let mut leaves = Vec::with_capacity(credentials.len());
        for (i, credential) in credentials.iter().enumerate() {
            if credentials[..i].contains(credential) {
                return Err(Error::DuplicateCredential);
            } else {
                leaves.push(Leaf::Credential(credential.clone()));
            }
        }
        Ok(Self::from_no_duplicate(leaves))
    }

    pub fn root(&self) -> Root<F> {
        self.nodes[D][0]
    }

    /// It’s assumed each credential is unique
    pub fn find(&self, credential: &Credential) -> Option<usize> {
        self.leaves.iter().position(|c| c.equals(credential))
    }

    /// Look for a hash in direct leaves hashes
    pub fn find_hash(&self, credential_hash: &Hash<F>) -> Option<usize> {
        self.nodes[0].iter().position(|h| h == credential_hash)
    }

    fn path_from_position(&self, mut i: usize) -> MerklePath<D, F, bool> {
        let mut depth = 0;
        let mut path = [hash::empty(); D];
        let mut positions = [false; D];
        while depth < D {
            let is_left = i.is_multiple_of(2);
            let neighbor = if is_left { i + 1 } else { i - 1 };
            path[depth] = self.nodes[depth][neighbor];
            positions[depth] = is_left;
            depth += 1;
            i /= 2;
        }
        MerklePath { path, positions }
    }

    // TODO: update in batch can be optimized
    fn update_leaf(&mut self, mut i: usize, leaf: Leaf) {
        let mut h = leaf.hash();
        self.leaves[i] = leaf;
        let mut depth = 0;
        self.nodes[depth][i] = h;
        while depth < D {
            let is_left = i.is_multiple_of(2);
            let neighbor = if is_left { i + 1 } else { i - 1 };
            let n = self.nodes[depth][neighbor];
            h = hash::merge_left_right(&h, is_left, &n);
            depth += 1;
            i /= 2;
            self.nodes[depth][i] = h
        }
    }

    /// Does nothing & returns None if the maximal capacity is reached
    /// Ensures no duplicates
    pub fn add(&mut self, credential: &Credential) -> Result<()> {
        let mut first_empty = None;
        for (i, leaf) in self.leaves.iter().enumerate() {
            match leaf {
                Leaf::Empty if first_empty.is_none() => first_empty = Some(i),
                Leaf::Credential(c) if c == credential => return Err(Error::DuplicateCredential),
                _ => continue,
            }
        }
        match first_empty {
            None => Err(Error::CapacityExceeded),
            Some(i) => Ok(self.update_leaf(i, Leaf::Credential(credential.clone()))),
        }
    }
    pub fn revoke(&mut self, credential: &Credential) -> Result<()> {
        match self.find(credential) {
            None => Err(Error::MissingCredential),
            Some(i) => Ok(self.update_leaf(i, Leaf::Empty)),
        }
    }

    pub fn prove(&self, credential_hash: &Hash<F>) -> Result<Proof<D, F>> {
        let position = self.find_hash(credential_hash);
        match position {
            None => Err(Error::MissingCredential),
            Some(index) => Ok(self.path_from_position(index)),
        }
    }

    pub fn prove_credential(&self, credential: &Credential) -> Result<Proof<D, F>> {
        let position = self.find(credential);
        match position {
            None => Err(Error::MissingCredential),
            Some(index) => Ok(self.path_from_position(index)),
        }
    }

    pub fn verify(root: Root<F>, credential: &Credential, proof: Proof<D, F>) -> bool {
        let MerklePath { positions, path } = proof;
        let credential_hash = hash::credential(credential);
        let claimed_root = positions
            .iter()
            .zip(path.iter())
            .fold(credential_hash, |acc, (is_left, neighbor)| {
                hash::merge_left_right(&acc, *is_left, neighbor)
            });
        claimed_root == root
    }
}

pub fn expand_tree<const D: usize, const E: usize, F: RichField>(_tree: Tree<D, F>) -> Tree<E, F> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;

    use super::{hash, Error, Tree};
    use crate::core::credential::Credential;

    #[test]
    fn proof_round_trip_for_each_inserted_credential() {
        let credentials = vec![
            Credential::from_seed(1).2,
            Credential::from_seed(2).2,
            Credential::from_seed(3).2,
            Credential::from_seed(4).2,
        ];
        let tree = Tree::<2, GoldilocksField>::from(&credentials)
            .expect("distinct credentials should build a tree");

        for credential in &credentials {
            let proof = tree
                .prove_credential(credential)
                .expect("credential should be in the tree");
            assert!(Tree::verify(tree.root(), credential, proof));
        }
    }

    #[test]
    fn verify_rejects_a_proof_for_a_different_credential() {
        let (_, _, credential_1) = Credential::from_seed(10);
        let (_, _, credential_2) = Credential::from_seed(11);
        let credentials = vec![credential_1.clone(), credential_2.clone()];
        let tree = Tree::<1, GoldilocksField>::from(&credentials)
            .expect("distinct credentials should build a tree");

        let proof = tree
            .prove_credential(&credential_1)
            .expect("credential_1 should be in the tree");

        assert!(!Tree::verify(tree.root(), &credential_2, proof));
    }

    #[test]
    fn add_and_revoke_update_root_and_membership() {
        let (_, _, credential_1) = Credential::from_seed(20);
        let (_, _, credential_2) = Credential::from_seed(21);
        let credentials = vec![credential_1.clone()];
        let mut tree = Tree::<2, GoldilocksField>::from(&credentials)
            .expect("distinct credentials should build a tree");
        let root_before = tree.root();

        tree.add(&credential_2)
            .expect("adding a fresh credential should succeed");
        let root_after_add = tree.root();
        assert_ne!(root_after_add, root_before);

        let proof = tree
            .prove_credential(&credential_2)
            .expect("added credential should be provable");
        assert!(Tree::verify(root_after_add, &credential_2, proof));

        // re-prove because Proof does not implement Clone
        let proof_before_revoke = tree
            .prove_credential(&credential_2)
            .expect("added credential should be provable");
        tree.revoke(&credential_2)
            .expect("revoking an existing credential should succeed");
        assert_eq!(tree.root(), root_before);
        assert!(matches!(
            tree.prove_credential(&credential_2),
            Err(Error::MissingCredential)
        ));
        assert!(!Tree::verify(
            tree.root(),
            &credential_2,
            proof_before_revoke
        ))
    }

    #[test]
    fn add_reports_duplicate_and_full_tree_errors() {
        let (_, _, credential_1) = Credential::from_seed(30);
        let (_, _, credential_2) = Credential::from_seed(31);
        let (_, _, credential_3) = Credential::from_seed(32);
        let credentials = vec![credential_1.clone()];
        let mut tree = Tree::<1, GoldilocksField>::from(&credentials)
            .expect("distinct credentials should build a tree");
        assert!(matches!(
            tree.add(&credential_1),
            Err(Error::DuplicateCredential)
        ));
        tree.add(&credential_2)
            .expect("second slot should still be available");
        assert!(matches!(
            tree.add(&credential_3),
            Err(Error::CapacityExceeded)
        ));
    }

    #[test]
    fn from_rejects_duplicate_credentials() {
        let (_, _, credential) = Credential::from_seed(35);
        let credentials = vec![credential.clone(), credential];
        assert!(matches!(
            Tree::<1, GoldilocksField>::from(&credentials),
            Err(Error::DuplicateCredential)
        ));
    }

    #[test]
    fn revoke_missing_credential_returns_missing_credential_error() {
        let (_, _, credential_1) = Credential::from_seed(40);
        let (_, _, credential_2) = Credential::from_seed(41);
        let credentials = vec![credential_1];
        let mut tree = Tree::<1, GoldilocksField>::from(&credentials)
            .expect("distinct credentials should build a tree");

        assert!(matches!(
            tree.revoke(&credential_2),
            Err(Error::MissingCredential)
        ));
    }

    #[test]
    fn empty_tree_root_matches_recursive_empty_hashes() {
        let credentials = vec![];
        let tree = Tree::<2, GoldilocksField>::from(&credentials)
            .expect("empty tree should build successfully");
        let leaves = vec![hash::empty(); 4];
        let level_1 = hash::hash_vec(&leaves);
        let level_2 = hash::hash_vec(&level_1);
        assert_eq!(tree.root(), level_2[0]);
    }
}
