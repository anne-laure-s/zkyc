use plonky2::hash::hash_types::RichField;

use crate::{core::credential::Credential, encoding::Pseudonym, merkle};

// TODO: for now, SIZE is very small for tests
pub const SIZE: usize = 8;

// TODO: Instanciate F here
/// Database with a capacity SIZE, as a Merkle Tree
struct Database<F: RichField>(merkle::Tree<SIZE, F>);

impl<F: RichField> Database<F> {
    pub fn init(credentials: &[Credential]) -> Self {
        Self(merkle::Tree::<SIZE, F>::from(credentials).unwrap())
    }

    pub fn proof(&self, credential: &Credential) -> merkle::Proof<SIZE, F> {
        self.0.prove(credential).unwrap()
    }

    pub fn from_pseudonym(&self, pseudo: Pseudonym<F>) {
        unimplemented!()
    }
}
