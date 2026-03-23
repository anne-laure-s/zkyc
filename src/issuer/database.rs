use plonky2::hash::hash_types::RichField;

use crate::{core::credential::Credential, encoding::Pseudonym, merkle};

// TODO: for now, SIZE is very small for tests
pub const SIZE: usize = 8;

// TODO: Instanciate F here?
/// Database with a capacity SIZE, as a Merkle Tree
pub struct Database<F: RichField>(merkle::Tree<SIZE, F>);

impl<F: RichField> Database<F> {
    pub fn init(credentials: &[Credential]) -> Self {
        Self(merkle::Tree::<SIZE, F>::from(credentials).unwrap())
    }

    pub fn root(&self) -> merkle::Root<F> {
        self.0.root()
    }

    pub fn proof(&self, credential: &Credential) -> merkle::Proof<SIZE, F> {
        self.0.prove(credential).unwrap()
    }

    pub fn from_pseudonym(&self, _pseudo: Pseudonym<F>) {
        unimplemented!()
    }
}

pub mod for_tests {
    use std::sync::LazyLock;

    use plonky2::field::goldilocks_field::GoldilocksField;

    use crate::{
        core::credential::Credential,
        issuer::database::{Database, SIZE},
    };

    pub static DATABASE: LazyLock<Database<GoldilocksField>> = LazyLock::new(|| {
        let credentials: [Credential; SIZE] =
            std::array::from_fn(|i| Credential::from_seed(i as u64).2);
        Database::init(&credentials)
    });
}
