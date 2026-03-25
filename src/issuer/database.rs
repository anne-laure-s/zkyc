use crate::{circuit, core::credential::Credential, merkle};

// TODO: for now, SIZE is very small for tests
pub const SIZE: usize = 8;

/// Database with a capacity SIZE, as a Merkle Tree
pub struct Database(merkle::Tree<SIZE, circuit::F>);

pub type Proof = merkle::Proof<SIZE, circuit::F>;
pub type Root = merkle::Root<circuit::F>;

impl Database {
    pub fn init(credentials: &[Credential]) -> Self {
        Self(merkle::Tree::<SIZE, circuit::F>::from(credentials).unwrap())
    }

    pub fn root(&self) -> Root {
        self.0.root()
    }

    pub fn proof(&self, credential: &Credential) -> merkle::Result<Proof> {
        self.0.prove(credential)
    }
}

pub mod for_tests {
    use std::sync::LazyLock;

    use crate::{
        core::credential::Credential,
        issuer::database::{Database, SIZE},
    };

    pub static DATABASE: LazyLock<Database> = LazyLock::new(|| {
        let credentials: [Credential; SIZE] =
            std::array::from_fn(|i| Credential::from_seed(i as u64).2);
        Database::init(&credentials)
    });
}
