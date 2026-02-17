use rand::Rng;

use crate::{core::credential::Credential, schnorr::signature::Signature};

pub mod keys;

pub fn random_and_sign(rng: &mut impl Rng) -> (Credential, Signature) {
    let credential = Credential::random_with_issuer(&keys::secret(), rng);
    let signature = credential.sign(&keys::secret());
    (credential, signature)
}

pub fn send(_credential: Credential, _signature: Signature) {
    todo!()
}
