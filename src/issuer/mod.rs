use rand::Rng;

use crate::{core::credential::Credential, schnorr::signature::Signature};

pub mod keys;

pub fn random_and_sign(rng: &mut impl Rng) -> (Credential, Signature) {
    let credential = Credential::random(rng);
    let signature = credential.sign(&keys::secret(), &keys::public());
    (credential, signature)
}

pub fn send(_credential: Credential, _signature: Signature) {
    todo!()
}
