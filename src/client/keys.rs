// FIXME: Obviously this is not a secure way to keep the keys, this should only be used for the PoC

use rand::{rngs::StdRng, SeedableRng};

use crate::schnorr::keys::{PublicKey, SecretKey};

// FIXME: TOTALLY INSECURE AND INEFFICIENT
pub fn secret() -> SecretKey {
    let mut rng = StdRng::seed_from_u64(43);
    SecretKey::random(&mut rng)
}

// TODO: public key should be given to the issuer, but not to the third party that performs the KYC
pub fn public() -> PublicKey {
    PublicKey::from(&secret())
}
