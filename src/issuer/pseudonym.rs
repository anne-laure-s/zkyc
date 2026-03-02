use plonky2::{
    field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::Hasher,
};

use crate::{
    encoding::{
        self,
        conversion::{ToPointField, ToStringField},
        LEN_POINT, LEN_STRING,
    },
    schnorr::keys::PublicKey,
};

pub type Pseudonym = encoding::Pseudonym<GoldilocksField>;

pub fn hash(
    service: encoding::String<GoldilocksField>,
    public_key: encoding::Point<GoldilocksField>,
) -> Pseudonym {
    let mut message = Vec::with_capacity(LEN_STRING + LEN_POINT);
    message.extend_from_slice(&service.0);
    let public_key: [GoldilocksField; LEN_POINT] = public_key.into();
    message.extend_from_slice(&public_key);
    encoding::Pseudonym(PoseidonHash::hash_no_pad(&message).elements)
}

pub fn hash_from_service(service: &str, public_key: &PublicKey) -> Pseudonym {
    hash(service.to_string().to_field(), public_key.0.to_field())
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::hash_from_service;
    use crate::schnorr::keys::SecretKey;

    #[test]
    fn pseudonym_changes_with_service_or_public_key() {
        let mut rng = StdRng::seed_from_u64(123);
        let sk1 = SecretKey::random(&mut rng);
        let sk2 = SecretKey::random(&mut rng);
        let pk1 = crate::schnorr::keys::PublicKey::from(&sk1);
        let pk2 = crate::schnorr::keys::PublicKey::from(&sk2);

        let h1 = hash_from_service("service-A", &pk1);
        let h2 = hash_from_service("service-B", &pk1);
        let h3 = hash_from_service("service-A", &pk2);

        assert_ne!(h1.0, h2.0, "pseudonym should depend on the service");
        assert_ne!(h1.0, h3.0, "pseudonym should depend on the public key");
    }
}
