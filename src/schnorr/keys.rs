use crate::arith::{Point, Scalar};
use rand::{rand_core, Rng};

pub struct SecretKey(pub(crate) Scalar);

#[derive(Debug, Clone)]
pub struct PublicKey(pub(crate) Point);

// pub(crate) struct InternalPublicKey(pub(crate) encoding::Point<GoldilocksField>);

impl SecretKey {
    /// Generates a random non-null scalar field element from secure rng
    pub fn new() -> Result<Self, rand_core::OsError> {
        let key = Scalar::random()?;
        Ok(Self(key))
    }
    pub fn random(rng: &mut impl Rng) -> Self {
        Self(Scalar::random_from_rng(rng))
    }
}

impl PublicKey {
    pub fn from(sk: &SecretKey) -> Self {
        Self(Point::mulgen(sk.0))
    }
}

// impl From<&PublicKey> for InternalPublicKey {
//     fn from(value: &PublicKey) -> Self {
//         Self((&value.0).into())
//     }
// }
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn public_key_from_secret_key_matches_mulgen() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = SecretKey::random(&mut rng);

        let pk = PublicKey::from(&sk);
        let expected = Point::GENERATOR * sk.0;

        assert!(pk.0.equals(expected) == u64::MAX);
    }

    #[test]
    fn secret_key_random_is_deterministic_for_seeded_rng() {
        let mut rng1 = StdRng::seed_from_u64(123456);
        let mut rng2 = StdRng::seed_from_u64(123456);

        let sk1 = SecretKey::random(&mut rng1);
        let sk2 = SecretKey::random(&mut rng2);

        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);

        assert!(pk1.0.equals(pk2.0) == u64::MAX);
    }

    #[test]
    fn secret_key_random_changes_with_rng_state() {
        let mut rng = StdRng::seed_from_u64(999);

        let sk1 = SecretKey::random(&mut rng);
        let sk2 = SecretKey::random(&mut rng);

        let pk1 = PublicKey::from(&sk1);
        let pk2 = PublicKey::from(&sk2);

        assert!(pk1.0.equals(pk2.0) == 0);
    }
}
