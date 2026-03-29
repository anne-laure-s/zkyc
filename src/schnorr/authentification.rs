use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;

use crate::encoding;
use crate::encoding::conversion::ToAuthentificationContextField;
use crate::encoding::conversion::ToAuthentificationField;
use crate::encoding::conversion::ToPointField;
use crate::encoding::conversion::ToSchnorrField;
use crate::encoding::conversion::ToStringField;
use crate::encoding::AuthentificationChallenge;
use crate::encoding::AuthentificationChallengeRaw;

use super::core::SchnorrProof;
/// Authentification will be used by the user to prove that they knows the secret key tied to some public key
/// TODO: public key for authentification should depend on the service
use super::keys::{PublicKey, SecretKey};
use super::transcript;

pub struct Context {
    public_key: PublicKey,
    // TODO: ensure everything is ascii ?
    challenge: AuthentificationChallengeRaw<encoding::String<GoldilocksField>>, // TODO: session_id, channel_id
}

impl Context {
    /// Creates a new context. Creates a copy of public_key and takes ownership
    /// of service & nonce
    pub fn new(public_key: &PublicKey, service: &str, nonce: &str) -> Self {
        Self {
            public_key: public_key.clone(),
            challenge: AuthentificationChallengeRaw {
                service: service.to_string().to_field(),
                nonce: nonce.to_string().to_field(),
            },
        }
    }

    pub fn from_challenge(
        public_key: &PublicKey,
        challenge: &AuthentificationChallengeRaw<String>,
    ) -> Self {
        Self {
            public_key: public_key.clone(),
            challenge: AuthentificationChallengeRaw {
                service: challenge.service.to_field(),
                nonce: challenge.nonce.to_field(),
            },
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn service(&self) -> &encoding::String<GoldilocksField> {
        &self.challenge.service
    }

    pub fn nonce(&self) -> &encoding::String<GoldilocksField> {
        &self.challenge.nonce
    }

    pub fn to_context(&self) -> transcript::Context<'_> {
        transcript::Context::Auth(self)
    }
}

// TODO: faire de la signature une schnorr proof plutôt que l’inverse
pub struct Authentification(SchnorrProof);

impl Authentification {
    /// returns a proof of knowledge of a secret key for the corresponding public key
    pub fn sign(sk: &SecretKey, ctx: &Context) -> Self {
        Self(SchnorrProof::prove(sk, ctx.to_context()))
    }

    /// verifies the authentification proof
    pub fn verify(&self, ctx: &Context) -> bool {
        self.0.verify(ctx.to_context())
    }
}

impl<F: RichField> ToAuthentificationField<F, bool> for Authentification {
    fn to_field(&self) -> encoding::Authentification<F, bool> {
        encoding::Authentification(self.0.to_field())
    }
}

impl<F: RichField> ToAuthentificationContextField<F> for Context {
    fn to_field(&self) -> encoding::AuthentificationContext<F> {
        encoding::AuthentificationContext {
            public_key: self.public_key.0.to_field(),
            challenge: AuthentificationChallenge {
                service: encoding::String(
                    self.challenge.service.0.map(|x| F::from_canonical_u64(x.0)),
                ),
                nonce: encoding::String(self.challenge.nonce.0.map(|x| F::from_canonical_u64(x.0))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Authentification, Context};
    use crate::schnorr::keys::{PublicKey, SecretKey};
    use rand::{rngs::StdRng, SeedableRng};

    fn keypair_from_seed(seed: u64) -> (SecretKey, PublicKey) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn auth_sign_then_verify_ok() {
        let (sk, pk) = keypair_from_seed(1);
        let ctx = Context::new(&pk, "service-A", "nonce-1");

        let auth = Authentification::sign(&sk, &ctx);
        assert!(auth.verify(&ctx));
    }

    #[test]
    fn verify_fails_if_service_changes() {
        let (sk, pk) = keypair_from_seed(2);

        let ctx_good = Context::new(&pk, "service-A", "nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good);

        let ctx_bad = Context::new(&pk, "service-B", "nonce-1");
        assert!(!auth.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_nonce_changes() {
        let (sk, pk) = keypair_from_seed(3);

        let ctx_good = Context::new(&pk, "service-A", "nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good);

        let ctx_bad = Context::new(&pk, "service-A", "nonce-2");
        assert!(!auth.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_public_key_changes() {
        let (sk1, pk1) = keypair_from_seed(4);
        let (_sk2, pk2) = keypair_from_seed(5);

        let ctx1 = Context::new(&pk1, "service-A", "nonce-1");
        let auth = Authentification::sign(&sk1, &ctx1);

        let ctx_other_pk = Context::new(&pk2, "service-A", "nonce-1");
        assert!(!auth.verify(&ctx_other_pk));
    }
}
