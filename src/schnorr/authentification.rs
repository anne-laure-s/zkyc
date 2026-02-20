use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;

use crate::encoding;
use crate::encoding::conversion::ToSignatureField;
use crate::encoding::conversion::ToVecField;
use crate::encoding::LEN_STRING;

use super::core::SchnorrProof;
/// Authentification will be used by the user to prove that they knows the secret key tied to some public key
/// TODO: public key for authentification should depend on the service
use super::keys::{PublicKey, SecretKey};
use super::transcript;

pub struct Context {
    public_key: PublicKey,
    // TODO: ensure everything is ascii ?
    // server service
    service: [GoldilocksField; LEN_STRING],
    // nonce from server, unique per session
    nonce: [GoldilocksField; LEN_STRING],
    // TODO: session_id, channel_id
}

impl Context {
    /// Creates a new context. Creates a copy of public_key and takes ownership
    /// of service & nonce
    pub fn new(public_key: &PublicKey, service: &[u8], nonce: &[u8]) -> Self {
        Self {
            public_key: public_key.clone(),
            service: service.to_field(LEN_STRING).try_into().unwrap(),
            nonce: nonce.to_field(LEN_STRING).try_into().unwrap(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn service(&self) -> &[GoldilocksField; LEN_STRING] {
        &self.service
    }

    pub fn nonce(&self) -> &[GoldilocksField; LEN_STRING] {
        &self.nonce
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

impl<F: RichField> ToSignatureField<F, bool> for Authentification {
    fn to_field(&self) -> encoding::Signature<F, bool> {
        self.0.to_field()
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
        let ctx = Context::new(&pk, b"service-A", b"nonce-1");

        let auth = Authentification::sign(&sk, &ctx);
        assert!(auth.verify(&ctx));
    }

    #[test]
    fn verify_fails_if_service_changes() {
        let (sk, pk) = keypair_from_seed(2);

        let ctx_good = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good);

        let ctx_bad = Context::new(&pk, b"service-B", b"nonce-1");
        assert!(!auth.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_nonce_changes() {
        let (sk, pk) = keypair_from_seed(3);

        let ctx_good = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good);

        let ctx_bad = Context::new(&pk, b"service-A", b"nonce-2");
        assert!(!auth.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_public_key_changes() {
        let (sk1, pk1) = keypair_from_seed(4);
        let (_sk2, pk2) = keypair_from_seed(5);

        let ctx1 = Context::new(&pk1, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk1, &ctx1);

        let ctx_other_pk = Context::new(&pk2, b"service-A", b"nonce-1");
        assert!(!auth.verify(&ctx_other_pk));
    }
}
