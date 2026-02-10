use super::core::SchnorrProof;
/// Signature will be used by the authority to sign the credential
/// We expect the authority to sign a lot of messages with the same secret key
use super::keys::{PublicKey, SecretKey};
use super::transcript;

pub struct Signature(SchnorrProof);
pub struct Context {
    public_key: PublicKey,
    message: Vec<u8>,
}

impl Context {
    /// Creates a new context. Creates a copy of public_key and takes ownership
    /// of message
    pub fn new(public_key: &PublicKey, message: Vec<u8>) -> Self {
        let public_key = PublicKey(public_key.0);
        Self {
            public_key,
            message,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub fn to_context(&self) -> transcript::Context<'_> {
        transcript::Context::Sig(self)
    }
}

impl Signature {
    /// returns a signature of the given message with the given secret key
    // TODO: pk is not needed for the prover, maybe it could be better to
    // remove it from here
    pub fn sign(sk: &SecretKey, ctx: &Context) -> Self {
        Self(SchnorrProof::prove(sk, ctx.to_context()))
    }

    /// verifies the signature produced by sign for the given message
    pub fn verify(&self, ctx: &Context) -> bool {
        self.0.verify(ctx.to_context())
    }
}
#[cfg(test)]
mod tests {
    use super::{Context, Signature};
    use crate::schnorr::keys::{PublicKey, SecretKey};
    use rand::{rngs::StdRng, SeedableRng};

    fn keypair_from_seed(seed: u64) -> (SecretKey, PublicKey) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn sign_then_verify_ok() {
        let (sk, pk) = keypair_from_seed(1);
        let ctx = Context::new(&pk, b"hello".to_vec());

        let sig = Signature::sign(&sk, &ctx);
        assert!(sig.verify(&ctx));
    }

    #[test]
    fn verify_fails_if_message_changes() {
        let (sk, pk) = keypair_from_seed(2);

        let ctx_good = Context::new(&pk, b"message A".to_vec());
        let sig = Signature::sign(&sk, &ctx_good);

        let ctx_bad = Context::new(&pk, b"message B".to_vec());
        assert!(!sig.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_public_key_changes() {
        let (sk1, pk1) = keypair_from_seed(3);
        let (_sk2, pk2) = keypair_from_seed(4);

        let ctx1 = Context::new(&pk1, b"same message".to_vec());
        let sig = Signature::sign(&sk1, &ctx1);

        let ctx_other_pk = Context::new(&pk2, b"same message".to_vec());
        assert!(!sig.verify(&ctx_other_pk));
    }
}
