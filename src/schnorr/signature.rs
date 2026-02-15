use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;

use crate::core::credential::Credential;
use crate::encoding;
use crate::encoding::conversion::ToSignatureField;

use super::core::SchnorrProof;
/// Signature will be used by the authority to sign the credential
/// We expect the authority to sign a lot of messages with the same secret key
use super::keys::{PublicKey, SecretKey};
use super::transcript;

type Message = [GoldilocksField; encoding::LEN_CREDENTIAL];

pub struct Signature(pub(crate) SchnorrProof);
pub struct Context {
    public_key: PublicKey,
    message: Message,
}

impl Context {
    /// Creates a new context. Creates a copy of public_key and takes ownership
    /// of message
    pub fn new(public_key: &PublicKey, credential: &Credential) -> Self {
        Self {
            public_key: public_key.clone(),
            message: (&credential.to_field()).into(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn message(&self) -> &Message {
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

impl<F: RichField> ToSignatureField<F, bool> for Signature {
    fn to_field(&self) -> crate::encoding::Signature<F, bool> {
        self.0.to_field()
    }
}

#[cfg(test)]
mod tests {
    use super::{Context, Signature};
    use crate::{
        core::credential::Credential,
        schnorr::keys::{PublicKey, SecretKey},
    };
    use rand::{rngs::StdRng, SeedableRng};

    fn keypair_and_credential_from_seed(seed: u64) -> (SecretKey, PublicKey, Credential) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(&sk);
        let credential = Credential::random(&mut rng);
        (sk, pk, credential)
    }

    #[test]
    fn sign_then_verify_ok() {
        let (sk, pk, credential) = keypair_and_credential_from_seed(1);
        let ctx = Context::new(&pk, &credential);

        let sig = Signature::sign(&sk, &ctx);
        assert!(sig.verify(&ctx));
    }

    #[test]
    fn verify_fails_if_message_changes() {
        let (sk, pk, credential) = keypair_and_credential_from_seed(2);

        let ctx_good = Context::new(&pk, &credential);
        let sig = Signature::sign(&sk, &ctx_good);

        let (_sk, _pk, credential) = keypair_and_credential_from_seed(3);

        let ctx_bad = Context::new(&pk, &credential);
        assert!(!sig.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_public_key_changes() {
        let (sk1, pk1, credential) = keypair_and_credential_from_seed(4);
        let (_sk2, pk2, _credential) = keypair_and_credential_from_seed(5);

        let ctx1 = Context::new(&pk1, &credential);
        let sig = Signature::sign(&sk1, &ctx1);

        let (_sk1, _pk1, credential) = keypair_and_credential_from_seed(4);

        let ctx_other_pk = Context::new(&pk2, &credential);
        assert!(!sig.verify(&ctx_other_pk));
    }
}
