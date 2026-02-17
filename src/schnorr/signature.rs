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
    pub fn new(credential: &Credential) -> Self {
        Self {
            public_key: credential.issuer(),
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
    use crate::{core::credential::Credential, schnorr::keys::SecretKey};
    use rand::{rngs::StdRng, SeedableRng};

    fn credential_from_seed(seed: u64) -> (SecretKey, Credential) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (sk, credential) = Credential::random(&mut rng);
        (sk, credential)
    }

    fn same_credential_different_issuer(
        seed: u64,
    ) -> (SecretKey, Credential, SecretKey, Credential) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (sk1, cred1) = Credential::random(&mut rng);
        let sk2 = SecretKey::random(&mut rng);
        let mut rng = StdRng::seed_from_u64(seed);
        let cred2 = Credential::random_with_issuer(&sk2, &mut rng);
        (sk1, cred1, sk2, cred2)
    }

    #[test]
    fn sign_then_verify_ok() {
        let (sk, credential) = credential_from_seed(1);
        let ctx = Context::new(&credential);

        let sig = Signature::sign(&sk, &ctx);
        assert!(sig.verify(&ctx));
    }

    #[test]
    fn verify_fails_if_message_changes() {
        let (sk, mut credential) = credential_from_seed(2);

        let ctx_good = Context::new(&credential);
        let sig = Signature::sign(&sk, &ctx_good);

        credential.switch_names_char();

        let (_sk, credential) = credential_from_seed(3);

        let ctx_bad = Context::new(&credential);
        assert!(!sig.verify(&ctx_bad));
    }

    #[test]
    fn verify_fails_if_public_key_changes() {
        let (sk1, cred1, _sk2, cred2) = same_credential_different_issuer(4);

        let ctx1 = Context::new(&cred1);
        let sig = Signature::sign(&sk1, &ctx1);

        let ctx_other_pk = Context::new(&cred2);
        assert!(!sig.verify(&ctx_other_pk));
    }
}
