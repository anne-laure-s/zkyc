use crate::{
    arith::{Point, Scalar},
    schnorr::{authentification, hash, keys::PublicKey, signature},
};
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

pub enum Context<'a> {
    Auth(&'a authentification::Context),
    Sig(&'a signature::Context),
}
impl<'a> Context<'a> {
    pub fn public_key(&'a self) -> &'a PublicKey {
        match self {
            Self::Auth(ctx) => ctx.public_key(),
            Self::Sig(ctx) => ctx.public_key(),
        }
    }
}

pub fn point_to_vec_goldilocks(x: &Point) -> Vec<GoldilocksField> {
    x.encode()
        .0
        .iter()
        .map(|x| GoldilocksField::from_canonical_u64(x.to_u64()))
        .collect()
}

// Pack by u32 instead of u64, to avoid modulo overflow that breaks injectivity
pub fn message_to_goldilocks(message: &[u8]) -> Vec<GoldilocksField> {
    let mut goldilocks_vec = Vec::with_capacity((message.len() / 4) + 1);
    let mut buffer = [0; 4];
    let mut counter = 0;
    while counter < message.len() {
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = *message.get(counter + i).unwrap_or(&0)
        }
        let u = u32::from_le_bytes(buffer);
        goldilocks_vec.push(GoldilocksField::from_canonical_u64(u as u64));
        counter += 4
    }
    goldilocks_vec
}

// FIXME: Add the tag back, (was removed for simplification in the circuit)
pub fn hash(nonce: &Point, ctx: Context) -> Scalar {
    // let tag = match ctx {
    //     Context::Auth(_) => b"ZKYC_SCHNORR_AUT_CHALLENGE_V1",
    //     Context::Sig(_) => b"ZKYC_SCHNORR_SIG_CHALLENGE_V1",
    // };
    // let mut f_message = message_to_goldilocks(tag);
    let mut f_message = Vec::new();
    match ctx {
        Context::Auth(ctx) => {
            f_message.extend_from_slice(
                &ctx.service()
                    .map(|x| GoldilocksField::from_canonical_u64(x.0)),
            );
            f_message.extend_from_slice(
                &ctx.nonce()
                    .map(|x| GoldilocksField::from_canonical_u64(x.0)),
            );
            // Public key is already in the credential
            f_message.extend_from_slice(&point_to_vec_goldilocks(&ctx.public_key().0));
        }
        Context::Sig(ctx) => {
            f_message.extend_from_slice(
                &ctx.message()
                    .map(|x| GoldilocksField::from_canonical_u64(x.0)),
            );
        }
    };
    let mut to_hash = point_to_vec_goldilocks(nonce);
    to_hash.extend_from_slice(&f_message);
    hash::poseidon_xof_bits_native(&to_hash)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::{
        authentification,
        keys::{PublicKey, SecretKey},
        signature,
    };
    use rand::{rngs::StdRng, SeedableRng};

    fn pk_from_seed(seed: u64) -> PublicKey {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        PublicKey::from(&sk)
    }

    fn nonce_point_from_seed(seed: u64) -> Point {
        let mut rng = StdRng::seed_from_u64(seed);
        let k = Scalar::random_from_rng(&mut rng);
        Point::mulgen(k)
    }

    fn sk_credential_from_seed(seed: u64) -> (SecretKey, crate::core::credential::Credential) {
        let mut rng = StdRng::seed_from_u64(seed);
        crate::core::credential::Credential::random(&mut rng)
    }

    fn switched_credential() -> (
        SecretKey,
        crate::core::credential::Credential,
        crate::core::credential::Credential,
    ) {
        let (sk, mut c2) = sk_credential_from_seed(12345);
        let c1 = c2.clone();
        c2.switch_names_char();
        (sk, c1, c2)
    }

    #[test]
    fn hash_injective() {
        let r = nonce_point_from_seed(2);

        let (_sk, cred1, cred2) = switched_credential();

        let ctx1 = signature::Context::new(&cred1);
        let ctx2 = signature::Context::new(&cred2);

        let e1 = hash(&r, ctx1.to_context());
        let e2 = hash(&r, ctx2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "challenge must differ when credential's variable-length field differs only by one character switch"
        );
    }

    #[test]
    fn auth_hash_changes_when_service_or_nonce_changes() {
        let pk = pk_from_seed(100);
        let r = nonce_point_from_seed(200);

        let ctx1 = authentification::Context::new(&pk, b"svcA", b"nonce1");
        let ctx2 = authentification::Context::new(&pk, b"svcB", b"nonce1");
        let ctx3 = authentification::Context::new(&pk, b"svcA", b"nonce2");

        let e1 = hash(&r, ctx1.to_context());
        let e2 = hash(&r, ctx2.to_context());
        let e3 = hash(&r, ctx3.to_context());

        assert!(
            e1.equals(e2) == 0,
            "auth challenge must change when service changes"
        );
        assert!(
            e1.equals(e3) == 0,
            "auth challenge must change when server nonce changes"
        );
    }

    #[test]
    fn challenge_is_bound_to_public_key() {
        let r = nonce_point_from_seed(4242);
        let msg = b"bind-me".to_vec();
        let pk1 = pk_from_seed(1);
        let pk2 = pk_from_seed(2);

        let ctx_pk1 = authentification::Context::new(&pk1, &msg, &msg);
        let ctx_pk2 = authentification::Context::new(&pk2, &msg, &msg);

        let e1 = hash(&r, ctx_pk1.to_context());
        let e2 = hash(&r, ctx_pk2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "authentification challenge must depend on the public key"
        );

        let (_sk, cred_pk1) = sk_credential_from_seed(4555);
        let mut cred_pk2 = cred_pk1.clone();
        let mut rng = StdRng::seed_from_u64(556);
        cred_pk2.switch_issuer(&mut rng);

        let ctx_pk1 = signature::Context::new(&cred_pk1);
        let ctx_pk2 = signature::Context::new(&cred_pk2);

        let e1 = hash(&r, ctx_pk1.to_context());
        let e2 = hash(&r, ctx_pk2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "signature challenge must depend on the public key"
        );
    }
}
