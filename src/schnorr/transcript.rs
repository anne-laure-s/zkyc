use poseidon_hash::{Fp5Element, Goldilocks};

use crate::{
    arith::{field::GFp5, Point, Scalar},
    schnorr::{authentification, keys::PublicKey, signature},
};

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

pub fn to_canonical_fp5_element(mut fp5: Fp5Element) -> Fp5Element {
    for u in fp5.0.iter_mut() {
        *u = Goldilocks::from_canonical_u64(Goldilocks::to_canonical_u64(u))
    }
    Fp5Element(fp5.0)
}

pub fn point_to_vec_goldilocks(x: &Point) -> Vec<Goldilocks> {
    x.encode()
        .0
        .iter()
        .map(|x| Goldilocks::from_canonical_u64(x.to_u64()))
        .collect()
}

// Pack by u32 instead of u64, to avoid modulo overflow that breaks injectivity
pub fn message_to_goldilocks(message: &[u8]) -> Vec<Goldilocks> {
    let mut goldilocks_vec = Vec::with_capacity((message.len() / 4) + 1);
    let mut buffer = [0; 4];
    let mut counter = 0;
    while counter < message.len() {
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = *message.get(counter + i).unwrap_or(&0)
        }
        let u = u32::from_le_bytes(buffer);
        goldilocks_vec.push(Goldilocks::from_canonical_u64(u as u64));
        counter += 4
    }
    goldilocks_vec
}

/// Performs poseidon on the provided message to return a scalar.
/// Expects canonical Goldilocks.
/// At every conversion steps, scalars & base field elements are reduced.
/// This function is not safe for nonce generation
pub fn poseidon_to_scalar(message: &[Goldilocks]) -> Scalar {
    let fp5 = poseidon_hash::hash_to_quintic_extension(message);
    let canonical_fp = to_canonical_fp5_element(fp5);
    let (gfp5, c) = GFp5::decode(&canonical_fp.to_bytes_le());
    if c == 0 {
        unreachable!("decode should always success, as fp is canonical")
    }
    Scalar::from_gfp5(&gfp5)
}

// TODO: check if the order is important, and if more length information are needed
//
pub fn hash(nonce: &Point, ctx: Context) -> Scalar {
    let tag = match ctx {
        Context::Auth(_) => b"ZKYC_SCHNORR_AUT_CHALLENGE_V1",
        Context::Sig(_) => b"ZKYC_SCHNORR_SIG_CHALLENGE_V1",
    };
    let mut f_message = message_to_goldilocks(tag);
    match ctx {
        Context::Auth(ctx) => {
            f_message
                .extend_from_slice(&ctx.service().map(|x| Goldilocks::from_canonical_u64(x.0)));
            f_message.extend_from_slice(&ctx.nonce().map(|x| Goldilocks::from_canonical_u64(x.0)));
        }
        Context::Sig(ctx) => {
            f_message
                .extend_from_slice(&ctx.message().map(|x| Goldilocks::from_canonical_u64(x.0)));
        }
    };
    let mut to_hash = point_to_vec_goldilocks(nonce);
    to_hash.extend_from_slice(&point_to_vec_goldilocks(&ctx.public_key().0));
    to_hash.extend_from_slice(&f_message);
    poseidon_to_scalar(&to_hash)
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

    fn credential_from_seed(seed: u64) -> crate::core::credential::Credential {
        let mut rng = StdRng::seed_from_u64(seed);
        crate::core::credential::Credential::random(&mut rng)
    }

    fn switched_credential() -> (
        crate::core::credential::Credential,
        crate::core::credential::Credential,
    ) {
        let mut c2 = credential_from_seed(12345);
        let c1 = c2.clone();
        c2.switch_names_char();
        (c1, c2)
    }

    #[test]
    fn hash_injective() {
        let pk = pk_from_seed(1);
        let r = nonce_point_from_seed(2);

        let (cred1, cred2) = switched_credential();

        let ctx1 = signature::Context::new(&pk, &cred1);
        let ctx2 = signature::Context::new(&pk, &cred2);

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

        let cred = credential_from_seed(4555);

        let ctx_pk1 = signature::Context::new(&pk1, &cred);
        let ctx_pk2 = signature::Context::new(&pk2, &cred);

        let e1 = hash(&r, ctx_pk1.to_context());
        let e2 = hash(&r, ctx_pk2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "signature challenge must depend on the public key"
        );
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let msg = message_to_goldilocks(b"canonical check");
        let fp5 = poseidon_hash::hash_to_quintic_extension(&msg);

        let c1 = to_canonical_fp5_element(fp5);
        let c2 = to_canonical_fp5_element(c1);

        assert_eq!(
            c1.to_bytes_le(),
            c2.to_bytes_le(),
            "canonicalization should be idempotent"
        );
    }
}
