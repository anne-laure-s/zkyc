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
            Self::Auth(ref ctx) => ctx.public_key(),
            Self::Sig(ref ctx) => ctx.public_key(),
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
        Context::Auth(_) => b"ZKYC_SCHNORR_AUT_CHALLENGE",
        Context::Sig(_) => b"ZKYC_SCHNORR_SIG_CHALLENGE",
    };
    let mut byte_message = tag.to_vec();
    match ctx {
        Context::Auth(ctx) => {
            byte_message.extend_from_slice(&(ctx.service().len() as u32).to_le_bytes());
            byte_message.extend_from_slice(&ctx.service());
            byte_message.extend_from_slice(&(ctx.nonce().len() as u32).to_le_bytes());
            byte_message.extend_from_slice(&ctx.nonce());
        }
        Context::Sig(ctx) => {
            byte_message.extend_from_slice(&(ctx.message().len() as u32).to_le_bytes());
            byte_message.extend_from_slice(ctx.message());
        }
    };
    let mut to_hash = point_to_vec_goldilocks(nonce);
    to_hash.extend_from_slice(&point_to_vec_goldilocks(&ctx.public_key().0));
    to_hash.extend_from_slice(&message_to_goldilocks(&byte_message));
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
        // nonce point r = k*G, avec k déterministe pour les tests
        let mut rng = StdRng::seed_from_u64(seed);
        let k = Scalar::random_from_rng(&mut rng);
        Point::mulgen(k)
    }

    #[test]
    fn message_length_prefix_makes_hash_injective_over_trailing_zeros() {
        let pk = pk_from_seed(1);
        let r = nonce_point_from_seed(2);

        let ctx1 = signature::Context::new(&pk, vec![1]);
        let ctx2 = signature::Context::new(&pk, vec![1, 0]);

        let e1 = hash(&r, ctx1.to_context());
        let e2 = hash(&r, ctx2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "hash should differ when message length differs, even if padding makes chunks look similar"
        );
    }

    #[test]
    fn signature_hash_changes_when_message_changes() {
        let pk = pk_from_seed(10);
        let r = nonce_point_from_seed(20);

        let ctx_a = signature::Context::new(&pk, b"hello".to_vec());
        let ctx_b = signature::Context::new(&pk, b"hellp".to_vec());

        let e_a = hash(&r, ctx_a.to_context());
        let e_b = hash(&r, ctx_b.to_context());

        assert!(
            e_a.equals(e_b) == 0,
            "signature challenge must change when message changes"
        );
    }

    #[test]
    fn auth_hash_changes_when_service_or_nonce_changes() {
        let pk = pk_from_seed(100);
        let r = nonce_point_from_seed(200);

        let ctx1 = authentification::Context::new(&pk, b"svcA".to_vec(), b"nonce1".to_vec());
        let ctx2 = authentification::Context::new(&pk, b"svcB".to_vec(), b"nonce1".to_vec());
        let ctx3 = authentification::Context::new(&pk, b"svcA".to_vec(), b"nonce2".to_vec());

        let e1 = hash(&r, ctx1.to_context());
        let e2 = hash(&r, ctx2.to_context());
        let e3 = hash(&r, ctx3.to_context());

        assert!(
            e1.equals(e2) != u64::MAX,
            "auth challenge must change when service changes"
        );
        assert!(
            e1.equals(e3) != u64::MAX,
            "auth challenge must change when server nonce changes"
        );
    }

    // TODO: FIXME: This test could be better
    #[test]
    fn domain_separation_auth_vs_sig_differs_even_with_same_bytes() {
        // Même si on force service/nonce == message, les tags doivent séparer les domaines.
        let pk = pk_from_seed(7);
        let r = nonce_point_from_seed(8);

        let bytes = b"same payload".to_vec();

        let auth_ctx = authentification::Context::new(&pk, bytes.clone(), bytes.clone());
        let sig_ctx = signature::Context::new(&pk, bytes.clone());

        let e_auth = hash(&r, auth_ctx.to_context());
        let e_sig = hash(&r, sig_ctx.to_context());

        assert!(
            e_auth.equals(e_sig) != u64::MAX,
            "domain separation tags must prevent Auth and Sig transcripts from colliding"
        );
    }

    #[test]
    fn auth_challenge_is_bound_to_public_key() {
        let r = nonce_point_from_seed(4242);
        let msg = b"bind-me".to_vec();

        let ctx_pk1 = authentification::Context::new(&pk_from_seed(1), msg.clone(), msg.clone());
        let ctx_pk2 = authentification::Context::new(&pk_from_seed(2), msg.clone(), msg.clone());

        let e1 = hash(&r, ctx_pk1.to_context());
        let e2 = hash(&r, ctx_pk2.to_context());

        assert!(
            e1.equals(e2) == 0,
            "authentification challenge must depend on the public key"
        );
    }

    #[test]
    fn canonicalization_is_idempotent() {
        // to_canonical_fp5_element(to_canonical_fp5_element(x)) == to_canonical_fp5_element(x)
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
