// Unifies signature and authentification code.
// The difference between these two protocol is what is hashed for fiat shamir

use crate::{
    arith::{Point, Scalar},
    schnorr::{
        keys::SecretKey,
        transcript::{hash, Context},
    },
};

// TODO: faire de la signature une schnorr proof plutôt que l’inverse
pub struct SchnorrProof {
    r: Point,
    s: Scalar,
}

impl SchnorrProof {
    /// returns a proof of knowledge of a secret key for the corresponding public key
    pub fn prove(sk: &SecretKey, ctx: Context) -> Self {
        // TODO: handle the error more carefully
        let k = Scalar::random().unwrap();
        let r = Point::mulgen(k);
        let e = hash(&r, ctx);
        let s = k + (sk.0 * e);
        assert!(s.iszero() == 0);
        Self { r, s }
    }

    /// verifies the signature produced by sign for the given message
    pub fn verify(&self, ctx: Context) -> bool {
        assert!(self.s.iszero() == 0);
        let pk = ctx.public_key().0;
        let e = hash(&self.r, ctx);
        let gs = Point::mulgen(self.s);
        let gr = self.r + (pk * e);
        gs.equals(gr) == u64::MAX
    }
}
