pub(crate) mod arith;
pub(crate) mod bank;
pub(crate) mod circuit;
pub(crate) mod client;
pub(crate) mod core;
pub(crate) mod encoding;
pub(crate) mod issuer;
pub(crate) mod schnorr;

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::core::credential::Credential;
    use crate::schnorr::{signature::Context, signature::Signature};

    #[test]
    fn it_works() {
        let mut rng = StdRng::from_os_rng();
        let (sk, credential) = Credential::random(&mut rng);
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&sk, &ctx);
        let b = signature.verify(&ctx);
        assert!(b)
    }
}
