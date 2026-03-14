pub mod arith;
pub mod bank;
pub mod circuit;
pub mod client;
pub mod core;
pub mod encoding;
pub mod issuer;
pub mod merkle;
pub mod schnorr;

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::core::credential::Credential;
    use crate::schnorr::{signature::Context, signature::Signature};

    #[test]
    fn it_works() {
        let mut rng = StdRng::from_os_rng();
        let (_, sk, credential) = Credential::random(&mut rng);
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&sk, &ctx);
        let b = signature.verify(&ctx);
        assert!(b)
    }
}
