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

    use crate::circuit::{circuit, inputs, prove, verify};
    use crate::core::credential::Credential;
    use crate::issuer;
    use crate::schnorr::keys::PublicKey;
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

    #[test]
    fn zk_proof() {
        let mut rng = StdRng::from_os_rng();
        let (sk, credential) = Credential::random(&mut rng);
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&sk, &ctx);
        let circuit = circuit();
        let public_inputs = inputs::Public::new_with_pk(PublicKey::from(&sk));
        let proof = prove(&circuit, &credential, &signature, &public_inputs).unwrap();
        verify(&circuit.circuit, proof, public_inputs).unwrap()
    }
    // #[test]
    // // FIXME: error is thrown by an assert, so I don’t know how to catch it properly for now
    // fn zk_proof_with_wrong_age() {
    //     let mut rng = StdRng::from_os_rng();
    //     let credential = Credential::random_minor(&mut rng);
    //     let ctx = Context::new(&credential);
    //     let signature = Signature::sign(&issuer::keys::secret(), &ctx);
    //     let circuit = circuit();
    //     let public_inputs = inputs::Public::new();
    //     let proof = prove(&circuit, &credential, &signature, &public_inputs).unwrap();
    //     assert!(verify(&circuit.circuit, proof, public_inputs).is_err())
    // }
}
