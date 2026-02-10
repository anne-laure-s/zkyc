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

    use crate::circuit::PublicInputs;
    use crate::circuit::{circuit, prove, verify};
    use crate::core::credential::Credential;
    use crate::schnorr::{
        keys::{PublicKey, SecretKey},
        signature::Context,
        signature::Signature,
    };

    #[test]
    fn it_works() {
        let mut rng = StdRng::from_os_rng();
        let credential = Credential::random(&mut rng).as_bytes();
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(&sk);
        let ctx = Context::new(&pk, credential);
        let signature = Signature::sign(&sk, &ctx);
        let b = signature.verify(&ctx);
        assert!(b)
    }

    #[test]
    fn zk_proof() {
        let mut rng = StdRng::from_os_rng();
        let credential = Credential::random(&mut rng);
        let circuit = circuit();
        let public_inputs = PublicInputs::new();
        let proof = prove(&circuit, &credential, &public_inputs).unwrap();
        verify(&circuit.circuit, proof, &public_inputs).unwrap()
    }
    // #[test]
    // FIXME: error is thrown by an assert, so I don’t know how to catch it properly for now
    // fn zk_proof_with_wrong_age() {
    //     let mut rng = StdRng::from_os_rng();
    //     let credential = Credential::random_minor(&mut rng);
    //     let circuit = circuit_credential_requirements();
    //     let public_inputs = PublicInputs::new();
    //     let proof = prove_credential_requirements(&circuit, &credential, &public_inputs).unwrap() ;
    //     assert!(verify_credential_requirements(&circuit.circuit, proof, &public_inputs).is_err())
    // }
}
