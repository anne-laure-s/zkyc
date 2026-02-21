use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit::{
        credential::CredentialTarget,
        scalar::ScalarTarget,
        schnorr::{CircuitBuilderSchnorr, PartialWitnessSchnorr},
    },
    encoding::{self, LEN_CREDENTIAL},
};

pub type SignatureTarget = encoding::Signature<Target, BoolTarget>;

pub trait CircuitBuilderSignature<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_signature_target(&mut self) -> SignatureTarget;
    fn register_signature_public_input(&mut self, target: SignatureTarget);
    fn hash(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) -> ScalarTarget;
    fn verify(&mut self, credential: &CredentialTarget, signature: &SignatureTarget);
}
pub trait PartialWitnessSignature<F: RichField>: Witness<F> {
    fn get_signature_target(&self, target: SignatureTarget) -> encoding::Signature<F, bool>;
    fn set_signature_target(
        &mut self,
        target: SignatureTarget,
        value: encoding::Signature<F, bool>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSignature<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_signature_target(&mut self) -> SignatureTarget {
        encoding::Signature(self.add_virtual_schnorr_target())
    }
    fn register_signature_public_input(&mut self, target: SignatureTarget) {
        self.register_schnorr_public_input(target.0);
    }
    fn hash(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) -> ScalarTarget {
        let credential_input: [Target; LEN_CREDENTIAL] = credential.into();
        self.schnorr_hash_with_message(signature.0, &credential_input)
    }
    fn verify(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) {
        let pk = credential.issuer;
        let e = self.hash(credential, signature);
        self.schnorr_final_verification(signature.0, e, pk, signature.0.r);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessSignature<F> for W {
    fn get_signature_target(&self, target: SignatureTarget) -> encoding::Signature<F, bool> {
        encoding::Signature(self.get_schnorr_target(target.0))
    }
    fn set_signature_target(
        &mut self,
        target: SignatureTarget,
        value: encoding::Signature<F, bool>,
    ) -> anyhow::Result<()> {
        self.set_schnorr_target(target.0, value.0)
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        arith,
        circuit::{
            credential::{CircuitBuilderCredential, PartialWitnessCredential},
            curve::{tests::check_public_input_point, CircuitBuilderCurve},
        },
        core::credential,
        encoding::{
            conversion::{ToPointField, ToSignatureField},
            LEN_FIELD, LEN_SCALAR,
        },
        schnorr::{
            self,
            signature::{self, Context},
        },
    };

    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField as F, types::Field},
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;

    #[test]
    fn test_add_virtual_signature_target_distinct() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let s1 = builder.add_virtual_signature_target();
        let s2 = builder.add_virtual_signature_target();

        // Sanity: the first limb of r.x should differ, and at least one scalar bit should differ.
        assert_ne!(s1.0.r.x.0[0], s2.0.r.x.0[0]);
        assert_ne!(s1.0.s.0[0].target, s2.0.s.0[0].target);
    }

    #[test]
    fn test_register_signature_public_input_count() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let sig = builder.add_virtual_signature_target();
        builder.register_signature_public_input(sig);

        // Build to access the number of public inputs.
        let data = builder.build::<Cfg>();

        // PointTarget = 4 GFp5 = 4*5 = 20 field elements
        // ScalarTarget = Scalar::NB_BITS public inputs (register_scalar_public_input usually registers bits)
        let expected = 20 + arith::Scalar::NB_BITS;

        assert_eq!(data.common.num_public_inputs, expected);
    }

    #[test]
    fn test_set_get_signature_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let sig_t = builder.add_virtual_signature_target();
        builder.register_signature_public_input(sig_t);

        // --- build a concrete signature value (r,s) ---
        // Use a simple non-zero scalar (bit 0 and bit 5 set).
        let mut bits = [false; arith::Scalar::NB_BITS];
        bits[0] = true;
        bits[5] = true;
        let s_native = encoding::Scalar(bits);

        // A simple point encoding
        let r_native: encoding::Point<F> = arith::Point::GENERATOR.to_field();

        let sig_native = encoding::Signature(encoding::SchnorrProof {
            r: r_native,
            s: s_native,
        });

        // --- set then get ---
        let mut pw = PartialWitness::<F>::new();
        pw.set_signature_target(sig_t, sig_native).unwrap();

        let got = pw.get_signature_target(sig_t);

        // Compare scalar
        for (s, n) in got.0.s.0.iter().zip(sig_native.0.s.0.iter()) {
            assert_eq!(s, n);
        }

        // Compare point limbs
        for i in 0..LEN_FIELD {
            assert_eq!(got.0.r.x.0[i], sig_native.0.r.x.0[i]);
            assert_eq!(got.0.r.z.0[i], sig_native.0.r.z.0[i]);
            assert_eq!(got.0.r.u.0[i], sig_native.0.r.u.0[i]);
            assert_eq!(got.0.r.t.0[i], sig_native.0.r.t.0[i]);
        }

        // Finally, proving should succeed since we added no constraints beyond PI wiring.
        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_verify_accepts() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let mut rng = StdRng::from_os_rng();

        let (sk, credential) = credential::Credential::random(&mut rng);
        let ctx = Context::new(&credential);
        let signature = signature::Signature::sign(&sk, &ctx);

        let expected_issuer = credential.issuer().0;
        let credential = credential.to_field();
        let signature = signature.to_field();

        // Targets
        let credential_t = builder.add_virtual_credential_target();
        let signature_t = builder.add_virtual_signature_target();

        builder.register_point_public_input(credential_t.issuer);

        builder.verify(&credential_t, &signature_t);

        // Witness
        let mut pw = PartialWitness::<F>::new();

        pw.set_credential_target(credential_t, credential).unwrap();

        pw.set_signature_target(signature_t, signature).unwrap();

        let data = builder.build::<Cfg>();

        let proof = data.prove(pw).expect("prove should pass");
        data.verify(proof.clone()).expect("verify should pass");
        check_public_input_point(&proof.public_inputs, expected_issuer);
    }

    #[test]
    fn test_hash_e_matches_native() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let mut rng = StdRng::from_os_rng();
        let (sk, credential0) = credential::Credential::random(&mut rng);
        let ctx = Context::new(&credential0);
        let sig0 = signature::Signature::sign(&sk, &ctx);

        let credential = credential0.to_field();
        let sig = sig0.to_field();

        let credential_t = builder.add_virtual_credential_target();
        let sig_t = builder.add_virtual_signature_target();

        // calcule e dans le circuit et expose ses bits
        let e_t = builder.hash(&credential_t, &sig_t);
        for b in e_t.0.iter() {
            builder.register_public_input(b.target);
        }

        let mut pw = PartialWitness::<F>::new();
        pw.set_credential_target(credential_t, credential).unwrap();
        pw.set_signature_target(sig_t, sig).unwrap();

        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).unwrap();

        let e_native =
            schnorr::transcript::hash(&sig0.0.get_nonce(), schnorr::transcript::Context::Sig(&ctx));

        let public_inputs: [F; LEN_SCALAR] = proof.public_inputs.try_into().unwrap();
        let e_circuit = arith::Scalar::from_bits_le(&public_inputs.map(|x| F::is_one(&x)));
        assert!(e_native.equals(e_circuit) == u64::MAX)
    }
}
