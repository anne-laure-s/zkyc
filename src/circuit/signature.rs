use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit::{
        credential::CredentialTarget,
        curve::{CircuitBuilderCurve, PartialWitnessCurve, PointTarget},
        scalar::{CircuitBuilderScalar, PartialWitnessScalar, ScalarTarget},
    },
    encoding::{Signature, LEN_CREDENTIAL, LEN_POINT, LEN_SCALAR},
};

pub type SignatureTarget = Signature<Target, BoolTarget>;

pub trait CircuitBuilderSignature<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_signature_target(&mut self) -> SignatureTarget;
    fn register_signature_public_input(&mut self, s: SignatureTarget);
    fn hash(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) -> ScalarTarget;
    fn verify(&mut self, credential: &CredentialTarget, signature: &SignatureTarget);
}
pub trait PartialWitnessSignature<F: RichField>: Witness<F> {
    fn get_signature_target(&self, target: SignatureTarget) -> crate::encoding::Signature<F, bool>;
    fn set_signature_target(
        &mut self,
        target: SignatureTarget,
        value: crate::encoding::Signature<F, bool>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSignature<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_signature_target(&mut self) -> SignatureTarget {
        SignatureTarget {
            r: self.add_virtual_point_target(),
            s: self.add_virtual_scalar_target(),
        }
    }
    fn register_signature_public_input(&mut self, s: SignatureTarget) {
        self.register_point_public_input(s.r);
        self.register_scalar_public_input(s.s);
    }
    fn hash(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) -> ScalarTarget {
        let base_inputs: [Target; LEN_POINT] = signature.r.into();
        let credential_input: [Target; LEN_CREDENTIAL] = credential.into();
        let mut base_inputs = base_inputs.to_vec();

        base_inputs.extend_from_slice(&credential_input);

        let mut bits: Vec<BoolTarget> = Vec::with_capacity(LEN_SCALAR);

        // h0
        let h0: HashOutTarget = self.hash_n_to_hash_no_pad::<PoseidonHash>(base_inputs);
        for i in 0..4 {
            bits.extend(self.split_le(h0.elements[i], 64));
        }

        // secondary hash

        let mut ctr = F::ONE;
        while bits.len() < LEN_SCALAR {
            let ctr_t = self.constant(ctr);

            let mut inp = vec![ctr_t];
            inp.extend_from_slice(&h0.elements); // 4 mots

            let hi: HashOutTarget = self.hash_n_to_hash_no_pad::<PoseidonHash>(inp);
            for i in 0..4 {
                bits.extend(self.split_le(hi.elements[i], 64));
            }
            ctr += F::ONE;
        }

        bits.truncate(LEN_SCALAR);
        let bits: [BoolTarget; LEN_SCALAR] = bits.try_into().unwrap();
        bits.into()
    }
    fn verify(&mut self, credential: &CredentialTarget, signature: &SignatureTarget) {
        let pk = credential.issuer;
        let e = self.hash(credential, signature);
        self.schnorr_final_verification(signature.s, e, pk, signature.r);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessSignature<F> for W {
    fn get_signature_target(&self, target: SignatureTarget) -> crate::encoding::Signature<F, bool> {
        crate::encoding::Signature {
            r: self.get_point_target(target.r),
            s: self.get_scalar_target(target.s),
        }
    }
    fn set_signature_target(
        &mut self,
        target: SignatureTarget,
        value: crate::encoding::Signature<F, bool>,
    ) -> anyhow::Result<()> {
        self.set_point_target(target.r, value.r)?;
        self.set_scalar_target(target.s, value.s)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        circuit::{
            credential::{CircuitBuilderCredential, PartialWitnessCredential},
            curve::tests::check_public_input_point,
        },
        core::credential,
        encoding::{
            conversion::{ToPointField, ToSignatureField},
            Point, LEN_FIELD,
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
        assert_ne!(s1.r.x.0[0], s2.r.x.0[0]);
        assert_ne!(s1.s.0[0].target, s2.s.0[0].target);
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
        let expected = 20 + crate::arith::Scalar::NB_BITS;

        assert_eq!(data.common.num_public_inputs, expected);
    }

    #[test]
    fn test_set_get_signature_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let sig_t = builder.add_virtual_signature_target();
        builder.register_signature_public_input(sig_t);

        // --- build a concrete signature value (r,s) ---
        // Use a simple non-zero scalar (bit 0 and bit 5 set).
        let mut bits = [false; crate::arith::Scalar::NB_BITS];
        bits[0] = true;
        bits[5] = true;
        let s_native = crate::encoding::Scalar(bits);

        // A simple point encoding
        let r_native: Point<F> = crate::arith::Point::GENERATOR.to_field();

        let sig_native = crate::encoding::Signature {
            r: r_native,
            s: s_native,
        };

        // --- set then get ---
        let mut pw = PartialWitness::<F>::new();
        pw.set_signature_target(sig_t, sig_native).unwrap();

        let got = pw.get_signature_target(sig_t);

        // Compare scalar
        for (s, n) in got.s.0.iter().zip(sig_native.s.0.iter()) {
            assert_eq!(s, n);
        }

        // Compare point limbs
        for i in 0..LEN_FIELD {
            assert_eq!(got.r.x.0[i], sig_native.r.x.0[i]);
            assert_eq!(got.r.z.0[i], sig_native.r.z.0[i]);
            assert_eq!(got.r.u.0[i], sig_native.r.u.0[i]);
            assert_eq!(got.r.t.0[i], sig_native.r.t.0[i]);
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

        builder.register_issuer_public_input(credential_t);

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
            schnorr::transcript::hash(&sig0.0.r, schnorr::transcript::Context::Sig(&ctx));

        let public_inputs: [F; LEN_SCALAR] = proof.public_inputs.try_into().unwrap();
        let e_circuit = crate::arith::Scalar::from_bits_le(&public_inputs.map(|x| F::is_one(&x)));
        assert!(e_native.equals(e_circuit) == u64::MAX)
    }
}
