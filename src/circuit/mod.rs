// Credential requirements: age > 18, nationality = FR

use plonky2::iop::target::BoolTarget;
use plonky2::{
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuit::authentification::{
    AuthentificationContextTarget, CircuitBuilderAuthentification,
};
use crate::circuit::signature::CircuitBuilderSignature;
use crate::core::credential::Credential;
use crate::encoding::conversion::{ToAuthentificationField, ToSignatureField};
use crate::encoding::{LEN_POINT, LEN_PSEUDONYM, LEN_STRING};
use crate::schnorr::authentification::Authentification;
use crate::schnorr::signature::Signature;

pub mod authentification;
pub mod credential;
pub mod curve;
pub mod gfp5;
pub mod hash;
pub mod inputs;
pub mod merkle;
pub mod passport_number;
pub mod scalar;
pub mod schnorr;
pub mod signature;
pub mod string;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub struct Circuit {
    pub private_inputs: inputs::Private<Target, BoolTarget>,
    pub public_inputs: inputs::Public<Target>,
    pub circuit: CircuitData<F, C, D>,
}
pub struct Builder {
    pub(crate) builder: CircuitBuilder<F, D>,
    pub(crate) public_inputs: inputs::Public<Target>,
    pub(crate) private_inputs: inputs::Private<Target, BoolTarget>,
}

impl Builder {
    /// Setups builder & inputs
    pub(crate) fn setup() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let (public_inputs, private_inputs) = inputs::register(&mut builder);
        Self {
            builder,
            public_inputs,
            private_inputs,
        }
    }
    pub(crate) fn build(self) -> Circuit {
        Circuit {
            private_inputs: self.private_inputs,
            circuit: self.builder.build::<C>(),
            public_inputs: self.public_inputs,
        }
    }

    pub(crate) fn check_majority(&mut self) {
        // check that dob <= cutoff18
        let diff = self.builder.sub(
            self.public_inputs.cutoff18_days,
            self.private_inputs.credential.birth_date,
        );
        // TODO: the range check on dob can be removed when this value is constrained to the credential. For now we leave it, and we ommit the range check on the public input cutoff18
        self.builder
            .range_check(self.private_inputs.credential.birth_date, 32);
        self.builder.range_check(diff, 32);
    }

    pub(crate) fn check_signature(&mut self) {
        self.builder.verify_signature(
            &self.private_inputs.credential,
            &self.private_inputs.signature,
        )
    }

    pub(crate) fn check_authentification(&mut self) {
        let ctx = AuthentificationContextTarget {
            public_key: self.private_inputs.credential.public_key,
            nonce: self.public_inputs.nonce,
            service: self.public_inputs.service,
        };
        self.builder
            .verify_authentification(&ctx, &self.private_inputs.authentification);
    }

    pub(crate) fn check_pseudonym(&mut self) {
        let mut to_hash: Vec<Target> = Vec::with_capacity(LEN_STRING + LEN_POINT);
        to_hash.extend_from_slice(&self.public_inputs.service.0);
        let public_key: [Target; LEN_POINT] = self.private_inputs.credential.public_key.into();
        to_hash.extend_from_slice(&public_key);
        let got = self.builder.hash_n_to_hash_no_pad::<PoseidonHash>(to_hash);
        for i in 0..LEN_PSEUDONYM {
            self.builder
                .connect(got.elements[i], self.public_inputs.pseudonym.0[i]);
        }
    }
}

/// Prove that client knows a credential such that:
/// - Nationality = FR,
/// - Age >= 18
/// - Signed by issuer
/// later : authentification check + non-revocation check (= is in the list of authorized keys)
pub fn circuit() -> Circuit {
    let mut builder = Builder::setup();
    builder.check_majority();
    builder.check_signature();
    builder.check_authentification();
    builder.check_pseudonym();
    builder.build()
}

pub fn witness(
    credential: &Credential,
    signature: &Signature,
    authentification: &Authentification,
    private_inputs: &inputs::Private<Target, BoolTarget>,
) -> anyhow::Result<PartialWitness<F>> {
    let mut pw = PartialWitness::new();
    let values = inputs::Private {
        credential: credential.to_field(),
        signature: signature.to_field(),
        authentification: authentification.to_field(),
    };
    values.set(&mut pw, private_inputs)?;
    Ok(pw)
}

pub fn prove(
    circuit: &Circuit,
    credential: &Credential,
    signature: &Signature,
    authentification: &Authentification,
    public_inputs: &inputs::Public<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = witness(
        credential,
        signature,
        authentification,
        &circuit.private_inputs,
    )?;
    public_inputs.set(&mut pw, &circuit.public_inputs)?;
    circuit.circuit.prove(pw)
}

pub fn verify(
    circuit: &CircuitData<F, C, D>,
    proof: ProofWithPublicInputs<F, C, D>,
    public_inputs: inputs::Public<F>,
) -> anyhow::Result<()> {
    let proved_public_inputs = proof.public_inputs.clone();
    circuit.verify(proof)?;
    public_inputs.check(&proved_public_inputs)
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;
    use rand::{rngs::StdRng, SeedableRng};

    use super::{circuit, inputs, prove, verify, F};
    use crate::{
        bank,
        circuit::Circuit,
        client,
        core::{credential::Credential, date::cutoff18_from_today_for_tests},
        encoding::conversion::{ToPointField, ToSingleField, ToStringField},
        issuer,
        issuer::pseudonym,
        schnorr::{
            authentification::{Authentification, Context as AuthentificationContext},
            keys::SecretKey,
            signature::{Context as SignatureContext, Signature},
        },
    };

    fn matching_public_inputs(credential: &Credential) -> inputs::Public<F> {
        let service = bank::service();
        inputs::Public {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: credential.nationality().to_field(),
            issuer_pk: credential.issuer().0.to_field(),
            nonce: bank::nonce().to_field(),
            service: service.to_field(),
            pseudonym: pseudonym::hash_from_service(&service, &credential.public_key()),
        }
    }

    fn valid_credential_signature_and_authentification(
        rng: &mut StdRng,
    ) -> (Credential, Signature, Authentification) {
        let (client_sk, issuer_sk, credential) = Credential::random(rng);
        let signature = Signature::sign(&issuer_sk, &SignatureContext::new(&credential));
        let service = bank::service();
        let nonce = bank::nonce();
        let auth_ctx = AuthentificationContext::new(
            &credential.public_key(),
            service.as_bytes(),
            nonce.as_bytes(),
        );
        let authentification = Authentification::sign(&client_sk, &auth_ctx);
        (credential, signature, authentification)
    }

    fn default_authentification() -> Authentification {
        let sk = client::keys::secret();
        let pk = crate::schnorr::keys::PublicKey::from(&sk);
        let ctx = AuthentificationContext::new(&pk, b"any-service", b"any-nonce");
        Authentification::sign(&sk, &ctx)
    }
    fn circuit_without_signature() -> Circuit {
        let mut builder = super::Builder::setup();
        builder.check_majority();
        builder.check_signature();
        builder.build()
    }

    #[test]
    fn prove_and_verify_accept_matching_inputs() {
        let mut rng = StdRng::seed_from_u64(1);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit();

        let proof = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        )
        .unwrap();
        verify(&c.circuit, proof, public_inputs).unwrap();
    }

    #[test]
    fn prove_rejects_wrong_issuer_public_input() {
        let mut rng = StdRng::seed_from_u64(2);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let mut public_inputs = matching_public_inputs(&credential);
        let wrong_issuer_sk = SecretKey::random(&mut rng);
        public_inputs.issuer_pk = crate::schnorr::keys::PublicKey::from(&wrong_issuer_sk)
            .0
            .to_field();

        let c = circuit_without_signature();
        let result = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn prove_rejects_wrong_nationality_public_input() {
        let mut rng = StdRng::seed_from_u64(3);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let mut public_inputs = matching_public_inputs(&credential);
        public_inputs.nationality = F::from_canonical_u64(251);

        let c = circuit_without_signature();
        let result = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn prove_rejects_wrong_pseudonym_public_input() {
        let mut rng = StdRng::seed_from_u64(33);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let mut public_inputs = matching_public_inputs(&credential);
        public_inputs.pseudonym.0[0] += F::ONE;

        let c = circuit();
        let result = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_mismatched_public_inputs() {
        let mut rng = StdRng::seed_from_u64(4);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        )
        .unwrap();

        let mut wrong_public_inputs = matching_public_inputs(&credential);
        wrong_public_inputs.cutoff18_days += F::ONE;
        let result = verify(&c.circuit, proof, wrong_public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_issuer_publc_input() {
        let mut rng = StdRng::seed_from_u64(7);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        )
        .unwrap();

        let mut wrong_public_inputs = matching_public_inputs(&credential);
        let wrong_issuer_sk = SecretKey::random(&mut rng);
        wrong_public_inputs.issuer_pk = crate::schnorr::keys::PublicKey::from(&wrong_issuer_sk)
            .0
            .to_field();

        let result = verify(&c.circuit, proof, wrong_public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_nationality_public_input() {
        let mut rng = StdRng::seed_from_u64(8);
        let (credential, signature, authentification) =
            valid_credential_signature_and_authentification(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        )
        .unwrap();

        let mut wrong_public_inputs = matching_public_inputs(&credential);
        wrong_public_inputs.nationality = F::from_canonical_u64(251);

        let result = verify(&c.circuit, proof, wrong_public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn prove_rejects_underage_credential() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let mut rng = StdRng::seed_from_u64(5);
        let credential = Credential::random_minor(&mut rng);
        let ctx = SignatureContext::new(&credential);
        let signature = Signature::sign(&issuer::keys::secret(), &ctx);
        let authentification = default_authentification();
        let c = circuit_without_signature();
        let public_inputs = inputs::Public::new();

        let result = catch_unwind(AssertUnwindSafe(|| {
            prove(
                &c,
                &credential,
                &signature,
                &authentification,
                &public_inputs,
            )
        }));
        assert!(result.is_err());
    }

    #[test]
    fn prove_rejects_signature_with_wrong_secret() {
        let mut rng = StdRng::seed_from_u64(6);
        let issuer_sk = issuer::keys::secret();
        let credential = Credential::random_with_issuer(&issuer_sk, &mut rng);
        let wrong_signing_sk = SecretKey::random(&mut rng);
        let ctx = SignatureContext::new(&credential);
        let signature = Signature::sign(&wrong_signing_sk, &ctx);
        let authentification = default_authentification();
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit();

        let result = prove(
            &c,
            &credential,
            &signature,
            &authentification,
            &public_inputs,
        );
        assert!(result.is_err());
    }
}
