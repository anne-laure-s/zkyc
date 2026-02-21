// Credential requirements: age > 18, nationality = FR

use plonky2::iop::target::BoolTarget;
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuit::signature::CircuitBuilderSignature;
use crate::core::credential::Credential;
use crate::encoding::conversion::ToSignatureField;
use crate::schnorr::signature::Signature;

pub(crate) mod authentification;
pub(crate) mod credential;
pub(crate) mod curve;
pub(crate) mod gfp5;
pub(crate) mod inputs;
pub(crate) mod passport_number;
pub(crate) mod scalar;
pub(crate) mod schnorr;
pub(crate) mod signature;
pub(crate) mod string;

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
        self.builder.verify(
            &self.private_inputs.credential,
            &self.private_inputs.signature,
        )
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
    builder.build()
}

pub fn witness(
    credential: &Credential,
    signature: &Signature,
    private_inputs: &inputs::Private<Target, BoolTarget>,
) -> anyhow::Result<PartialWitness<F>> {
    let mut pw = PartialWitness::new();
    let values = inputs::Private {
        credential: credential.to_field(),
        signature: signature.to_field(),
    };
    values.set(&mut pw, private_inputs)?;
    Ok(pw)
}

pub fn prove(
    circuit: &Circuit,
    credential: &Credential,
    signature: &Signature,
    public_inputs: &inputs::Public<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = witness(credential, signature, &circuit.private_inputs)?;
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
        circuit::Circuit,
        core::{credential::Credential, date::cutoff18_from_today_for_tests},
        encoding::conversion::{ToPointField, ToSingleField},
        issuer,
        schnorr::{
            keys::SecretKey,
            signature::{Context, Signature},
        },
    };

    fn matching_public_inputs(credential: &Credential) -> inputs::Public<F> {
        inputs::Public {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: credential.nationality().to_field(),
            issuer_pk: credential.issuer().0.to_field(),
        }
    }

    fn valid_credential_and_signature(rng: &mut StdRng) -> (Credential, Signature) {
        let issuer_sk = issuer::keys::secret();
        let credential = Credential::random_with_issuer(&issuer_sk, rng);
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&issuer_sk, &ctx);
        (credential, signature)
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
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit();

        let proof = prove(&c, &credential, &signature, &public_inputs).unwrap();
        verify(&c.circuit, proof, public_inputs).unwrap();
    }

    #[test]
    fn prove_rejects_wrong_issuer_public_input() {
        let mut rng = StdRng::seed_from_u64(2);
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let mut public_inputs = matching_public_inputs(&credential);
        let wrong_issuer_sk = SecretKey::random(&mut rng);
        public_inputs.issuer_pk = crate::schnorr::keys::PublicKey::from(&wrong_issuer_sk)
            .0
            .to_field();

        let c = circuit_without_signature();
        let result = prove(&c, &credential, &signature, &public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn prove_rejects_wrong_nationality_public_input() {
        let mut rng = StdRng::seed_from_u64(3);
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let mut public_inputs = matching_public_inputs(&credential);
        public_inputs.nationality = F::from_canonical_u64(251);

        let c = circuit_without_signature();
        let result = prove(&c, &credential, &signature, &public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_mismatched_public_inputs() {
        let mut rng = StdRng::seed_from_u64(4);
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(&c, &credential, &signature, &public_inputs).unwrap();

        let mut wrong_public_inputs = matching_public_inputs(&credential);
        wrong_public_inputs.cutoff18_days += F::ONE;
        let result = verify(&c.circuit, proof, wrong_public_inputs);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_issuer_publc_input() {
        let mut rng = StdRng::seed_from_u64(7);
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(&c, &credential, &signature, &public_inputs).unwrap();

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
        let (credential, signature) = valid_credential_and_signature(&mut rng);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit_without_signature();
        let proof = prove(&c, &credential, &signature, &public_inputs).unwrap();

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
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&issuer::keys::secret(), &ctx);
        let c = circuit_without_signature();
        let public_inputs = inputs::Public::new();

        let result = catch_unwind(AssertUnwindSafe(|| {
            prove(&c, &credential, &signature, &public_inputs)
        }));
        assert!(matches!(result, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn prove_rejects_signature_with_wrong_secret() {
        let mut rng = StdRng::seed_from_u64(6);
        let issuer_sk = issuer::keys::secret();
        let credential = Credential::random_with_issuer(&issuer_sk, &mut rng);
        let wrong_signing_sk = SecretKey::random(&mut rng);
        let ctx = Context::new(&credential);
        let signature = Signature::sign(&wrong_signing_sk, &ctx);
        let public_inputs = matching_public_inputs(&credential);
        let c = circuit();

        let result = prove(&c, &credential, &signature, &public_inputs);
        assert!(result.is_err());
    }
}
