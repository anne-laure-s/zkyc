// Credential requirements: age > 18, nationality = FR

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuit::private_inputs::PrivateInputs;
use crate::circuit::public_inputs::PublicInputs;
use crate::core::credential::Credential;
use crate::encoding::LEN_CREDENTIAL;
use crate::schnorr::signature::Signature;

pub(crate) mod curve;
pub(crate) mod gfp5;
pub(crate) mod private_inputs;
pub(crate) mod public_inputs;
pub(crate) mod scalar;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub(crate) trait Input<F: RichField + Extendable<D>, const D: usize>: Sized {
    fn from_list(inputs: &[Target]) -> Self;
    fn register(builder: &mut CircuitBuilder<F, D>) -> Self;
    fn set(pw: &mut PartialWitness<F>, targets: Vec<Target>, values: Vec<F>) -> anyhow::Result<()>;
}

pub struct Circuit {
    pub private_inputs: PrivateInputs<Target>,
    pub public_inputs: PublicInputs<Target>,
    pub circuit: CircuitData<F, C, D>,
}

/// Prove that client knows a credential such that:
/// - Nationality = FR,
/// - Age >= 18
/// later : signature check + authentification check + non-revocation check (= is in the list of authorized keys)
pub fn circuit() -> Circuit {
    let config = CircuitConfig::default();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let public_inputs = PublicInputs::<Target>::register(&mut builder);
    let private_inputs = PrivateInputs::<Target>::register(&mut builder);

    // TODO: range check u16 for nat_code?
    builder.connect(
        public_inputs.nationality,
        private_inputs.credential.nationality,
    );

    // check that dob <= cutoff18
    let diff = builder.sub(
        public_inputs.cutoff18_days,
        private_inputs.credential.birth_date,
    );
    // TODO: the range check on dob can be removed when this value is constrained to the credential. For now we leave it, and we ommit the range check on the public input cutoff18
    builder.range_check(private_inputs.credential.birth_date, 32);
    builder.range_check(diff, 32);

    // builder.

    Circuit {
        private_inputs,
        circuit: builder.build::<C>(),
        public_inputs,
    }
}

pub fn witness(
    credential: &Credential,
    signature: &Signature,
    private_inputs: &PrivateInputs<Target>,
) -> anyhow::Result<PartialWitness<F>> {
    let credential: [F; LEN_CREDENTIAL] = (&credential.to_field()).into();
    // let signature: encoding::Signature<F, bool> = signature.to_field();
    let mut pw = PartialWitness::new();
    <PrivateInputs<Target> as Input<F, D>>::set(
        &mut pw,
        private_inputs.to_list().to_vec(),
        // TODO: concat with signature
        credential.to_vec(),
    )?;
    Ok(pw)
}

pub fn prove(
    circuit: &Circuit,
    credential: &Credential,
    signature: &Signature,
    public_inputs: &PublicInputs<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = witness(credential, signature, &circuit.private_inputs)?;
    <PublicInputs<Target> as Input<F, D>>::set(
        &mut pw,
        circuit.public_inputs.to_list().to_vec(),
        public_inputs.to_list().to_vec(),
    )?;
    circuit.circuit.prove(pw)
}

pub fn verify(
    circuit: &CircuitData<F, C, D>,
    proof: ProofWithPublicInputs<F, C, D>,
    public_inputs: &PublicInputs<F>,
) -> anyhow::Result<()> {
    let proved_public_inputs = proof.public_inputs.clone();
    circuit.verify(proof)?;
    public_inputs.check(&proved_public_inputs)
}
