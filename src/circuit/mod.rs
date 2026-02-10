// Credential requirements: age > 18, nationality = FR

use plonky2::field::types::Field;
use plonky2::{
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuit::public_inputs::PublicInputs;
use crate::core::{credential::Credential, date::days_from_origin};

pub(crate) mod public_inputs;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Copy)]
pub struct PrivateInputs {
    pub nat_code: Target, // private: nationality code (TODO: lookup?)
    pub dob_days: Target, // private: days since ORIGIN
}

pub struct Circuit {
    pub private_inputs: PrivateInputs,
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

    let nat_code = builder.add_virtual_target();
    let dob_days = builder.add_virtual_target();

    let public_inputs = PublicInputs::<Target>::register(&mut builder);

    // TODO: range check u16 for nat_code?
    builder.connect(nat_code, public_inputs.nat_code);

    // check that dob <= cutoff18
    let diff = builder.sub(public_inputs.cutoff18_days, dob_days);
    // TODO: the range check on dob can be removed when this value is constrained to the credential. For now we leave it, and we ommit the range check on the public input cutoff18
    builder.range_check(dob_days, 32);
    builder.range_check(diff, 32);

    let circuit = builder.build::<C>();
    let private_inputs = PrivateInputs { nat_code, dob_days };
    Circuit {
        private_inputs,
        circuit,
        public_inputs,
    }
}

pub fn witness(
    credential: &Credential,
    private_inputs: &PrivateInputs,
) -> anyhow::Result<PartialWitness<F>> {
    let mut pw = PartialWitness::new();
    pw.set_target(
        private_inputs.nat_code,
        F::from_canonical_u16(credential.nationality().code()),
    )?;
    pw.set_target(
        private_inputs.dob_days,
        F::from_canonical_u32(days_from_origin(*credential.birth_date())),
    )?;
    Ok(pw)
}

pub fn prove(
    circuit: &Circuit,
    credential: &Credential,
    public_inputs: &PublicInputs<F>,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = witness(credential, &circuit.private_inputs)?;
    circuit.public_inputs.set::<D, F>(&mut pw, public_inputs)?;
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
