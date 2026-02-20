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
        curve::{CircuitBuilderCurve, PartialWitnessCurve},
        passport_number::{CircuitBuilderPassportNumber, PartialWitnessPassportNumber},
        string::{CircuitBuilderString, PartialWitnessString},
    },
    encoding::{self, conversion::FromBool},
};

pub type CredentialTarget = encoding::Credential<Target, BoolTarget>;

impl FromBool<Target> for BoolTarget {
    fn from_bool(self) -> Target {
        self.target
    }
}

pub trait CircuitBuilderCredential<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_credential_target(&mut self) -> CredentialTarget;
    /// Registers nationnality and issuer as public_input
    fn register_credential_public_input(&mut self, c: CredentialTarget);
}
pub trait PartialWitnessCredential<F: RichField>: Witness<F> {
    fn get_credential_target(&self, target: CredentialTarget) -> encoding::Credential<F, bool>;
    fn set_credential_target(
        &mut self,
        target: CredentialTarget,
        value: encoding::Credential<F, bool>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCredential<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_credential_target(&mut self) -> CredentialTarget {
        CredentialTarget {
            first_name: self.add_virtual_string_target(),
            family_name: self.add_virtual_string_target(),
            place_of_birth: self.add_virtual_string_target(),
            passport_number: self.add_virtual_passport_number_target(),
            birth_date: self.add_virtual_target(),
            expiration_date: self.add_virtual_target(),
            gender: self.add_virtual_bool_target_safe(),
            nationality: self.add_virtual_target(),
            issuer: self.add_virtual_point_target(),
        }
    }
    fn register_credential_public_input(&mut self, c: CredentialTarget) {
        self.register_public_input(c.nationality);
        self.register_point_public_input(c.issuer);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessCredential<F> for W {
    fn get_credential_target(&self, target: CredentialTarget) -> encoding::Credential<F, bool> {
        encoding::Credential {
            first_name: self.get_string_target(target.first_name),
            family_name: self.get_string_target(target.family_name),
            place_of_birth: self.get_string_target(target.place_of_birth),
            passport_number: self.get_passport_number_target(target.passport_number),
            birth_date: self.get_target(target.birth_date),
            expiration_date: self.get_target(target.expiration_date),
            gender: self.get_bool_target(target.gender),
            nationality: self.get_target(target.nationality),
            issuer: self.get_point_target(target.issuer),
        }
    }
    fn set_credential_target(
        &mut self,
        target: CredentialTarget,
        value: encoding::Credential<F, bool>,
    ) -> anyhow::Result<()> {
        self.set_string_target(target.first_name, value.first_name)?;
        self.set_string_target(target.family_name, value.family_name)?;
        self.set_string_target(target.place_of_birth, value.place_of_birth)?;
        self.set_passport_number_target(target.passport_number, value.passport_number)?;
        self.set_target(target.birth_date, value.birth_date)?;
        self.set_target(target.expiration_date, value.expiration_date)?;
        self.set_bool_target(target.gender, value.gender)?;
        self.set_target(target.nationality, value.nationality)?;
        self.set_point_target(target.issuer, value.issuer)
    }
}
