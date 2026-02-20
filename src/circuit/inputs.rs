use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit::{
        credential::CircuitBuilderCredential, curve::PartialWitnessCurve,
        passport_number::PartialWitnessPassportNumber, scalar::PartialWitnessScalar,
        signature::CircuitBuilderSignature, string::PartialWitnessString,
    },
    core::{credential::Nationality, date::cutoff18_from_today_for_tests},
    encoding::{
        self,
        conversion::{ToPointField, ToSingleField},
        LEN_CREDENTIAL, LEN_POINT,
    },
    issuer,
    schnorr::keys::PublicKey,
};

pub struct Public<T> {
    pub(crate) cutoff18_days: T,
    pub(crate) nationality: T,
    pub(crate) issuer_pk: encoding::Point<T>,
}
pub(crate) struct Private<T, TBool> {
    pub(crate) credential: encoding::Credential<T, TBool>,
    pub(crate) signature: encoding::Signature<T, TBool>,
}

pub const LEN_PUBLIC_INPUTS: usize = 1 + 1 + LEN_POINT;

/// len(credential) + len(signature.r); signature.s is BoolTarget so it's
/// processed differently
pub const LEN_PRIVATE_INPUTS: usize = LEN_CREDENTIAL + LEN_POINT;

/// Registers credential and signature, and registers nationality and
/// issuer as public inputs
pub fn register<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (Public<Target>, Private<Target, BoolTarget>) {
    let credential = builder.add_virtual_credential_target();
    builder.register_credential_public_input(credential);
    let signature = builder.add_virtual_signature_target();
    let cutoff18_days = builder.add_virtual_target();
    builder.register_public_input(cutoff18_days);
    (
        Public {
            cutoff18_days,
            nationality: credential.nationality,
            issuer_pk: credential.issuer,
        },
        Private {
            credential,
            signature,
        },
    )
}
impl<F: RichField> Private<F, bool> {
    /// Ommits public inputs
    pub fn set(
        &self,
        pw: &mut PartialWitness<F>,
        targets: &Private<Target, BoolTarget>,
    ) -> anyhow::Result<()> {
        // credential
        {
            pw.set_string_target(targets.credential.first_name, self.credential.first_name)?;
            pw.set_string_target(targets.credential.family_name, self.credential.family_name)?;
            pw.set_string_target(
                targets.credential.place_of_birth,
                self.credential.place_of_birth,
            )?;
            pw.set_passport_number_target(
                targets.credential.passport_number,
                self.credential.passport_number,
            )?;
            pw.set_target(targets.credential.birth_date, self.credential.birth_date)?;
            pw.set_target(
                targets.credential.expiration_date,
                self.credential.expiration_date,
            )?;
            pw.set_bool_target(targets.credential.gender, self.credential.gender)?;
        }
        // signature
        {
            pw.set_point_target(targets.signature.r, self.signature.r)?;
            pw.set_scalar_target(targets.signature.s, self.signature.s)?;
        }
        Ok(())
    }
}

impl<F: RichField> Public<F> {
    pub fn set(&self, pw: &mut PartialWitness<F>, targets: &Public<Target>) -> anyhow::Result<()> {
        pw.set_target(targets.nationality, self.nationality)?;
        pw.set_point_target(targets.issuer_pk, self.issuer_pk)?;
        pw.set_target(targets.cutoff18_days, self.cutoff18_days)?;

        Ok(())
    }

    // TODO: distinguish error from proof verification & public input checks
    pub(crate) fn check(self, proved: &[F]) -> anyhow::Result<()> {
        assert!(proved.len() == LEN_PUBLIC_INPUTS);
        anyhow::ensure!(
            proved[0] == self.nationality,
            "public inputs mismatch for nationality"
        );
        {
            let value: [F; LEN_POINT] = proved[1..LEN_POINT + 1].try_into().unwrap();
            let value: encoding::Point<F> = value.into();
            anyhow::ensure!(
                value == self.issuer_pk,
                "public inputs mismatch for issuer_pk"
            );
        }
        anyhow::ensure!(
            proved[LEN_POINT + 1] == self.cutoff18_days,
            "public inputs mismatch for cutoff18_days"
        );
        Ok(())
    }

    pub fn new() -> Self {
        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: Nationality::FR.to_field(),
            issuer_pk: issuer::keys::public().0.to_field(),
        }
    }

    pub fn new_with_pk(issuer_pk: PublicKey) -> Self {
        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: Nationality::FR.to_field(),
            issuer_pk: issuer_pk.0.to_field(),
        }
    }
}
