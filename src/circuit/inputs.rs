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
    bank,
    circuit::{
        authentification::{CircuitBuilderAuthentification, PartialWitnessAuthentification},
        credential::{CircuitBuilderCredential, PartialWitnessCredential},
        curve::PartialWitnessCurve,
        pseudonym::{CircuitBuilderPseudonym, PartialWitnessPseudonym},
        signature::{CircuitBuilderSignature, PartialWitnessSignature},
        string::{CircuitBuilderString, PartialWitnessString},
    },
    core::{credential::Nationality, date::cutoff18_from_today_for_tests},
    encoding::{
        self,
        conversion::{ToPointField, ToSingleField, ToStringField},
        LEN_CREDENTIAL, LEN_POINT, LEN_PSEUDONYM, LEN_STRING,
    },
    issuer,
    schnorr::keys::PublicKey,
};

pub struct Public<T> {
    pub(crate) cutoff18_days: T,
    pub(crate) nationality: T,
    pub(crate) issuer_pk: encoding::Point<T>,
    pub(crate) nonce: encoding::String<T>,
    pub(crate) service: encoding::String<T>,
    pub(crate) pseudonym: encoding::Pseudonym<T>,
}
pub struct Private<T, TBool> {
    pub(crate) credential: encoding::Credential<T, TBool>,
    pub(crate) signature: encoding::Signature<T, TBool>,
    pub(crate) authentification: encoding::Authentification<T, TBool>,
}

pub const LEN_PUBLIC_INPUTS: usize = 1 + 1 + LEN_POINT + LEN_STRING * 2 + LEN_PSEUDONYM;

/// len(credential) + len(signature.r); signature.s is BoolTarget so it's
/// processed differently
pub const LEN_PRIVATE_INPUTS: usize = LEN_CREDENTIAL + LEN_POINT;

/// Registers credential and signature, and registers nationality, issuer,
/// nonce & service as public inputs
pub fn register<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (Public<Target>, Private<Target, BoolTarget>) {
    let credential = builder.add_virtual_credential_target();
    let signature = builder.add_virtual_signature_target();
    let authentification = builder.add_virtual_authentification_target();
    let cutoff18_days = builder.add_virtual_target();
    let nonce = builder.add_virtual_string_target();
    let service = builder.add_virtual_string_target();
    let pseudonym = builder.add_virtual_pseudonym_target();

    builder.register_credential_public_input(credential);
    builder.register_public_input(cutoff18_days);
    builder.register_string_public_input(nonce);
    builder.register_string_public_input(service);
    builder.register_pseudonym_public_input(pseudonym);

    (
        Public {
            cutoff18_days,
            nationality: credential.nationality,
            issuer_pk: credential.issuer,
            nonce,
            service,
            pseudonym,
        },
        Private {
            credential,
            signature,
            authentification,
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
        pw.set_credential_private_target(targets.credential, self.credential)?;
        pw.set_signature_target(targets.signature, self.signature)?;
        pw.set_authentification_target(targets.authentification, self.authentification)
    }
}

impl<F: RichField> Public<F> {
    pub fn set(&self, pw: &mut PartialWitness<F>, targets: &Public<Target>) -> anyhow::Result<()> {
        pw.set_target(targets.nationality, self.nationality)?;
        pw.set_point_target(targets.issuer_pk, self.issuer_pk)?;
        pw.set_target(targets.cutoff18_days, self.cutoff18_days)?;
        pw.set_string_target(targets.nonce, self.nonce)?;
        pw.set_string_target(targets.service, self.service)?;
        pw.set_pseudonym_target(targets.pseudonym, self.pseudonym)
    }

    // TODO: distinguish error from proof verification & public input checks
    pub(crate) fn check(self, proved: &[F]) -> anyhow::Result<()> {
        assert!(proved.len() == LEN_PUBLIC_INPUTS);
        anyhow::ensure!(
            proved[0] == self.nationality,
            "public inputs mismatch for nationality"
        );
        let mut start = 1;
        let mut end = start + LEN_POINT;
        {
            let value: [F; LEN_POINT] = proved[start..end].try_into().unwrap();
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
        start = LEN_POINT + 2;
        end = start + LEN_STRING;
        {
            let value: [F; LEN_STRING] = proved[start..end].try_into().unwrap();
            let value: encoding::String<F> = encoding::String(value);
            anyhow::ensure!(value == self.nonce, "public inputs mismatch for nonce");
        }
        start = end;
        end = start + LEN_STRING;
        {
            let value: [F; LEN_STRING] = proved[start..end].try_into().unwrap();
            let value: encoding::String<F> = encoding::String(value);
            anyhow::ensure!(value == self.service, "public inputs mismatch for service");
        }
        start = end;
        end = start + LEN_PSEUDONYM;
        {
            let value: [F; LEN_PSEUDONYM] = proved[start..end].try_into().unwrap();
            let value: encoding::Pseudonym<F> = encoding::Pseudonym(value);
            anyhow::ensure!(
                value == self.pseudonym,
                "public inputs mismatch for pseudonym"
            );
        }
        anyhow::ensure!(
            end == LEN_PUBLIC_INPUTS,
            "public inputs mismatch for lengths"
        );
        Ok(())
    }

    // TODO: pseudonym should be given directly and not recomputed (it shouldn’t be computable by the bank)
    pub fn new() -> Self {
        let service = bank::service();
        let client_pk = crate::client::keys::public();
        let pseudonym = issuer::pseudonym::hash_from_service(&service, &client_pk);

        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: Nationality::FR.to_field(),
            issuer_pk: issuer::keys::public().0.to_field(),
            nonce: bank::nonce().to_field(),
            service: service.to_field(),
            pseudonym: (&pseudonym).into(),
        }
    }

    pub fn new_with_pk(issuer_pk: PublicKey) -> Self {
        let service = bank::service();
        let client_pk = crate::client::keys::public();
        let pseudonym = issuer::pseudonym::hash_from_service(&service, &client_pk);
        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: Nationality::FR.to_field(),
            issuer_pk: issuer_pk.0.to_field(),
            nonce: bank::nonce().to_field(),
            service: service.to_field(),
            pseudonym: (&pseudonym).into(),
        }
    }
}
