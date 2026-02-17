use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{
    conversion::ToSignatureField, Credential, Point, Scalar, Signature, LEN_CREDENTIAL, LEN_POINT,
    LEN_SCALAR,
};

pub(crate) struct PrivateInputs<T, TBool> {
    pub(crate) credential: Credential<T>,
    pub(crate) signature: Signature<T, TBool>,
}

/// len(credential) + len(signature.r)
pub const LEN_PRIVATE_INPUTS: usize = LEN_CREDENTIAL + LEN_POINT;

impl PrivateInputs<Target, BoolTarget> {
    pub fn register<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let field_elts: [Target; LEN_PRIVATE_INPUTS] =
            std::array::from_fn(|_| builder.add_virtual_target());
        let s: [BoolTarget; LEN_SCALAR] =
            std::array::from_fn(|_| builder.add_virtual_bool_target_safe());
        Self::from_list(&field_elts, &s)
    }

    pub fn set<F: RichField + Extendable<D>, const D: usize>(
        pw: &mut PartialWitness<F>,
        targets: &PrivateInputs<Target, BoolTarget>,
        values: &PrivateInputs<F, bool>,
    ) -> anyhow::Result<()> {
        let (field_targets, bool_targets) = targets.to_list();
        let (field_values, bool_values) = values.to_list();
        for (target, value) in field_targets.into_iter().zip(field_values.into_iter()) {
            pw.set_target(target, value)?;
        }
        for (target, value) in bool_targets.into_iter().zip(bool_values.into_iter()) {
            pw.set_bool_target(target, value)?;
        }
        Ok(())
    }
}
impl<F: RichField> PrivateInputs<F, bool> {
    pub fn from(
        credential: &crate::core::credential::Credential,
        signature: &crate::schnorr::signature::Signature,
    ) -> Self {
        Self {
            credential: credential.to_field(),
            signature: signature.to_field(),
        }
    }
}

impl<T: Copy, TBool: Copy> PrivateInputs<T, TBool> {
    fn from_list(inputs: &[T; LEN_PRIVATE_INPUTS], bool_inputs: &[TBool; LEN_SCALAR]) -> Self {
        let credential: &[T; LEN_CREDENTIAL] = &inputs[..LEN_CREDENTIAL].try_into().unwrap();
        let r: [T; LEN_POINT] = inputs[LEN_CREDENTIAL..].try_into().unwrap();
        let credential: Credential<T> = credential.into();
        let r: Point<T> = r.into();
        Self {
            credential,
            signature: Signature {
                r,
                s: Scalar(*bool_inputs),
            },
        }
    }

    pub fn to_list(&self) -> ([T; LEN_PRIVATE_INPUTS], [TBool; LEN_SCALAR]) {
        let credential: [T; LEN_CREDENTIAL] = (&self.credential).into();
        let r: [T; LEN_POINT] = self.signature.r.into();
        let s: [TBool; LEN_SCALAR] = self.signature.s.0;
        let mut field_elts = credential.to_vec();
        field_elts.extend_from_slice(r.as_slice());
        let field_elts: [T; LEN_PRIVATE_INPUTS] = field_elts
            .try_into()
            .unwrap_or_else(|_| panic!("Given list don't fit the right length"));
        (field_elts, s)
    }
}
