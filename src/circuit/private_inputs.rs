use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit::Input,
    encoding::{Credential, Signature, LEN_CREDENTIAL},
};

pub(crate) struct PrivateInputs<T> {
    pub(crate) credential: Credential<T>,
    pub(crate) signature: Signature<T>,
}

pub const LEN_PRIVATE_INPUTS: usize = LEN_CREDENTIAL + LEN_SIGNATURE;

impl<F: RichField + Extendable<D>, const D: usize> Input<F, D> for PrivateInputs<Target> {
    fn from_list(inputs: &[Target]) -> Self {
        assert_eq!(inputs.len(), LEN_PRIVATE_INPUTS);
        let credential: &[Target; LEN_CREDENTIAL] = &inputs[..LEN_CREDENTIAL].try_into().unwrap();
        let signature: &[Target; LEN_SIGNATURE] = &inputs[LEN_CREDENTIAL..].try_into().unwrap();
        Self {
            credential: credential.into(),
            signature: signature.into(),
        }
    }
    fn register(builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut res = Vec::with_capacity(LEN_PRIVATE_INPUTS);
        for _ in 0..LEN_PRIVATE_INPUTS {
            let target = builder.add_virtual_target();
            res.push(target)
        }
        <Self as Input<F, D>>::from_list(&res)
    }
    fn set(pw: &mut PartialWitness<F>, targets: Vec<Target>, values: Vec<F>) -> anyhow::Result<()> {
        assert_eq!(values.len(), LEN_PRIVATE_INPUTS);
        assert_eq!(targets.len(), LEN_PRIVATE_INPUTS);
        for (target, &value) in targets.into_iter().zip(values.iter()) {
            pw.set_target(target, value)?;
        }
        Ok(())
    }
}

impl<T: Copy> PrivateInputs<T> {
    pub fn to_list(&self) -> [T; LEN_PRIVATE_INPUTS] {
        let credential: [T; LEN_CREDENTIAL] = (&self.credential).into();
        let signature: [T; LEN_SIGNATURE] = (&self.signature).into();
        let mut res = credential.to_vec();
        res.extend_from_slice(signature.as_slice());
        res.try_into()
            .unwrap_or_else(|_| panic!("Given list don't fit the right length"))
    }
}

// impl PrivateInputs<Target> {
//     pub fn witness<F: RichField>(&self, credential: &credential::Credential) -> anyhow::Result<PartialWitness<F>>  {
//         let mut pw = PartialWitness::new();
//         pw.set_target(
//             self.nat_code,
//             F::from_canonical_u16(credential.nationality().code()),
//         )?;
//         pw.set_target(
//             self.dob_days,
//             F::from_canonical_u32(days_from_origin(*credential.birth_date())),
//         )?;
//         Ok(pw)}
// }
