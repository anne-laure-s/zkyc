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
    core::{credential::Nationality, date::cutoff18_from_today_for_tests},
    encoding::{
        conversion::{ToPointField, ToSingleField},
        Point, LEN_FIELD, LEN_POINT,
    },
    issuer,
};

pub const LEN_PUBLIC_INPUTS: usize = 22;

pub struct PublicInputs<T> {
    pub(crate) cutoff18_days: T,
    pub(crate) nationality: T,
    pub(crate) issuer_pk: Point<T>,
}

impl<F: RichField + Extendable<D>, const D: usize> Input<F, D> for PublicInputs<Target> {
    fn from_list(public_inputs: &[Target]) -> Self {
        let x: [Target; LEN_FIELD] = public_inputs[2..7].try_into().unwrap();
        let z: [Target; LEN_FIELD] = public_inputs[7..12].try_into().unwrap();
        let u: [Target; LEN_FIELD] = public_inputs[12..17].try_into().unwrap();
        let t: [Target; LEN_FIELD] = public_inputs[17..22].try_into().unwrap();
        PublicInputs {
            nationality: public_inputs[0],
            cutoff18_days: public_inputs[1],
            issuer_pk: Point { x, z, u, t },
        }
    }
    fn register(builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut res = Vec::with_capacity(LEN_PUBLIC_INPUTS);
        for _ in 0..LEN_PUBLIC_INPUTS {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            res.push(target)
        }
        <Self as Input<F, D>>::from_list(&res)
    }
    fn set(pw: &mut PartialWitness<F>, targets: Vec<Target>, values: Vec<F>) -> anyhow::Result<()> {
        assert_eq!(values.len(), LEN_PUBLIC_INPUTS);
        assert_eq!(targets.len(), LEN_PUBLIC_INPUTS);
        for (target, &value) in targets.into_iter().zip(values.iter()) {
            pw.set_target(target, value)?;
        }
        Ok(())
    }
}

impl<T: Copy> PublicInputs<T> {
    pub fn to_list(&self) -> [T; LEN_PUBLIC_INPUTS] {
        let mut res = vec![self.nationality, self.cutoff18_days];
        let issuer: [T; LEN_POINT] = (&self.issuer_pk).into();
        res.extend(issuer);
        // TODO: this error should not happen if the public inputs are
        // correct, but the check should be done more properly
        res.try_into()
            .unwrap_or_else(|_| panic!("wrong public input length"))
    }
}

impl<F: RichField> PublicInputs<F> {
    pub fn new() -> Self {
        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nationality: Nationality::FR.to_field(),
            issuer_pk: issuer::keys::public().0.to_field(),
        }
    }
    // TODO: distinguish error from proof verification & public input checks
    pub(crate) fn check(&self, proved: &[F]) -> anyhow::Result<()> {
        assert!(proved.len() == LEN_PUBLIC_INPUTS);
        let expected = self.to_list();
        for (&proved, &expected) in proved.iter().zip(expected.iter()) {
            anyhow::ensure!(proved == expected, "public inputs mismatch");
        }
        Ok(())
    }
}
