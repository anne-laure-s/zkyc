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

impl PublicInputs<Target> {
    pub fn register<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let res: [Target; LEN_PUBLIC_INPUTS] = std::array::from_fn(|_| {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            target
        });
        Self::from_list(&res)
    }

    pub fn set<F: RichField + Extendable<D>, const D: usize>(
        pw: &mut PartialWitness<F>,
        targets: &PublicInputs<Target>,
        values: &PublicInputs<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in targets
            .to_list()
            .into_iter()
            .zip(values.to_list().into_iter())
        {
            pw.set_target(target, value)?;
        }
        Ok(())
    }
}

impl<T: Copy> PublicInputs<T> {
    fn from_list(public_inputs: &[T; LEN_PUBLIC_INPUTS]) -> Self {
        let x: [T; LEN_FIELD] = public_inputs[2..7].try_into().unwrap();
        let z: [T; LEN_FIELD] = public_inputs[7..12].try_into().unwrap();
        let u: [T; LEN_FIELD] = public_inputs[12..17].try_into().unwrap();
        let t: [T; LEN_FIELD] = public_inputs[17..22].try_into().unwrap();
        PublicInputs {
            nationality: public_inputs[0],
            cutoff18_days: public_inputs[1],
            issuer_pk: Point { x, z, u, t },
        }
    }

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
