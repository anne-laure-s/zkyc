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
        Point, LEN_EXTENSION_FIELD,
    },
    issuer,
};

pub const LEN_PUBLIC_INPUTS: usize = 22;

pub struct PublicInputs<T> {
    pub cutoff18_days: T,
    pub nat_code: T,
    pub issuer_pk: Point<T>,
}

impl<T: Copy> PublicInputs<T> {
    pub fn to_list(&self) -> [T; LEN_PUBLIC_INPUTS] {
        let mut res = vec![self.nat_code, self.cutoff18_days];
        for &i in self
            .issuer_pk
            .x
            .iter()
            .chain(self.issuer_pk.z.iter())
            .chain(self.issuer_pk.u.iter())
            .chain(self.issuer_pk.t.iter())
        {
            res.push(i)
        }
        // TODO: this error should not happen if the public inputs are
        // correct, but the check should be done more properly
        res.try_into()
            .unwrap_or_else(|_| panic!("wrong public input length"))
    }

    pub fn from_list(public_inputs: &[T; LEN_PUBLIC_INPUTS]) -> Self {
        let x: [T; LEN_EXTENSION_FIELD] = public_inputs[2..7].try_into().unwrap();
        let z: [T; LEN_EXTENSION_FIELD] = public_inputs[7..12].try_into().unwrap();
        let u: [T; LEN_EXTENSION_FIELD] = public_inputs[12..17].try_into().unwrap();
        let t: [T; LEN_EXTENSION_FIELD] = public_inputs[17..22].try_into().unwrap();
        PublicInputs {
            nat_code: public_inputs[0],
            cutoff18_days: public_inputs[1],
            issuer_pk: Point { x, z, u, t },
        }
    }
}

impl<F: RichField> PublicInputs<F> {
    pub fn new() -> Self {
        Self {
            cutoff18_days: cutoff18_from_today_for_tests().to_field(),
            nat_code: Nationality::FR.to_field(),
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

impl PublicInputs<Target> {
    pub(crate) fn register<const D: usize, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut res = Vec::with_capacity(LEN_PUBLIC_INPUTS);
        for _ in 0..LEN_PUBLIC_INPUTS {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            res.push(target)
        }
        // TODO: more graceful error
        Self::from_list(&res.try_into().unwrap_or_else(|_| panic!()))
    }

    pub(crate) fn set<const D: usize, F: RichField + Extendable<D>>(
        &self,
        pw: &mut PartialWitness<F>,
        values: &PublicInputs<F>,
    ) -> anyhow::Result<()> {
        let targets = self.to_list();
        let values = values.to_list();
        for (target, &value) in targets.into_iter().zip(values.iter()) {
            pw.set_target(target, value)?;
        }
        Ok(())
    }
}
