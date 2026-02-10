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
    encoding::{conversion::ToPointField, Point},
    issuer,
};

pub struct PublicInputs<T> {
    pub cutoff18_days: T,
    pub nat_code: T,
    pub issuer_pk: Point<T>,
}

impl<T: Copy> PublicInputs<T> {
    pub const LEN: usize = 22;
    pub fn to_list(&self) -> Vec<T> {
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
        res
    }

    pub fn from_list(public_inputs: &[T]) -> Self {
        assert!(public_inputs.len() == Self::LEN);
        let x: [T; 5] = public_inputs[2..7].try_into().unwrap();
        let z: [T; 5] = public_inputs[7..12].try_into().unwrap();
        let u: [T; 5] = public_inputs[12..17].try_into().unwrap();
        let t: [T; 5] = public_inputs[17..22].try_into().unwrap();
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
            cutoff18_days: F::from_canonical_u32(cutoff18_from_today_for_tests()),
            nat_code: F::from_canonical_u16(Nationality::FR.code()),
            issuer_pk: issuer::keys::public().0.to_field(),
        }
    }
    // TODO: distinguish error from proof verification & public input checks
    pub(crate) fn check(&self, proved: &[F]) -> anyhow::Result<()> {
        assert!(proved.len() == Self::LEN);
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
        let mut res = Vec::with_capacity(Self::LEN);
        for _ in 0..Self::LEN {
            let target = builder.add_virtual_target();
            builder.register_public_input(target);
            res.push(target)
        }
        Self::from_list(&res)
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
