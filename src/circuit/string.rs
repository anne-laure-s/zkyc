use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{self, LEN_STRING};

type StringTarget = encoding::String<Target>;

pub trait CircuitBuilderString<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_string_target(&mut self) -> StringTarget;
    fn register_string_public_input(&mut self, s: StringTarget);
}
pub trait PartialWitnessString<F: RichField>: Witness<F> {
    fn get_string_target(&self, target: StringTarget) -> encoding::String<F>;
    fn set_string_target(
        &mut self,
        target: StringTarget,
        value: encoding::String<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderString<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_string_target(&mut self) -> StringTarget {
        encoding::String(std::array::from_fn::<_, LEN_STRING, _>(|_| {
            self.add_virtual_target()
        }))
    }
    fn register_string_public_input(&mut self, s: StringTarget) {
        for t in s.0.into_iter() {
            self.register_public_input(t);
        }
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessString<F> for W {
    fn get_string_target(&self, target: StringTarget) -> encoding::String<F> {
        encoding::String(target.0.map(|t| self.get_target(t)))
    }
    fn set_string_target(
        &mut self,
        target: StringTarget,
        value: encoding::String<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in target.0.into_iter().zip(value.0.into_iter()) {
            self.set_target(target, value)?;
        }
        Ok(())
    }
}
