use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{self, LEN_PASSPORT_NUMBER};

type PassportNumberTarget = encoding::PassportNumber<Target>;

pub trait CircuitBuilderPassportNumber<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_passport_number_target(&mut self) -> PassportNumberTarget;
    fn register_passport_number_public_input(&mut self, target: PassportNumberTarget);
}
pub trait PartialWitnessPassportNumber<F: RichField>: Witness<F> {
    fn get_passport_number_target(
        &self,
        target: PassportNumberTarget,
    ) -> encoding::PassportNumber<F>;
    fn set_passport_number_target(
        &mut self,
        target: PassportNumberTarget,
        value: encoding::PassportNumber<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPassportNumber<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_passport_number_target(&mut self) -> PassportNumberTarget {
        encoding::PassportNumber(std::array::from_fn::<_, LEN_PASSPORT_NUMBER, _>(|_| {
            self.add_virtual_target()
        }))
    }
    fn register_passport_number_public_input(&mut self, target: PassportNumberTarget) {
        for t in target.0.into_iter() {
            self.register_public_input(t);
        }
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessPassportNumber<F> for W {
    fn get_passport_number_target(
        &self,
        target: PassportNumberTarget,
    ) -> encoding::PassportNumber<F> {
        encoding::PassportNumber(target.0.map(|t| self.get_target(t)))
    }
    fn set_passport_number_target(
        &mut self,
        target: PassportNumberTarget,
        value: encoding::PassportNumber<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in target.0.into_iter().zip(value.0.into_iter()) {
            self.set_target(target, value)?;
        }
        Ok(())
    }
}
