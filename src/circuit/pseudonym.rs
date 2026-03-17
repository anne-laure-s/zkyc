use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{self, LEN_PSEUDONYM};

type PseudonymTarget = encoding::Pseudonym<Target>;

pub trait CircuitBuilderPseudonym<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_pseudonym_target(&mut self) -> PseudonymTarget;
    fn register_pseudonym_public_input(&mut self, target: PseudonymTarget);
}
pub trait PartialWitnessPseudonym<F: RichField>: Witness<F> {
    fn get_pseudonym_target(&self, target: PseudonymTarget) -> encoding::Pseudonym<F>;
    fn set_pseudonym_target(
        &mut self,
        target: PseudonymTarget,
        value: encoding::Pseudonym<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPseudonym<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_pseudonym_target(&mut self) -> PseudonymTarget {
        encoding::Hash(std::array::from_fn::<_, LEN_PSEUDONYM, _>(|_| {
            self.add_virtual_target()
        }))
    }
    fn register_pseudonym_public_input(&mut self, target: PseudonymTarget) {
        for t in target.0.into_iter() {
            self.register_public_input(t);
        }
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessPseudonym<F> for W {
    fn get_pseudonym_target(&self, target: PseudonymTarget) -> encoding::Pseudonym<F> {
        encoding::Hash(target.0.map(|t| self.get_target(t)))
    }
    fn set_pseudonym_target(
        &mut self,
        target: PseudonymTarget,
        value: encoding::Pseudonym<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in target.0.into_iter().zip(value.0.into_iter()) {
            self.set_target(target, value)?;
        }
        Ok(())
    }
}
