use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{self, LEN_HASH};

type HashTarget = encoding::Hash<Target>;

pub trait CircuitBuilderHash<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash_target(&mut self) -> HashTarget;
    fn register_hash_public_input(&mut self, target: HashTarget);
}
pub trait PartialWitnessHash<F: RichField>: Witness<F> {
    fn get_hash_target(&self, target: HashTarget) -> encoding::Hash<F>;
    fn set_hash_target(
        &mut self,
        target: HashTarget,
        value: encoding::Hash<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_hash_target(&mut self) -> HashTarget {
        encoding::Hash(std::array::from_fn::<_, LEN_HASH, _>(|_| {
            self.add_virtual_target()
        }))
    }
    fn register_hash_public_input(&mut self, target: HashTarget) {
        for t in target.0.into_iter() {
            self.register_public_input(t);
        }
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessHash<F> for W {
    fn get_hash_target(&self, target: HashTarget) -> encoding::Hash<F> {
        encoding::Hash(target.0.map(|t| self.get_target(t)))
    }
    fn set_hash_target(
        &mut self,
        target: HashTarget,
        value: encoding::Hash<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in target.0.into_iter().zip(value.0.into_iter()) {
            self.set_target(target, value)?;
        }
        Ok(())
    }
}
