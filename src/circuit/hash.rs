use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::encoding::{self, LEN_HASH};

// TODO: some functions are already existing for hash, maybe it’s relevant to use them
pub type HashTarget = encoding::Hash<Target>;

impl From<HashOutTarget> for HashTarget {
    fn from(value: HashOutTarget) -> Self {
        encoding::Hash(value.elements)
    }
}

pub trait CircuitBuilderHash<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash_target(&mut self) -> HashTarget;
    fn register_hash_public_input(&mut self, target: HashTarget);
    fn connect_hash(&mut self, target1: HashTarget, target2: HashTarget);
    fn merge_left_right(
        &mut self,
        node: HashTarget,
        is_left: BoolTarget,
        neighbor: HashTarget,
    ) -> HashTarget;
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
    fn connect_hash(&mut self, target1: HashTarget, target2: HashTarget) {
        target1
            .0
            .into_iter()
            .zip(target2.0)
            .for_each(|(t1, t2)| self.connect(t1, t2));
    }

    fn merge_left_right(
        &mut self,
        node: HashTarget,
        is_left: BoolTarget,
        neighbor: HashTarget,
    ) -> HashTarget {
        let left =
            std::array::from_fn::<_, LEN_HASH, _>(|i| self._if(is_left, node.0[i], neighbor.0[i]));
        let right =
            std::array::from_fn::<_, LEN_HASH, _>(|i| self._if(is_left, neighbor.0[i], node.0[i]));
        let mut buffer = Vec::with_capacity(2 * LEN_HASH);
        buffer.extend_from_slice(&left);
        buffer.extend_from_slice(&right);
        self.hash_n_to_hash_no_pad::<PoseidonHash>(buffer).into()
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
