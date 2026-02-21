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

use crate::{
    circuit::{
        curve::{CircuitBuilderCurve, PartialWitnessCurve, PointTarget},
        scalar::{CircuitBuilderScalar, PartialWitnessScalar, ScalarTarget},
    },
    encoding::{self, LEN_POINT, LEN_SCALAR},
};

pub type SchnorrTarget = encoding::SchnorrProof<Target, BoolTarget>;

pub trait CircuitBuilderSchnorr<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_schnorr_target(&mut self) -> SchnorrTarget;
    fn register_schnorr_public_input(&mut self, target: SchnorrTarget);
    fn schnorr_hash_with_message(
        &mut self,
        proof: SchnorrTarget,
        message: &[Target],
    ) -> ScalarTarget;
    fn schnorr_final_verification(
        &mut self,
        proof: SchnorrTarget,
        e: ScalarTarget,
        pk: PointTarget,
        r: PointTarget,
    );
}

pub trait PartialWitnessSchnorr<F: RichField>: Witness<F> {
    fn get_schnorr_target(&self, target: SchnorrTarget) -> encoding::SchnorrProof<F, bool>;
    fn set_schnorr_target(
        &mut self,
        target: SchnorrTarget,
        value: encoding::SchnorrProof<F, bool>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSchnorr<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_schnorr_target(&mut self) -> SchnorrTarget {
        encoding::SchnorrProof {
            r: self.add_virtual_point_target(),
            s: self.add_virtual_scalar_target(),
        }
    }
    fn register_schnorr_public_input(&mut self, target: SchnorrTarget) {
        self.register_point_public_input(target.r);
        self.register_scalar_public_input(target.s);
    }

    fn schnorr_hash_with_message(
        &mut self,
        proof: SchnorrTarget,
        message: &[Target],
    ) -> ScalarTarget {
        let mut to_hash: Vec<Target> = Vec::with_capacity(LEN_POINT + message.len());
        let r_input: [Target; LEN_POINT] = proof.r.into();
        to_hash.extend_from_slice(&r_input);
        to_hash.extend_from_slice(message);

        let mut bits: Vec<BoolTarget> = Vec::with_capacity(LEN_SCALAR);

        let h0: HashOutTarget = self.hash_n_to_hash_no_pad::<PoseidonHash>(to_hash);
        for i in 0..4 {
            bits.extend(self.split_le(h0.elements[i], 64));
        }

        let mut ctr = F::ONE;
        while bits.len() < LEN_SCALAR {
            let ctr_t = self.constant(ctr);

            let mut inp = vec![ctr_t];
            inp.extend_from_slice(&h0.elements);

            let hi: HashOutTarget = self.hash_n_to_hash_no_pad::<PoseidonHash>(inp);
            for i in 0..4 {
                bits.extend(self.split_le(hi.elements[i], 64));
            }
            ctr += F::ONE;
        }

        bits.truncate(LEN_SCALAR);
        let bits: [BoolTarget; LEN_SCALAR] = bits.try_into().unwrap();
        bits.into()
    }

    // Optimized Schnorr verification using Shamir (double-scalar mul) in one loop.
    // Verifies: s*G == R + e*P   <=>   s*G + e*(-P) == R
    fn schnorr_final_verification(
        &mut self,
        proof: SchnorrTarget,
        e: ScalarTarget,
        pk: PointTarget,
        r: PointTarget,
    ) {
        let pk_neg = self.neg_point(pk);

        // lhs = s*G + e*(-P)
        let lhs = self.double_scalar_mul_shamir(proof.s, e, pk_neg);

        // lhs must equal R
        let res = self.is_equal_point(lhs, r);

        self.assert_one(res.target);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessSchnorr<F> for W {
    fn get_schnorr_target(&self, target: SchnorrTarget) -> encoding::SchnorrProof<F, bool> {
        encoding::SchnorrProof {
            r: self.get_point_target(target.r),
            s: self.get_scalar_target(target.s),
        }
    }
    fn set_schnorr_target(
        &mut self,
        target: SchnorrTarget,
        value: encoding::SchnorrProof<F, bool>,
    ) -> anyhow::Result<()> {
        self.set_point_target(target.r, value.r)?;
        self.set_scalar_target(target.s, value.s)
    }
}
