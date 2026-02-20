use std::array;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    arith,
    encoding::{self, LEN_SCALAR},
};

pub type ScalarTarget = encoding::Scalar<BoolTarget>;

pub trait CircuitBuilderScalar<F: RichField + Extendable<D>, const D: usize> {
    /// The Target is asserted to be 0 <= s < modulus
    fn add_virtual_scalar_target(&mut self) -> ScalarTarget;
    // fn connect_scalar(&mut self, a: ScalarTarget, b: ScalarTarget);
    fn register_scalar_public_input(&mut self, s: ScalarTarget);
}
pub trait PartialWitnessScalar<F: RichField>: Witness<F> {
    fn get_scalar_target(&self, target: ScalarTarget) -> encoding::Scalar<bool>;

    fn set_scalar_target(
        &mut self,
        target: ScalarTarget,
        value: encoding::Scalar<bool>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderScalar<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_scalar_target(&mut self) -> ScalarTarget {
        // No built in equality for bool target
        // Safe because bits are checked & safe
        fn eq_bool<F: RichField + Extendable<D>, const D: usize>(
            builder: &mut CircuitBuilder<F, D>,
            a: BoolTarget,
            b: BoolTarget,
        ) -> BoolTarget {
            let a = a.target;
            let b = b.target;

            let ab = builder.mul(a, b);
            let two_ab = builder.add(ab, ab);

            let sum = builder.add(a, b);
            let xor = builder.sub(sum, two_ab);
            let one = builder.one();
            let eq = builder.sub(one, xor);
            BoolTarget::new_unsafe(eq)
        }
        let bits = array::from_fn(|_| self.add_virtual_bool_target_safe());
        // target was checked smaller than modulus
        let mut lt = self._false();
        // until now every bits are equal
        let mut eq = self._true();
        for i in (0..LEN_SCALAR).rev() {
            let b = bits[i];
            let n = self.constant_bool(arith::Scalar::modulus_bit_le(i));

            // lt becomes true when a strictly_less has been found and every other bigger bits have been equal until now
            lt = {
                let not_b = self.not(b);
                let strictly_less = self.and(not_b, n);
                let eq_and_strictly_less = self.and(eq, strictly_less);
                self.or(lt, eq_and_strictly_less)
            };

            // eq stays true as long as all the seen bits have been equal
            eq = {
                let b_eq_n = eq_bool(self, b, n);
                self.and(eq, b_eq_n)
            }
        }
        self.assert_one(lt.target);
        bits.into()
    }
    fn register_scalar_public_input(&mut self, s: ScalarTarget) {
        s.0.iter()
            .for_each(|&t| self.register_public_input(t.target));
    }
}
impl<W: Witness<F>, F: RichField> PartialWitnessScalar<F> for W {
    fn get_scalar_target(&self, target: ScalarTarget) -> encoding::Scalar<bool> {
        target.0.map(|b| self.get_bool_target(b)).into()
    }

    fn set_scalar_target(
        &mut self,
        target: ScalarTarget,
        value: encoding::Scalar<bool>,
    ) -> anyhow::Result<()> {
        for (&target, &value) in target.0.iter().zip(value.0.iter()) {
            self.set_bool_target(target, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::conversion::ToScalarField;

    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField as F, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;

    fn prove_and_get_public_inputs(builder: CircuitBuilder<F, D>, pw: PartialWitness<F>) -> Vec<F> {
        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).expect("prove() should succeed");
        data.verify(proof.clone()).expect("verify() should succeed");
        proof.public_inputs
    }

    fn prove_err(builder: CircuitBuilder<F, D>, pw: PartialWitness<F>) {
        let data = builder.build::<Cfg>();
        let res = data.prove(pw);
        assert!(res.is_err(), "prove() should fail but succeeded");
    }

    fn modulus_bits_le() -> [bool; LEN_SCALAR] {
        core::array::from_fn(arith::Scalar::modulus_bit_le)
    }

    #[test]
    fn test_set_get_scalar_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let s_t = builder.add_virtual_scalar_target();

        // No need to prove: we just test witness helpers.
        let mut pw = PartialWitness::<F>::new();

        // use a safe value < modulus
        let mut bits = [false; LEN_SCALAR];
        bits[0] = true;
        bits[5] = true;
        let s0: encoding::Scalar<bool> = bits.into();
        pw.set_scalar_target(s_t, s0).unwrap();
        let got = pw.get_scalar_target(s_t);
        for (s, g) in s0.0.iter().zip(got.0.iter()) {
            assert!(s == g)
        }
    }

    #[test]
    fn test_scalar_accepts_zero_one_modulus_minus_one() {
        // We'll reuse the same circuit shape 3 times by rebuilding (simple, reliable).
        for scalar in [
            arith::Scalar::ZERO.to_field(),
            arith::Scalar::ONE.to_field(),
            (arith::Scalar::ZERO - arith::Scalar::ONE).to_field(),
        ] {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

            let s_t = builder.add_virtual_scalar_target();
            builder.register_scalar_public_input(s_t);

            let mut pw = PartialWitness::<F>::new();
            pw.set_scalar_target(s_t, scalar).unwrap();

            let pis = prove_and_get_public_inputs(builder, pw);

            // public inputs are bits as field elems
            assert_eq!(pis.len(), LEN_SCALAR);

            for (i, &pi) in pis.iter().enumerate() {
                let expected = if scalar.0[i] { F::ONE } else { F::ZERO };
                assert_eq!(pi, expected);
            }
        }
    }

    #[test]
    fn test_scalar_rejects_modulus_equal() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let s_t = builder.add_virtual_scalar_target();
        // No need to register, constraint failure happens regardless.
        // (But registering doesn't hurt either.)

        let mut pw = PartialWitness::<F>::new();
        let bits = modulus_bits_le();

        for (i, s_t) in s_t.0.into_iter().enumerate() {
            pw.set_bool_target(s_t, bits[i]).unwrap();
        }

        // If bits encode exactly modulus, lt should be false, and assert_one(lt) must fail.
        prove_err(builder, pw);
    }
}
