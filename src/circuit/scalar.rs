use std::array;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::arith::Scalar;

#[derive(Clone, Copy)]
pub struct ScalarTarget {
    /// little endian
    pub(crate) bits: [BoolTarget; Scalar::NB_BITS],
}

pub trait CircuitBuilderScalar<F: RichField + Extendable<D>, const D: usize> {
    /// The Target is asserted to be 0 <= s < modulus
    fn add_virtual_scalar_target(&mut self) -> ScalarTarget;
    // fn connect_scalar(&mut self, a: ScalarTarget, b: ScalarTarget);
    fn register_scalar_public_input(&mut self, s: ScalarTarget);
}
pub trait PartialWitnessScalar<F: RichField>: Witness<F> {
    fn get_scalar_target(&self, target: ScalarTarget) -> Scalar;

    fn set_scalar_target(&mut self, target: ScalarTarget, value: Scalar) -> anyhow::Result<()>;
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
        for i in (0..Scalar::NB_BITS).rev() {
            let b = bits[i];
            let n = self.constant_bool(Scalar::modulus_bit_le(i));

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
        ScalarTarget { bits }
    }
    fn register_scalar_public_input(&mut self, s: ScalarTarget) {
        s.bits
            .iter()
            .for_each(|&t| self.register_public_input(t.target));
    }
}
impl<W: Witness<F>, F: RichField> PartialWitnessScalar<F> for W {
    fn get_scalar_target(&self, target: ScalarTarget) -> Scalar {
        Scalar::from_bits_le(&target.bits.map(|b| self.get_bool_target(b)))
    }

    fn set_scalar_target(&mut self, target: ScalarTarget, value: Scalar) -> anyhow::Result<()> {
        for (&target, &value) in target.bits.iter().zip(value.to_bits_le().iter()) {
            self.set_bool_target(target, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    fn modulus_bits_le() -> [bool; Scalar::NB_BITS] {
        core::array::from_fn(Scalar::modulus_bit_le)
    }

    #[test]
    fn test_set_get_scalar_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let s_t = builder.add_virtual_scalar_target();

        // No need to prove: we just test witness helpers.
        let mut pw = PartialWitness::<F>::new();

        // use a safe value < modulus
        let mut bits = [false; Scalar::NB_BITS];
        bits[0] = true;
        bits[5] = true;
        let s0 = Scalar::from_bits_le(&bits);
        pw.set_scalar_target(s_t, s0).unwrap();
        let got = pw.get_scalar_target(s_t);
        assert!((got.equals(s0)) == u64::MAX)
    }

    #[test]
    fn test_scalar_accepts_zero_one_modulus_minus_one() {
        // We'll reuse the same circuit shape 3 times by rebuilding (simple, reliable).
        for scalar in [Scalar::ZERO, Scalar::ONE, (Scalar::ZERO - Scalar::ONE)] {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

            let s_t = builder.add_virtual_scalar_target();
            builder.register_scalar_public_input(s_t);

            let mut pw = PartialWitness::<F>::new();
            pw.set_scalar_target(s_t, scalar).unwrap();

            let pis = prove_and_get_public_inputs(builder, pw);

            // public inputs are bits as field elems
            assert_eq!(pis.len(), Scalar::NB_BITS);

            let expected_bits = scalar.to_bits_le();

            for (i, &pi) in pis.iter().enumerate() {
                let expected = if expected_bits[i] { F::ONE } else { F::ZERO };
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

        for (i, s_t) in s_t.bits.into_iter().enumerate() {
            pw.set_bool_target(s_t, bits[i]).unwrap();
        }

        // If bits encode exactly modulus, lt should be false, and assert_one(lt) must fail.
        prove_err(builder, pw);
    }
}
