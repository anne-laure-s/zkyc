use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug, Clone, Copy)]
pub struct GFp5Target([Target; 5]);

impl From<[Target; 5]> for GFp5Target {
    fn from(value: [Target; 5]) -> Self {
        Self(value)
    }
}
// TODO: check endianness in the arith implementation
pub trait CircuitBuilderGFp5<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_gfp5_target(&mut self) -> GFp5Target;
    fn connect_gfp5(&mut self, a: GFp5Target, b: GFp5Target);
    fn register_gfp5_public_input(&mut self, a: GFp5Target);
    fn zero_gfp5(&mut self) -> GFp5Target;
    fn one_gfp5(&mut self) -> GFp5Target;
    fn constant_gfp5(&mut self, c: [F; 5]) -> GFp5Target;
    fn is_equal_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> BoolTarget;
    fn neg_gfp5(&mut self, a: GFp5Target) -> GFp5Target;
    fn add_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target;
    fn sub_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target;
    fn mul_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target;
    fn mul_const_gfp5(&mut self, c: [F; 5], a: GFp5Target) -> GFp5Target;
    fn double_gfp5(&mut self, a: GFp5Target) -> GFp5Target;
    fn is_zero_gfp5(&mut self, a: GFp5Target) -> BoolTarget;
    fn mul_by_b_gfp5(&mut self, v: GFp5Target) -> GFp5Target;
    fn mul_small_gfp5(&mut self, a: GFp5Target, rhs: u32) -> GFp5Target;
    fn mul_by_a_gfp5(&mut self, v: GFp5Target) -> GFp5Target {
        self.double_gfp5(v)
    }
    fn mul_small_k1_gfp5(&mut self, a: GFp5Target, rhs: u32) -> GFp5Target;
    fn select_gfp5(&mut self, c: BoolTarget, a: GFp5Target, b: GFp5Target) -> GFp5Target;
}

pub trait PartialWitnessGFp5<F: RichField>: Witness<F> {
    fn get_gfp5_target(&self, target: GFp5Target) -> [F; 5];

    fn get_gfp5_targets(&self, targets: &[GFp5Target]) -> Vec<[F; 5]> {
        targets.iter().map(|&t| self.get_gfp5_target(t)).collect()
    }

    fn set_gfp5_target(&mut self, target: GFp5Target, value: [F; 5]) -> anyhow::Result<()>;

    fn set_gfp5_targets(
        &mut self,
        targets: &[GFp5Target],
        values: &[[F; 5]],
    ) -> anyhow::Result<()> {
        for (&t, &v) in targets.iter().zip(values.iter()) {
            self.set_gfp5_target(t, v)?;
        }
        Ok(())
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderGFp5<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_gfp5_target(&mut self) -> GFp5Target {
        [
            self.add_virtual_target(),
            self.add_virtual_target(),
            self.add_virtual_target(),
            self.add_virtual_target(),
            self.add_virtual_target(),
        ]
        .into()
    }
    fn connect_gfp5(&mut self, a: GFp5Target, b: GFp5Target) {
        for (lhs, rhs) in a.0.into_iter().zip(b.0.into_iter()) {
            self.connect(lhs, rhs);
        }
    }
    fn register_gfp5_public_input(&mut self, a: GFp5Target) {
        for t in a.0.into_iter() {
            self.register_public_input(t);
        }
    }
    fn zero_gfp5(&mut self) -> GFp5Target {
        GFp5Target([self.zero(); 5])
    }

    fn is_zero_gfp5(&mut self, a: GFp5Target) -> BoolTarget {
        let zero = self.zero();
        let terms = vec![
            self.is_equal(a.0[0], zero).target,
            self.is_equal(a.0[1], zero).target,
            self.is_equal(a.0[2], zero).target,
            self.is_equal(a.0[3], zero).target,
            self.is_equal(a.0[4], zero).target,
        ];
        let prod = self.mul_many(terms);
        BoolTarget::new_unsafe(prod)
    }

    fn one_gfp5(&mut self) -> GFp5Target {
        [
            self.one(),
            self.zero(),
            self.zero(),
            self.zero(),
            self.zero(),
        ]
        .into()
    }

    fn constant_gfp5(&mut self, c: [F; 5]) -> GFp5Target {
        [
            self.constant(c[0]),
            self.constant(c[1]),
            self.constant(c[2]),
            self.constant(c[3]),
            self.constant(c[4]),
        ]
        .into()
    }
    fn is_equal_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> BoolTarget {
        let terms = vec![
            self.is_equal(a.0[0], b.0[0]).target,
            self.is_equal(a.0[1], b.0[1]).target,
            self.is_equal(a.0[2], b.0[2]).target,
            self.is_equal(a.0[3], b.0[3]).target,
            self.is_equal(a.0[4], b.0[4]).target,
        ];
        let prod = self.mul_many(terms);
        BoolTarget::new_unsafe(prod)
    }
    fn neg_gfp5(&mut self, a: GFp5Target) -> GFp5Target {
        [
            self.neg(a.0[0]),
            self.neg(a.0[1]),
            self.neg(a.0[2]),
            self.neg(a.0[3]),
            self.neg(a.0[4]),
        ]
        .into()
    }

    fn double_gfp5(&mut self, a: GFp5Target) -> GFp5Target {
        [
            self.mul_const(F::TWO, a.0[0]),
            self.mul_const(F::TWO, a.0[1]),
            self.mul_const(F::TWO, a.0[2]),
            self.mul_const(F::TWO, a.0[3]),
            self.mul_const(F::TWO, a.0[4]),
        ]
        .into()
    }

    fn add_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target {
        [
            self.add(a.0[0], b.0[0]),
            self.add(a.0[1], b.0[1]),
            self.add(a.0[2], b.0[2]),
            self.add(a.0[3], b.0[3]),
            self.add(a.0[4], b.0[4]),
        ]
        .into()
    }

    fn sub_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target {
        [
            self.sub(a.0[0], b.0[0]),
            self.sub(a.0[1], b.0[1]),
            self.sub(a.0[2], b.0[2]),
            self.sub(a.0[3], b.0[3]),
            self.sub(a.0[4], b.0[4]),
        ]
        .into()
    }

    fn mul_gfp5(&mut self, a: GFp5Target, b: GFp5Target) -> GFp5Target {
        let GFp5Target([a0, a1, a2, a3, a4]) = a;
        let GFp5Target([b0, b1, b2, b3, b4]) = b;

        let three = F::from_canonical_u64(3);

        // c0 ← a0b0 + 3(a1b4 + a2b3 + a3b2 + a4b1)
        // c1 ← a0b1 + a1b0 + 3(a2b4 + a3b3 + a4b2)
        // c2 ← a0b2 + a1b1 + a2b0 + 3(a3b4 + a4b3)
        // c3 ← a0b3 + a1b2 + a2b1 + a3b0 + 3a4b4
        // c4 ← a0b4 + a1b3 + a2b2 + a3b1 + a4b0

        let mut c0 = self.mul(a4, b1);
        c0 = self.mul_add(a3, b2, c0);
        c0 = self.mul_add(a2, b3, c0);
        c0 = self.mul_add(a1, b4, c0);
        c0 = self.mul_const(three, c0);
        c0 = self.mul_add(a0, b0, c0);

        let mut c1 = self.mul(a4, b2);
        c1 = self.mul_add(a3, b3, c1);
        c1 = self.mul_add(a2, b4, c1);
        c1 = self.mul_const(three, c1);
        c1 = self.mul_add(a1, b0, c1);
        c1 = self.mul_add(a0, b1, c1);

        let mut c2 = self.mul(a4, b3);
        c2 = self.mul_add(a3, b4, c2);
        c2 = self.mul_const(three, c2);
        c2 = self.mul_add(a2, b0, c2);
        c2 = self.mul_add(a1, b1, c2);
        c2 = self.mul_add(a0, b2, c2);

        let mut c3 = self.mul(a4, b4);
        c3 = self.mul_const(three, c3);
        c3 = self.mul_add(a3, b0, c3);
        c3 = self.mul_add(a2, b1, c3);
        c3 = self.mul_add(a1, b2, c3);
        c3 = self.mul_add(a0, b3, c3);

        let mut c4 = self.mul(a4, b0);
        c4 = self.mul_add(a3, b1, c4);
        c4 = self.mul_add(a2, b2, c4);
        c4 = self.mul_add(a1, b3, c4);
        c4 = self.mul_add(a0, b4, c4);

        [c0, c1, c2, c3, c4].into()
    }

    fn mul_const_gfp5(&mut self, c: [F; 5], a: GFp5Target) -> GFp5Target {
        let GFp5Target([a0, a1, a2, a3, a4]) = a;
        let [c0, c1, c2, c3, c4] = c;
        let one = self.one();

        let three = F::from_canonical_u64(3);

        let lhs = self.arithmetic(c1, c2, one, a4, a3);
        let rhs = self.arithmetic(c3, c4, one, a2, a1);
        let mut r0 = self.add(lhs, rhs);
        r0 = self.arithmetic(c0, three, one, a0, r0);

        let mut rhs = self.arithmetic(c2, c3, one, a4, a3);
        rhs = self.arithmetic(c4 * three, three, one, a2, rhs);
        let lhs = self.arithmetic(c0, c1, one, a1, a0);
        let r1 = self.add(lhs, rhs);

        let mut rhs = self.arithmetic(c3, c4, one, a4, a3);
        rhs = self.arithmetic(c2, three, one, a0, rhs);
        let lhs = self.arithmetic(c0, c1, one, a2, a1);
        let r2 = self.add(lhs, rhs);

        let mut rhs = self.arithmetic(c3, three * c4, one, a0, a4);
        rhs = self.arithmetic(c2, F::ONE, one, a1, rhs);
        let lhs = self.arithmetic(c0, c1, one, a3, a2);
        let r3 = self.add(lhs, rhs);

        let mut rhs = self.arithmetic(c3, c4, one, a1, a0);
        rhs = self.arithmetic(c2, F::ONE, one, a2, rhs);
        let lhs = self.arithmetic(c0, c1, one, a4, a3);
        let r4 = self.add(lhs, rhs);

        [r0, r1, r2, r3, r4].into()
    }

    fn mul_by_b_gfp5(&mut self, v: GFp5Target) -> GFp5Target {
        // v*w = [3*v4, v0, v1, v2, v3]
        let three = self.constant(F::from_canonical_u64(3));
        let mut w0 = self.mul(v.0[4], three);

        // then *263
        let k = self.constant(F::from_canonical_u64(263));
        w0 = self.mul(w0, k);

        let r1 = self.mul(v.0[0], k);
        let r2 = self.mul(v.0[1], k);
        let r3 = self.mul(v.0[2], k);
        let r4 = self.mul(v.0[3], k);

        [w0, r1, r2, r3, r4].into()
    }
    /// multiplies every coefficient by an u32 constant
    fn mul_small_gfp5(&mut self, a: GFp5Target, rhs: u32) -> GFp5Target {
        let k = self.constant(F::from_canonical_u64(rhs as u64));
        let mut limbs = [self.zero(); 5];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = self.mul(a.0[i], k);
        }
        limbs.into()
    }
    fn mul_small_k1_gfp5(&mut self, a: GFp5Target, rhs: u32) -> GFp5Target {
        // a * (rhs * w) with w^5 = 3 and base [1,w,w^2,w^3,w^4]
        let k = self.constant(F::from_canonical_u64(rhs as u64));
        let k3 = self.constant(F::from_canonical_u64((rhs as u64) * 3));

        let d0 = self.mul(a.0[4], k3);
        let d1 = self.mul(a.0[0], k);
        let d2 = self.mul(a.0[1], k);
        let d3 = self.mul(a.0[2], k);
        let d4 = self.mul(a.0[3], k);

        [d0, d1, d2, d3, d4].into()
    }

    fn select_gfp5(&mut self, c: BoolTarget, a: GFp5Target, b: GFp5Target) -> GFp5Target {
        let limbs: [Target; 5] = core::array::from_fn(|i| self.select(c, a.0[i], b.0[i]));
        limbs.into()
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessGFp5<F> for W {
    fn get_gfp5_target(&self, target: GFp5Target) -> [F; 5] {
        [
            self.get_target(target.0[0]),
            self.get_target(target.0[1]),
            self.get_target(target.0[2]),
            self.get_target(target.0[3]),
            self.get_target(target.0[4]),
        ]
    }

    fn set_gfp5_target(&mut self, target: GFp5Target, value: [F; 5]) -> anyhow::Result<()> {
        self.set_target(target.0[0], value[0])?;
        self.set_target(target.0[1], value[1])?;
        self.set_target(target.0[2], value[2])?;
        self.set_target(target.0[3], value[3])?;
        self.set_target(target.0[4], value[4])
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

    // ---------- Helpers: native arithmetic in GF(p)^5 with w^5 = 3 ----------
    fn f(x: u64) -> F {
        F::from_canonical_u64(x)
    }

    fn add_native(a: [F; 5], b: [F; 5]) -> [F; 5] {
        core::array::from_fn(|i| a[i] + b[i])
    }

    fn sub_native(a: [F; 5], b: [F; 5]) -> [F; 5] {
        core::array::from_fn(|i| a[i] - b[i])
    }

    fn neg_native(a: [F; 5]) -> [F; 5] {
        core::array::from_fn(|i| -a[i])
    }

    fn double_native(a: [F; 5]) -> [F; 5] {
        core::array::from_fn(|i| a[i] + a[i])
    }

    fn mul_native(a: [F; 5], b: [F; 5]) -> [F; 5] {
        // Matches your circuit formula (basis [1,w,w^2,w^3,w^4] with w^5 = 3)
        let three = f(3);

        let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);
        let (b0, b1, b2, b3, b4) = (b[0], b[1], b[2], b[3], b[4]);

        // c0 ← a0b0 + 3(a1b4 + a2b3 + a3b2 + a4b1)
        let mut c0 = a4 * b1 + a3 * b2 + a2 * b3 + a1 * b4;
        c0 = three * c0 + a0 * b0;

        // c1 ← a0b1 + a1b0 + 3(a2b4 + a3b3 + a4b2)
        let mut c1 = a4 * b2 + a3 * b3 + a2 * b4;
        c1 = three * c1 + a1 * b0 + a0 * b1;

        // c2 ← a0b2 + a1b1 + a2b0 + 3(a3b4 + a4b3)
        let mut c2 = a4 * b3 + a3 * b4;
        c2 = three * c2 + a2 * b0 + a1 * b1 + a0 * b2;

        // c3 ← a0b3 + a1b2 + a2b1 + a3b0 + 3a4b4
        let mut c3 = three * (a4 * b4);
        c3 = c3 + a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3;

        // c4 ← a0b4 + a1b3 + a2b2 + a3b1 + a4b0
        let c4 = a4 * b0 + a3 * b1 + a2 * b2 + a1 * b3 + a0 * b4;

        [c0, c1, c2, c3, c4]
    }

    fn mul_by_b_then_263_native(v: [F; 5]) -> [F; 5] {
        // v*w = [3*v4, v0, v1, v2, v3] then *263 coefficient-wise
        let three = f(3);
        let k = f(263);
        [(three * v[4]) * k, v[0] * k, v[1] * k, v[2] * k, v[3] * k]
    }

    fn mul_small_native(a: [F; 5], rhs: u32) -> [F; 5] {
        let k = f(rhs as u64);
        core::array::from_fn(|i| a[i] * k)
    }

    fn mul_small_k1_native(a: [F; 5], rhs: u32) -> [F; 5] {
        // a * (rhs*w)
        let k = f(rhs as u64);
        let k3 = f((rhs as u64) * 3);
        [a[4] * k3, a[0] * k, a[1] * k, a[2] * k, a[3] * k]
    }

    fn prove_and_get_public_inputs(builder: CircuitBuilder<F, D>, pw: PartialWitness<F>) -> Vec<F> {
        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).expect("prove() should succeed");
        data.verify(proof.clone()).expect("verify() should succeed");
        proof.public_inputs
    }

    // ---------- Tests ----------
    #[test]
    fn test_zero_one_constant() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let z = builder.zero_gfp5();
        let o = builder.one_gfp5();
        let c = builder.constant_gfp5([f(7), f(8), f(9), f(10), f(11)]);

        builder.register_gfp5_public_input(z);
        builder.register_gfp5_public_input(o);
        builder.register_gfp5_public_input(c);

        let pw = PartialWitness::<F>::new();
        let pis = prove_and_get_public_inputs(builder, pw);

        assert_eq!(&pis[0..5], &[F::ZERO; 5]);
        assert_eq!(&pis[5..10], &[F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
        assert_eq!(&pis[10..15], &[f(7), f(8), f(9), f(10), f(11)]);
    }

    #[test]
    fn test_add_sub_neg_double() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let a_t = builder.add_virtual_gfp5_target();
        let b_t = builder.add_virtual_gfp5_target();

        let add_t = builder.add_gfp5(a_t, b_t);
        let sub_t = builder.sub_gfp5(a_t, b_t);
        let neg_t = builder.neg_gfp5(a_t);
        let dbl_t = builder.double_gfp5(a_t);

        builder.register_gfp5_public_input(add_t);
        builder.register_gfp5_public_input(sub_t);
        builder.register_gfp5_public_input(neg_t);
        builder.register_gfp5_public_input(dbl_t);

        let a = [f(1), f(2), f(3), f(4), f(5)];
        let b = [f(10), f(20), f(30), f(40), f(50)];

        let mut pw = PartialWitness::<F>::new();
        pw.set_gfp5_target(a_t, a).unwrap();
        pw.set_gfp5_target(b_t, b).unwrap();

        let pis = prove_and_get_public_inputs(builder, pw);

        assert_eq!(&pis[0..5], &add_native(a, b));
        assert_eq!(&pis[5..10], &sub_native(a, b));
        assert_eq!(&pis[10..15], &neg_native(a));
        assert_eq!(&pis[15..20], &double_native(a));
    }

    #[test]
    fn test_mul_matches_native() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let a_t = builder.add_virtual_gfp5_target();
        let b_t = builder.add_virtual_gfp5_target();
        let c_t = builder.mul_gfp5(a_t, b_t);

        builder.register_gfp5_public_input(c_t);

        let a = [f(3), f(5), f(7), f(11), f(13)];
        let b = [f(17), f(19), f(23), f(29), f(31)];

        let mut pw = PartialWitness::<F>::new();
        pw.set_gfp5_target(a_t, a).unwrap();
        pw.set_gfp5_target(b_t, b).unwrap();

        let pis = prove_and_get_public_inputs(builder, pw);
        assert_eq!(&pis[0..5], &mul_native(a, b));
    }

    #[test]
    fn test_mul_const_matches_general_mul() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let a_t = builder.add_virtual_gfp5_target();

        let c = [f(2), f(3), f(5), f(7), f(11)];
        let c_t = builder.mul_const_gfp5(c, a_t);

        // Compare with mul_gfp5(constant(c), a)
        let c_const_t = builder.constant_gfp5(c);
        let prod_t = builder.mul_gfp5(c_const_t, a_t);

        builder.register_gfp5_public_input(c_t);
        builder.register_gfp5_public_input(prod_t);

        let a = [f(101), f(102), f(103), f(104), f(105)];
        let mut pw = PartialWitness::<F>::new();
        pw.set_gfp5_target(a_t, a).unwrap();

        let pis = prove_and_get_public_inputs(builder, pw);
        assert_eq!(&pis[0..5], &pis[5..10]);
        assert_eq!(&pis[0..5], &mul_native(c, a));
    }

    #[test]
    fn test_mul_by_b_and_small_variants() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let a_t = builder.add_virtual_gfp5_target();

        let mb_t = builder.mul_by_b_gfp5(a_t);
        let ms_t = builder.mul_small_gfp5(a_t, 42);
        let mk1_t = builder.mul_small_k1_gfp5(a_t, 42);

        builder.register_gfp5_public_input(mb_t);
        builder.register_gfp5_public_input(ms_t);
        builder.register_gfp5_public_input(mk1_t);

        let a = [f(9), f(8), f(7), f(6), f(5)];
        let mut pw = PartialWitness::<F>::new();
        pw.set_gfp5_target(a_t, a).unwrap();

        let pis = prove_and_get_public_inputs(builder, pw);

        assert_eq!(&pis[0..5], &mul_by_b_then_263_native(a));
        assert_eq!(&pis[5..10], &mul_small_native(a, 42));
        assert_eq!(&pis[10..15], &mul_small_k1_native(a, 42));
    }

    #[test]
    fn test_is_equal_is_zero_select() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let a_t = builder.add_virtual_gfp5_target();
        let b_t = builder.add_virtual_gfp5_target();

        let eq_t = builder.is_equal_gfp5(a_t, b_t);
        let z_t = builder.is_zero_gfp5(a_t);

        let c_bool = builder.add_virtual_bool_target_safe();
        let sel_t = builder.select_gfp5(c_bool, a_t, b_t);

        builder.register_public_input(eq_t.target);
        builder.register_public_input(z_t.target);
        builder.register_gfp5_public_input(sel_t);

        // Build ONCE
        let data = builder.build::<Cfg>();

        let a = [F::ZERO; 5];
        let b = [f(1), f(2), f(3), f(4), f(5)];

        // Case 1: a=0, b!=0, c=true -> select(a), eq=false, is_zero(a)=true
        {
            let mut pw = PartialWitness::<F>::new();
            pw.set_gfp5_target(a_t, a).unwrap();
            pw.set_gfp5_target(b_t, b).unwrap();
            pw.set_bool_target(c_bool, true).unwrap();

            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();
            let pis = proof.public_inputs;

            assert_eq!(pis[0], F::ZERO); // a != b
            assert_eq!(pis[1], F::ONE); // a == 0
            assert_eq!(&pis[2..7], &a); // selected a
        }

        // Case 2: a=b, c=false -> select(b), eq=true, is_zero(a)=false
        {
            let mut pw = PartialWitness::<F>::new();
            pw.set_gfp5_target(a_t, b).unwrap();
            pw.set_gfp5_target(b_t, b).unwrap();
            pw.set_bool_target(c_bool, false).unwrap();

            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();
            let pis = proof.public_inputs;

            assert_eq!(pis[0], F::ONE); // a == b
            assert_eq!(pis[1], F::ZERO); // a != 0
            assert_eq!(&pis[2..7], &b); // selected b
        }
    }
}
