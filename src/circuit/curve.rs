use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    arith::Point,
    circuit::{
        gfp5::{CircuitBuilderGFp5, PartialWitnessGFp5},
        scalar::ScalarTarget,
    },
    encoding::{self, GFp5},
};

pub type PointTarget = encoding::Point<Target>;

pub trait CircuitBuilderCurve<F: RichField + Extendable<D>, const D: usize> {
    fn generator(&mut self) -> PointTarget;
    fn select_point(&mut self, c: BoolTarget, a: PointTarget, b: PointTarget) -> PointTarget;
    fn schnorr_final_verification(
        &mut self,
        s: &ScalarTarget,
        e: &ScalarTarget,
        pk: PointTarget,
        r: PointTarget,
    );
    fn double_scalar_mul_shamir(
        &mut self,
        s_bits_le: &[BoolTarget],
        e_bits_le: &[BoolTarget],
        p: PointTarget,
    ) -> PointTarget;
    fn neg_point(&mut self, p: PointTarget) -> PointTarget;
    fn is_zero_point(&mut self, p: PointTarget) -> BoolTarget;
    fn assert_non_zero_point(&mut self, p: PointTarget);
    fn add_virtual_point_target(&mut self) -> PointTarget;
    fn register_point_public_input(&mut self, p: PointTarget);
    fn assert_on_curve(&mut self, p: PointTarget);
    fn zero_point(&mut self) -> PointTarget;
    fn connect_point(&mut self, a: PointTarget, b: PointTarget);
    fn is_equal_point(&mut self, a: PointTarget, b: PointTarget) -> BoolTarget;
    fn add_point(&mut self, p: PointTarget, q: PointTarget) -> PointTarget;
    fn double_point(&mut self, p: PointTarget) -> PointTarget;
    fn constant_point_unsafe(
        &mut self,
        x: GFp5<F>,
        z: GFp5<F>,
        u: GFp5<F>,
        t: GFp5<F>,
    ) -> PointTarget;
}

pub trait PartialWitnessCurve<F: RichField>: Witness<F> {
    fn get_point_target(&self, target: PointTarget) -> crate::encoding::Point<F>;
    fn set_point_target(
        &mut self,
        target: PointTarget,
        value: crate::encoding::Point<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCurve<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_point_target(&mut self) -> PointTarget {
        let x = self.add_virtual_gfp5_target();
        let z = self.add_virtual_gfp5_target();
        let u = self.add_virtual_gfp5_target();
        let t = self.add_virtual_gfp5_target();

        let p = PointTarget { x, z, u, t };

        // Sanity check
        self.assert_on_curve(p);

        p
    }

    fn register_point_public_input(&mut self, p: PointTarget) {
        self.register_gfp5_public_input(p.x);
        self.register_gfp5_public_input(p.z);
        self.register_gfp5_public_input(p.u);
        self.register_gfp5_public_input(p.t);
    }

    fn zero_point(&mut self) -> PointTarget {
        PointTarget {
            x: self.zero_gfp5(),
            z: self.one_gfp5(),
            u: self.zero_gfp5(),
            t: self.one_gfp5(),
        }
    }

    fn generator(&mut self) -> PointTarget {
        let generator = Point::GENERATOR;
        PointTarget {
            x: self.constant_gfp5(generator.X.into()),
            z: self.constant_gfp5(generator.Z.into()),
            u: self.constant_gfp5(generator.U.into()),
            t: self.constant_gfp5(generator.T.into()),
        }
    }

    fn assert_on_curve(&mut self, p: PointTarget) {
        let p_is_zero = self.is_zero_point(p);
        let PointTarget { x, z, u, t } = p;

        // Precompute squares and products.
        let u2 = self.mul_gfp5(u, u);
        let t2 = self.mul_gfp5(t, t);
        let x2 = self.mul_gfp5(x, x);
        let z2 = self.mul_gfp5(z, z);
        let xz = self.mul_gfp5(x, z);

        // a·X·Z & b·Z²
        let axz = self.mul_by_a_gfp5(xz);
        let bz2 = self.mul_by_b_gfp5(z2);

        // inner = X² + a·X·Z + b·Z²
        let x2_axz = self.add_gfp5(x2, axz);
        let inner = self.add_gfp5(x2_axz, bz2);

        // lhs = u²·inner ; rhs = X·Z·t²
        let lhs = self.mul_gfp5(u2, inner);
        let rhs = self.mul_gfp5(xz, t2);

        // assert lhs == rhs unless p is zero
        let eq = self.is_equal_gfp5(lhs, rhs);
        let ok = self.or(p_is_zero, eq);
        self.assert_one(ok.target);
    }

    fn assert_non_zero_point(&mut self, p: PointTarget) {
        let is_zero = self.is_zero_gfp5(p.u);
        self.assert_zero(is_zero.target);
    }

    fn is_zero_point(&mut self, p: PointTarget) -> BoolTarget {
        self.is_zero_gfp5(p.u)
    }

    fn connect_point(&mut self, a: PointTarget, b: PointTarget) {
        self.connect_gfp5(a.x, b.x);
        self.connect_gfp5(a.z, b.z);
        self.connect_gfp5(a.u, b.u);
        self.connect_gfp5(a.t, b.t);
    }

    fn is_equal_point(&mut self, p: PointTarget, q: PointTarget) -> BoolTarget {
        let p_is_zero = self.is_zero_point(p);
        let q_is_zero = self.is_zero_point(q);

        let both_are_zero = self.and(p_is_zero, q_is_zero);

        // When non-inf: enforce X1*Z2 == X2*Z1 and U1*T2 == U2*T1.

        let x1z2 = self.mul_gfp5(p.x, q.z);
        let x2z1 = self.mul_gfp5(q.x, p.z);
        let u1t2 = self.mul_gfp5(p.u, q.t);
        let u2t1 = self.mul_gfp5(q.u, p.t);

        let x1z2_x2z1 = self.is_equal_gfp5(x1z2, x2z1);
        let u1t2_u2t1 = self.is_equal_gfp5(u1t2, u2t1);

        let non_zero_equal = self.and(x1z2_x2z1, u1t2_u2t1);

        self.or(both_are_zero, non_zero_equal)
    }

    fn double_point(&mut self, p: PointTarget) -> PointTarget {
        let t1 = self.mul_gfp5(p.z, p.t);
        let t2 = self.mul_gfp5(t1, p.t);
        let x1 = self.mul_gfp5(t2, t2);
        let z1 = self.mul_gfp5(t1, p.u);
        let t3 = self.mul_gfp5(p.u, p.u);

        let x_plus_z = self.add_gfp5(p.x, p.z);
        let x_plus_z_dbl = self.double_gfp5(x_plus_z);
        let w1 = {
            let prod = self.mul_gfp5(x_plus_z_dbl, t3);
            self.sub_gfp5(t2, prod)
        };

        let t4 = self.mul_gfp5(z1, z1);

        let new_x = self.mul_small_k1_gfp5(t4, 4 * Point::B1);
        let new_z = self.mul_gfp5(w1, w1);
        let new_u = {
            let s = self.add_gfp5(w1, z1);
            let s2 = self.mul_gfp5(s, s);
            let tmp = self.sub_gfp5(s2, t4);
            self.sub_gfp5(tmp, new_z)
        };
        let new_t = {
            let x1d = self.double_gfp5(x1);
            let t4_4 = self.mul_small_gfp5(t4, 4);
            let tmp = self.sub_gfp5(x1d, t4_4);
            self.sub_gfp5(tmp, new_z)
        };

        PointTarget {
            x: new_x,
            z: new_z,
            u: new_u,
            t: new_t,
        }
    }

    fn add_point(&mut self, p: PointTarget, q: PointTarget) -> PointTarget {
        let x_1 = p.x;
        let z_1 = p.z;
        let u_1 = p.u;
        let t_1 = p.t;
        let x_2 = q.x;
        let z_2 = q.z;
        let u_2 = q.u;
        let t_2 = q.t;

        // t1 = X1*X2
        let t1 = self.mul_gfp5(x_1, x_2);
        // t2 = Z1*Z2
        let t2 = self.mul_gfp5(z_1, z_2);
        // t3 = U1*U2
        let t3 = self.mul_gfp5(u_1, u_2);
        // t4 = T1*T2
        let t4 = self.mul_gfp5(t_1, t_2);

        // t5 = (X1+Z1)*(X2+Z2) - t1 - t2
        let t5 = {
            let a = self.add_gfp5(x_1, z_1);
            let b = self.add_gfp5(x_2, z_2);
            let m = self.mul_gfp5(a, b);
            let m = self.sub_gfp5(m, t1);
            self.sub_gfp5(m, t2)
        };

        // t6 = (U1+T1)*(U2+T2) - t3 - t4
        let t6 = {
            let a = self.add_gfp5(u_1, t_1);
            let b = self.add_gfp5(u_2, t_2);
            let m = self.mul_gfp5(a, b);
            let m = self.sub_gfp5(m, t3);
            self.sub_gfp5(m, t4)
        };

        // t7 = t1 + t2.mul_small_k1(B1)
        let t2b1 = self.mul_small_k1_gfp5(t2, Point::B1);
        let t7 = self.add_gfp5(t1, t2b1);

        // t8 = t4 * t7
        let t8 = self.mul_gfp5(t4, t7);

        // t9 = t3 * (t5.mul_small_k1(2*B1) + t7.double())
        let t9 = {
            let a = self.mul_small_k1_gfp5(t5, 2 * Point::B1);
            let b = self.double_gfp5(t7);
            let s = self.add_gfp5(a, b);
            self.mul_gfp5(t3, s)
        };

        // t10 = (t4 + t3.double()) * (t5 + t7)
        let t10 = {
            let t32 = self.double_gfp5(t3);
            let a = self.add_gfp5(t4, t32);
            let b = self.add_gfp5(t5, t7);
            self.mul_gfp5(a, b)
        };

        // X3 = (t10 - t8).mul_small_k1(B1)
        let t10t8 = self.sub_gfp5(t10, t8);
        let x_3 = self.mul_small_k1_gfp5(t10t8, Point::B1);
        // Z3 = t8 - t9
        let z_3 = self.sub_gfp5(t8, t9);

        // U3 = t6 * (t2.mul_small_k1(B1) - t1)
        let u_3 = {
            let a = self.sub_gfp5(t2b1, t1);
            self.mul_gfp5(t6, a)
        };

        // T3 = t8 + t9
        let t_3 = self.add_gfp5(t8, t9);

        PointTarget {
            x: x_3,
            z: z_3,
            u: u_3,
            t: t_3,
        }
    }

    fn neg_point(&mut self, p: PointTarget) -> PointTarget {
        PointTarget {
            x: p.x,
            z: p.z,
            // y -> -y  ==>  u = x/y -> -u  (so negate U; keep T)
            u: self.neg_gfp5(p.u),
            t: p.t,
        }
    }

    fn select_point(&mut self, c: BoolTarget, a: PointTarget, b: PointTarget) -> PointTarget {
        PointTarget {
            x: self.select_gfp5(c, a.x, b.x),
            z: self.select_gfp5(c, a.z, b.z),
            u: self.select_gfp5(c, a.u, b.u),
            t: self.select_gfp5(c, a.t, b.t),
        }
    }

    // TODO: generator multiplication can be optimized (see mul_gen in arith)
    /// Shamir trick: compute s*G + e*P in one MSB->LSB loop.
    ///
    /// bits are provided as little-endian; we iterate from high to low index.
    fn double_scalar_mul_shamir(
        &mut self,
        s_bits_le: &[BoolTarget],
        e_bits_le: &[BoolTarget],
        p: PointTarget,
    ) -> PointTarget {
        let n = s_bits_le.len().max(e_bits_le.len());

        let g = self.generator();

        let o = self.zero_point();
        let gp = self.add_point(g, p);

        let mut acc = self.zero_point();

        for i in (0..n).rev() {
            acc = self.double_point(acc);

            let sb = if i < s_bits_le.len() {
                s_bits_le[i]
            } else {
                self._false()
            };
            let eb = if i < e_bits_le.len() {
                e_bits_le[i]
            } else {
                self._false()
            };

            // 00 -> O
            // 01 -> P
            // 10 -> G
            // 11 -> G+P
            let t_sb0 = self.select_point(eb, p, o); // eb ? P : O
            let t_sb1 = self.select_point(eb, gp, g); // eb ? G+P : G
            let to_add = self.select_point(sb, t_sb1, t_sb0);

            acc = self.add_point(acc, to_add);
        }

        acc
    }

    // Optimized Schnorr verification using Shamir (double-scalar mul) in one loop.
    // Verifies: s*G == R + e*P   <=>   s*G + e*(-P) == R
    fn schnorr_final_verification(
        &mut self,
        s: &ScalarTarget,
        e: &ScalarTarget,
        pk: PointTarget,
        r: PointTarget,
    ) {
        let pk_neg = self.neg_point(pk);

        // lhs = s*G + e*(-P)
        let lhs = self.double_scalar_mul_shamir(&s.bits, &e.bits, pk_neg);

        // lhs must equal R
        self.connect_point(lhs, r);
    }

    fn constant_point_unsafe(
        &mut self,
        x: GFp5<F>,
        z: GFp5<F>,
        u: GFp5<F>,
        t: GFp5<F>,
    ) -> PointTarget {
        PointTarget {
            x: self.constant_gfp5(x),
            z: self.constant_gfp5(z),
            u: self.constant_gfp5(u),
            t: self.constant_gfp5(t),
        }
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessCurve<F> for W {
    fn get_point_target(&self, target: PointTarget) -> crate::encoding::Point<F> {
        crate::encoding::Point {
            x: self.get_gfp5_target(target.x),
            z: self.get_gfp5_target(target.z),
            u: self.get_gfp5_target(target.u),
            t: self.get_gfp5_target(target.t),
        }
    }

    fn set_point_target(
        &mut self,
        target: PointTarget,
        value: crate::encoding::Point<F>,
    ) -> anyhow::Result<()> {
        self.set_gfp5_target(target.x, value.x)?;
        self.set_gfp5_target(target.z, value.z)?;
        self.set_gfp5_target(target.u, value.u)?;
        self.set_gfp5_target(target.t, value.t)?;
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

    fn f(x: u64) -> F {
        F::from_canonical_u64(x)
    }
    fn native_generator() -> crate::encoding::Point<F> {
        let native = Point::GENERATOR;
        crate::encoding::Point {
            x: native.X.into(),
            z: native.Z.into(),
            u: native.U.into(),
            t: native.T.into(),
        }
    }
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

    fn assert_point_pis_eq(pis: &[F], offset: usize, expected: &[[F; 5]; 4]) {
        // expected order: x,z,u,t, each is 5 elems
        for (i, expected) in expected.iter().enumerate() {
            let start = offset + i * 5;
            let got = &pis[start..start + 5];
            assert_eq!(got, expected.as_slice());
        }
    }

    #[test]
    fn test_zero_point_is_zero_and_has_expected_limbs() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let z = builder.zero_point();
        let is_z = builder.is_zero_point(z);

        builder.register_public_input(is_z.target);
        builder.register_point_public_input(z);

        let pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());

        // public input 0 = is_zero(z)
        assert_eq!(pis[0], F::ONE);

        // then the point limbs
        let x = [F::ZERO; 5];
        let z_limb = [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
        let u = [F::ZERO; 5];
        let t = [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO];

        assert_point_pis_eq(&pis, 1, &[x, z_limb, u, t]);
    }

    #[test]
    fn test_zero_point_group_identities() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let z = builder.zero_point();

        let neg_z = builder.neg_point(z);
        let dbl_z = builder.double_point(z);
        let add_zz = builder.add_point(z, z);

        // Verify standard group equalities
        let eq_neg = builder.is_equal_point(z, neg_z);
        let eq_dbl = builder.is_equal_point(z, dbl_z);
        let eq_add = builder.is_equal_point(z, add_zz);

        // Stronger & representation-independent: each result is the identity
        let isz_neg = builder.is_zero_point(neg_z);
        let isz_dbl = builder.is_zero_point(dbl_z);
        let isz_add = builder.is_zero_point(add_zz);

        builder.assert_on_curve(z);
        builder.assert_on_curve(neg_z);
        builder.assert_on_curve(dbl_z);
        builder.assert_on_curve(add_zz);

        builder.register_public_input(eq_neg.target);
        builder.register_public_input(eq_dbl.target);
        builder.register_public_input(eq_add.target);
        builder.register_public_input(isz_neg.target);
        builder.register_public_input(isz_dbl.target);
        builder.register_public_input(isz_add.target);

        let pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());

        assert_eq!(pis[0], F::ONE);
        assert_eq!(pis[1], F::ONE);
        assert_eq!(pis[2], F::ONE);

        assert_eq!(pis[3], F::ONE);
        assert_eq!(pis[4], F::ONE);
        assert_eq!(pis[5], F::ONE);
    }
    #[test]
    fn test_is_equal_point_zero_vs_nonzero() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let z = builder.zero_point();
        let nz = builder.constant_point_unsafe(
            [F::ZERO; 5].into(),
            [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO].into(),
            [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO].into(), // u != 0 => non-zero point (for is_zero_point)
            [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO].into(),
        );

        let eq_zz = builder.is_equal_point(z, z);
        let eq_znz = builder.is_equal_point(z, nz);
        let eq_nzz = builder.is_equal_point(nz, z);

        builder.register_public_input(eq_zz.target);
        builder.register_public_input(eq_znz.target);
        builder.register_public_input(eq_nzz.target);

        let pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());
        assert_eq!(pis[0], F::ONE);
        assert_eq!(pis[1], F::ZERO);
        assert_eq!(pis[2], F::ZERO);
    }

    #[test]
    fn test_assert_non_zero_point_rejects_zero() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let z = builder.zero_point();

        // This must fail: z is zero by definition (u=0)
        builder.assert_non_zero_point(z);

        prove_err(builder, PartialWitness::<F>::new());
    }

    #[test]
    fn test_generator_matches_native_and_is_valid() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Generator in circuit
        let g = builder.generator();

        // Structural checks
        builder.assert_on_curve(g);
        builder.assert_non_zero_point(g);

        // Expose coordinates
        builder.register_point_public_input(g);

        let data = builder.build::<Cfg>();
        let proof = data.prove(PartialWitness::<F>::new()).unwrap();
        data.verify(proof.clone()).unwrap();

        let pis = proof.public_inputs;

        let expected = native_generator();

        // public inputs are in order x,z,u,t (each 5 limbs)
        for i in 0..5 {
            assert_eq!(pis[i], expected.x.0[i]);
            assert_eq!(pis[5 + i], expected.z.0[i]);
            assert_eq!(pis[10 + i], expected.u.0[i]);
            assert_eq!(pis[15 + i], expected.t.0[i]);
        }
    }

    #[test]
    fn test_select_point() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Two arbitrary constant "points" (not necessarily on-curve); this test only checks selection wiring.
        let a = builder.constant_point_unsafe(
            [f(11), f(12), f(13), f(14), f(15)].into(),
            [f(21), f(22), f(23), f(24), f(25)].into(),
            [f(31), f(32), f(33), f(34), f(35)].into(),
            [f(41), f(42), f(43), f(44), f(45)].into(),
        );

        let b = builder.constant_point_unsafe(
            [f(111), f(112), f(113), f(114), f(115)].into(),
            [f(121), f(122), f(123), f(124), f(125)].into(),
            [f(131), f(132), f(133), f(134), f(135)].into(),
            [f(141), f(142), f(143), f(144), f(145)].into(),
        );

        let c = builder.add_virtual_bool_target_safe();
        let sel = builder.select_point(c, a, b);
        builder.register_point_public_input(sel);

        let data = builder.build::<Cfg>();

        // Case c=true => choose a
        {
            let mut pw = PartialWitness::<F>::new();
            pw.set_bool_target(c, true).unwrap();

            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();
            let pis = proof.public_inputs;

            assert_point_pis_eq(
                &pis,
                0,
                &[
                    [f(11), f(12), f(13), f(14), f(15)],
                    [f(21), f(22), f(23), f(24), f(25)],
                    [f(31), f(32), f(33), f(34), f(35)],
                    [f(41), f(42), f(43), f(44), f(45)],
                ],
            );
        }
        // Case c=false => choose b
        {
            let mut pw = PartialWitness::<F>::new();
            pw.set_bool_target(c, false).unwrap();

            let proof = data.prove(pw).unwrap();
            data.verify(proof.clone()).unwrap();
            let pis = proof.public_inputs;

            assert_point_pis_eq(
                &pis,
                0,
                &[
                    [f(111), f(112), f(113), f(114), f(115)],
                    [f(121), f(122), f(123), f(124), f(125)],
                    [f(131), f(132), f(133), f(134), f(135)],
                    [f(141), f(142), f(143), f(144), f(145)],
                ],
            );
        }
    }

    #[test]
    fn test_is_equal_point_projective_equivalence() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Construct p and q such that:
        //   q.x = p.x * kx, q.z = p.z * kx  => X/Z same
        //   q.u = p.u * ku, q.t = p.t * ku  => U/T same
        // and u != 0 so they are treated as non-zero points by is_equal_point.
        let p = builder.constant_point_unsafe(
            [f(2), f(0), f(0), f(0), f(0)].into(), // x
            [f(3), f(0), f(0), f(0), f(0)].into(), // z
            [f(5), f(0), f(0), f(0), f(0)].into(), // u (non-zero)
            [f(7), f(0), f(0), f(0), f(0)].into(), // t
        );

        let kx = f(9);
        let ku = f(11);

        let q = builder.constant_point_unsafe(
            [f(2) * kx, f(0), f(0), f(0), f(0)].into(),
            [f(3) * kx, f(0), f(0), f(0), f(0)].into(),
            [f(5) * ku, f(0), f(0), f(0), f(0)].into(),
            [f(7) * ku, f(0), f(0), f(0), f(0)].into(),
        );

        // A clearly different point (break X/Z)
        let r = builder.constant_point_unsafe(
            [f(2) * kx + F::ONE, f(0), f(0), f(0), f(0)].into(),
            [f(3) * kx, f(0), f(0), f(0), f(0)].into(),
            [f(5) * ku, f(0), f(0), f(0), f(0)].into(),
            [f(7) * ku, f(0), f(0), f(0), f(0)].into(),
        );

        let eq_pq = builder.is_equal_point(p, q);
        let eq_pr = builder.is_equal_point(p, r);

        builder.register_public_input(eq_pq.target);
        builder.register_public_input(eq_pr.target);

        let pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());

        assert_eq!(
            pis[0],
            F::ONE,
            "p and q should be equal by cross-product checks"
        );
        assert_eq!(pis[1], F::ZERO, "p and r should not be equal");
    }

    #[test]
    fn test_assert_on_curve_accepts_additions_and_doublings() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let g = builder.generator();

        // Quelques points
        let g2 = builder.double_point(g);
        let g3 = builder.add_point(g2, g);
        let g4 = builder.double_point(g2);
        let g5 = builder.add_point(g4, g);

        // Tous doivent être sur la courbe
        builder.assert_on_curve(g);
        builder.assert_on_curve(g2);
        builder.assert_on_curve(g3);
        builder.assert_on_curve(g4);
        builder.assert_on_curve(g5);

        // Et non nuls
        builder.assert_non_zero_point(g2);
        builder.assert_non_zero_point(g3);
        builder.assert_non_zero_point(g4);
        builder.assert_non_zero_point(g5);

        let _pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());
    }

    #[test]
    fn test_assert_on_curve_accepts_native_points() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // Points natives: G, 2G, 3G, 5G (calculés côté arith)
        let g = crate::arith::curve::Point::GENERATOR;
        let g2 = g.double();
        let g3 = g2 + g;
        let g5 = g3 + g2;

        let tg = builder.constant_point_unsafe(g.X.into(), g.Z.into(), g.U.into(), g.T.into());
        let tg2 = builder.constant_point_unsafe(g2.X.into(), g2.Z.into(), g2.U.into(), g2.T.into());
        let tg3 = builder.constant_point_unsafe(g3.X.into(), g3.Z.into(), g3.U.into(), g3.T.into());
        let tg5 = builder.constant_point_unsafe(g5.X.into(), g5.Z.into(), g5.U.into(), g5.T.into());

        builder.assert_on_curve(tg);
        builder.assert_on_curve(tg2);
        builder.assert_on_curve(tg3);
        builder.assert_on_curve(tg5);

        builder.assert_non_zero_point(tg);
        builder.assert_non_zero_point(tg2);
        builder.assert_non_zero_point(tg3);
        builder.assert_non_zero_point(tg5);

        let _pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());
    }

    #[test]
    fn test_assert_on_curve_rejects_tampered_x() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        let mut bad = native_generator();

        // Tamper: x[0] += 1
        bad.x.0[0] += F::ONE;

        let bad = builder.constant_point_unsafe(bad.x, bad.z, bad.u, bad.t);
        builder.assert_on_curve(bad);

        prove_err(builder, PartialWitness::<F>::new());
    }

    #[test]
    fn test_assert_on_curve_bypasses_when_u_is_zero() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

        // u = 0 => bypass
        let junk = builder.constant_point_unsafe(
            [F::from_canonical_u64(123); 5].into(), // X junk
            [F::from_canonical_u64(456); 5].into(), // Z junk
            [F::ZERO; 5].into(),                    // U = 0  => bypass
            [F::from_canonical_u64(789); 5].into(), // T junk
        );

        builder.assert_on_curve(junk);

        let _pis = prove_and_get_public_inputs(builder, PartialWitness::<F>::new());
    }
    #[test]
    fn test_partial_witness_point_set_then_get_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let p = builder.add_virtual_point_target();

        let mut pw = PartialWitness::<F>::new();

        // Valeurs “non triviales” pour éviter qu’un swap passe inaperçu.
        let mk = |base: u64| -> [F; 5] {
            [
                F::from_canonical_u64(base + 1),
                F::from_canonical_u64(base + 2),
                F::from_canonical_u64(base + 3),
                F::from_canonical_u64(base + 4),
                F::from_canonical_u64(base + 5),
            ]
        };

        let v = crate::encoding::Point::<F> {
            x: mk(10).into(),
            z: mk(20).into(),
            u: mk(30).into(),
            t: mk(40).into(),
        };

        pw.set_point_target(p, v).unwrap();
        let got = pw.get_point_target(p);

        assert_eq!(got.x.0, v.x.0);
        assert_eq!(got.z.0, v.z.0);
        assert_eq!(got.u.0, v.u.0);
        assert_eq!(got.t.0, v.t.0);
    }
    #[test]
    fn test_partial_witness_point_populates_public_inputs_correctly() {
        use plonky2::iop::witness::PartialWitness;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let p = builder.add_virtual_point_target();

        builder.register_point_public_input(p);

        let v = native_generator();

        let mut pw = PartialWitness::<F>::new();
        pw.set_point_target(p, v.clone()).unwrap();

        let pis = prove_and_get_public_inputs(builder, pw);

        // Ordre: x(5), z(5), u(5), t(5)
        assert_eq!(&pis[0..5], v.x.0.as_slice());
        assert_eq!(&pis[5..10], v.z.0.as_slice());
        assert_eq!(&pis[10..15], v.u.0.as_slice());
        assert_eq!(&pis[15..20], v.t.0.as_slice());
    }
}
