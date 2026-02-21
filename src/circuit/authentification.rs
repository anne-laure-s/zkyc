use anyhow::Ok;
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
    circuit::{
        curve::{CircuitBuilderCurve, PartialWitnessCurve, PointTarget},
        schnorr::{CircuitBuilderSchnorr, PartialWitnessSchnorr, SchnorrTarget},
        string::{CircuitBuilderString, PartialWitnessString},
    },
    encoding::{self, LEN_POINT, LEN_STRING},
};

pub type AuthentificationTarget = encoding::Authentification<Target, BoolTarget>;

pub type AuthentificationContextTarget = encoding::AuthentificationContext<Target>;

pub trait CircuitBuilderAuthentification<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_authentification_target(&mut self) -> AuthentificationTarget;
    fn add_virtual_authentification_context_target(&mut self) -> AuthentificationContextTarget;
    fn register_authentification_context_public_input(
        &mut self,
        ctx: AuthentificationContextTarget,
    );
    fn hash_authentification(
        &mut self,
        ctx: &AuthentificationContextTarget,
        auth: &AuthentificationTarget,
    ) -> encoding::Scalar<BoolTarget>;
    fn verify_authentification(
        &mut self,
        ctx: &AuthentificationContextTarget,
        auth: &AuthentificationTarget,
    );
}

pub trait PartialWitnessAuthentification<F: RichField>: Witness<F> {
    fn get_authentification_target(
        &self,
        target: AuthentificationTarget,
    ) -> encoding::Authentification<F, bool>;
    fn set_authentification_target(
        &mut self,
        target: AuthentificationTarget,
        value: encoding::Authentification<F, bool>,
    ) -> anyhow::Result<()>;
    fn get_authentification_context_target(
        &self,
        target: AuthentificationContextTarget,
    ) -> encoding::AuthentificationContext<F>;
    fn set_authentification_context_target(
        &mut self,
        target: AuthentificationContextTarget,
        value: encoding::AuthentificationContext<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderAuthentification<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_authentification_target(&mut self) -> AuthentificationTarget {
        encoding::Authentification(self.add_virtual_schnorr_target())
    }

    fn add_virtual_authentification_context_target(&mut self) -> AuthentificationContextTarget {
        AuthentificationContextTarget {
            public_key: self.add_virtual_point_target(),
            service: self.add_virtual_string_target(),
            nonce: self.add_virtual_string_target(),
        }
    }

    fn register_authentification_context_public_input(
        &mut self,
        ctx: AuthentificationContextTarget,
    ) {
        self.register_point_public_input(ctx.public_key);
        self.register_string_public_input(ctx.service);
        self.register_string_public_input(ctx.nonce);
    }

    fn hash_authentification(
        &mut self,
        ctx: &AuthentificationContextTarget,
        auth: &AuthentificationTarget,
    ) -> encoding::Scalar<BoolTarget> {
        let mut message = Vec::with_capacity(2 * LEN_STRING + LEN_POINT);
        message.extend_from_slice(&ctx.service.0);
        message.extend_from_slice(&ctx.nonce.0);
        let public_key: [Target; LEN_POINT] = ctx.public_key.into();
        message.extend_from_slice(&public_key);
        self.schnorr_hash_with_message(auth.0, &message)
    }

    fn verify_authentification(
        &mut self,
        ctx: &AuthentificationContextTarget,
        auth: &AuthentificationTarget,
    ) {
        let e = self.hash_authentification(ctx, auth);
        self.schnorr_final_verification(auth.0, e, ctx.public_key);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessAuthentification<F> for W {
    fn get_authentification_target(
        &self,
        target: AuthentificationTarget,
    ) -> encoding::Authentification<F, bool> {
        encoding::Authentification(self.get_schnorr_target(target.0))
    }

    fn set_authentification_target(
        &mut self,
        target: AuthentificationTarget,
        value: encoding::Authentification<F, bool>,
    ) -> anyhow::Result<()> {
        self.set_schnorr_target(target.0, value.0)
    }

    fn get_authentification_context_target(
        &self,
        target: AuthentificationContextTarget,
    ) -> encoding::AuthentificationContext<F> {
        encoding::AuthentificationContext {
            public_key: self.get_point_target(target.public_key),
            service: self.get_string_target(target.service),
            nonce: self.get_string_target(target.nonce),
        }
    }

    fn set_authentification_context_target(
        &mut self,
        target: AuthentificationContextTarget,
        value: encoding::AuthentificationContext<F>,
    ) -> anyhow::Result<()> {
        self.set_point_target(target.public_key, value.public_key)?;
        self.set_string_target(target.service, value.service)?;
        self.set_string_target(target.nonce, value.nonce)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField as F, types::Field},
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        encoding::{
            conversion::{ToAuthentificationField, ToPointField, ToSignatureField},
            LEN_SCALAR,
        },
        schnorr::{
            self,
            authentification::{Authentification, Context},
            keys::{PublicKey, SecretKey},
        },
    };

    use super::*;

    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;

    fn keypair_from_seed(seed: u64) -> (SecretKey, PublicKey) {
        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    fn ctx_to_target(ctx: &Context) -> encoding::AuthentificationContext<F> {
        encoding::AuthentificationContext {
            public_key: ctx.public_key().0.to_field(),
            service: encoding::String(ctx.service().map(|x| F::from_canonical_u64(x.0))),
            nonce: encoding::String(ctx.nonce().map(|x| F::from_canonical_u64(x.0))),
        }
    }

    #[test]
    fn test_verify_auth_accepts() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let (sk, pk) = keypair_from_seed(1);
        let ctx = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx).to_field();

        let auth_t = builder.add_virtual_authentification_target();
        let ctx_t = builder.add_virtual_authentification_context_target();
        builder.verify_authentification(&ctx_t, &auth_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_authentification_context_target(ctx_t, ctx_to_target(&ctx))
            .unwrap();
        pw.set_authentification_target(auth_t, auth).unwrap();

        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).expect("prove should pass");
        data.verify(proof).expect("verify should pass");
    }

    #[test]
    fn test_verify_auth_fails_if_service_changes() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let (sk, pk) = keypair_from_seed(2);
        let ctx_good = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good).to_field();

        let ctx_bad = Context::new(&pk, b"service-B", b"nonce-1");

        let auth_t = builder.add_virtual_authentification_target();
        let ctx_t = builder.add_virtual_authentification_context_target();
        builder.verify_authentification(&ctx_t, &auth_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_authentification_context_target(ctx_t, ctx_to_target(&ctx_bad))
            .unwrap();
        pw.set_authentification_target(auth_t, auth).unwrap();

        let data = builder.build::<Cfg>();
        let result = data.prove(pw);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_auth_fails_if_nonce_changes() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let (sk, pk) = keypair_from_seed(3);
        let ctx_good = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx_good).to_field();

        let ctx_bad = Context::new(&pk, b"service-A", b"nonce-2");

        let auth_t = builder.add_virtual_authentification_target();
        let ctx_t = builder.add_virtual_authentification_context_target();
        builder.verify_authentification(&ctx_t, &auth_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_authentification_context_target(ctx_t, ctx_to_target(&ctx_bad))
            .unwrap();
        pw.set_authentification_target(auth_t, auth).unwrap();

        let data = builder.build::<Cfg>();
        let result = data.prove(pw);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_auth_fails_if_public_key_changes() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let (sk1, pk1) = keypair_from_seed(4);
        let (_sk2, pk2) = keypair_from_seed(5);

        let ctx_good = Context::new(&pk1, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk1, &ctx_good).to_field();

        let ctx_bad = Context::new(&pk2, b"service-A", b"nonce-1");

        let auth_t = builder.add_virtual_authentification_target();
        let ctx_t = builder.add_virtual_authentification_context_target();
        builder.verify_authentification(&ctx_t, &auth_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_authentification_context_target(ctx_t, ctx_to_target(&ctx_bad))
            .unwrap();
        pw.set_authentification_target(auth_t, auth).unwrap();

        let data = builder.build::<Cfg>();
        let result = data.prove(pw);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_auth_matches_native() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let (sk, pk) = keypair_from_seed(6);
        let ctx = Context::new(&pk, b"service-A", b"nonce-1");
        let auth = Authentification::sign(&sk, &ctx);

        let auth_t = builder.add_virtual_authentification_target();
        let ctx_t = builder.add_virtual_authentification_context_target();
        let e_t = builder.hash_authentification(&ctx_t, &auth_t);
        for b in e_t.0.iter() {
            builder.register_public_input(b.target);
        }

        let mut pw = PartialWitness::<F>::new();
        pw.set_authentification_context_target(ctx_t, ctx_to_target(&ctx))
            .unwrap();
        pw.set_authentification_target(auth_t, auth.to_field())
            .unwrap();

        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).unwrap();

        let auth_field: encoding::Authentification<F, bool> = auth.to_field();
        let r_native: crate::arith::Point = auth_field.0.r.into();
        let e_native =
            schnorr::transcript::hash(&r_native, schnorr::transcript::Context::Auth(&ctx));
        let public_inputs: [F; LEN_SCALAR] = proof.public_inputs.try_into().unwrap();
        let e_circuit = crate::arith::Scalar::from_bits_le(&public_inputs.map(|x| F::is_one(&x)));
        assert!(e_native.equals(e_circuit) == u64::MAX);
    }
}
