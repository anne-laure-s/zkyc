use anyhow::Ok;
use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    circuit::{
        credential::CredentialTarget,
        hash::{CircuitBuilderHash, HashTarget, PartialWitnessHash},
    },
    encoding::{self, LEN_CREDENTIAL, LEN_HASH},
    issuer,
};

type ProofTarget = encoding::MerklePath<{ issuer::database::SIZE }, Target, BoolTarget>;
type Proof<F> = encoding::MerklePath<{ issuer::database::SIZE }, F, bool>;

pub trait CircuitBuilderMerkleProof<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_merkle_proof_target(&mut self) -> ProofTarget;
    fn register_merkle_proof_public_input(&mut self, target: ProofTarget);
    // TODO: factorize hash credential here & in signature verification
    fn check_merkle_proof(
        &mut self,
        credential: &CredentialTarget,
        proof: ProofTarget,
        root: HashTarget,
    );
}
pub trait PartialWitnessMerkleProof<F: RichField>: Witness<F> {
    fn get_merkle_proof_target(&self, target: ProofTarget) -> Proof<F>;
    fn set_merkle_proof_target(
        &mut self,
        target: ProofTarget,
        value: Proof<F>,
    ) -> anyhow::Result<()>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderMerkleProof<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_merkle_proof_target(&mut self) -> ProofTarget {
        encoding::MerklePath {
            path: (std::array::from_fn::<_, { issuer::database::SIZE }, _>(|_| {
                encoding::Hash(std::array::from_fn::<_, LEN_HASH, _>(|_| {
                    self.add_virtual_target()
                }))
            })),
            positions: std::array::from_fn::<_, { issuer::database::SIZE }, _>(|_| {
                self.add_virtual_bool_target_safe()
            }),
        }
    }
    fn register_merkle_proof_public_input(&mut self, target: ProofTarget) {
        for hash in target.path.into_iter() {
            for t in hash.0.into_iter() {
                self.register_public_input(t)
            }
        }
        for position in target.positions.into_iter() {
            self.register_public_input(position.target);
        }
    }
    // TODO: there might be already built in functions for this (verify_merkle_proof)
    fn check_merkle_proof(
        &mut self,
        credential: &CredentialTarget,
        proof: ProofTarget,
        root: HashTarget,
    ) {
        let credential: [Target; LEN_CREDENTIAL] = credential.into();
        // TODO: maybe relevant to factorize with sig verification
        let credential_hash: HashTarget = self
            .hash_n_to_hash_no_pad::<PoseidonHash>(credential.to_vec())
            .into();
        let claimed_root = proof
            .positions
            .into_iter()
            .zip(proof.path.into_iter())
            .fold(credential_hash, |acc, (is_left, neighbor)| {
                self.merge_left_right(acc, is_left, neighbor)
            });
        self.connect_hash(claimed_root, root);
    }
}

impl<W: Witness<F>, F: RichField> PartialWitnessMerkleProof<F> for W {
    fn get_merkle_proof_target(&self, target: ProofTarget) -> Proof<F> {
        encoding::MerklePath {
            path: target
                .path
                .map(|t| PartialWitnessHash::get_hash_target(self, t)),
            positions: target.positions.map(|t| self.get_bool_target(t)),
        }
    }
    fn set_merkle_proof_target(
        &mut self,
        target: ProofTarget,
        value: Proof<F>,
    ) -> anyhow::Result<()> {
        for (target, value) in target.path.into_iter().zip(value.path.into_iter()) {
            PartialWitnessHash::set_hash_target(self, target, value)?;
        }
        for (target, value) in target
            .positions
            .into_iter()
            .zip(value.positions.into_iter())
        {
            self.set_bool_target(target, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField as F,
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        circuit::{
            credential::{CircuitBuilderCredential, PartialWitnessCredential},
            hash::{CircuitBuilderHash, PartialWitnessHash},
        },
        core::credential::Credential,
        merkle::Tree,
    };

    const D: usize = 2;
    type Cfg = PoseidonGoldilocksConfig;

    fn credential_from_seed(seed: u64) -> Credential {
        let mut rng = StdRng::seed_from_u64(seed);
        let (_, _, credential) = Credential::random(&mut rng);
        credential
    }

    #[test]
    fn test_register_merkle_proof_public_input_count() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = builder.add_virtual_merkle_proof_target();
        builder.register_merkle_proof_public_input(proof_t);

        let data = builder.build::<Cfg>();
        let expected = issuer::database::SIZE * (LEN_HASH + 1);
        assert_eq!(data.common.num_public_inputs, expected);
    }

    #[test]
    fn test_set_get_merkle_proof_roundtrip() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = builder.add_virtual_merkle_proof_target();
        let data = builder.build::<Cfg>();

        let credentials = vec![
            credential_from_seed(1),
            credential_from_seed(2),
            credential_from_seed(3),
        ];
        let tree = Tree::<{ issuer::database::SIZE }, F>::from(&credentials).unwrap();
        let proof = tree.prove(&credentials[1]).unwrap();

        let mut pw = PartialWitness::<F>::new();
        pw.set_merkle_proof_target(proof_t, proof).unwrap();

        let got = pw.get_merkle_proof_target(proof_t);
        let expected = tree.prove(&credentials[1]).unwrap();
        assert_eq!(got, expected);

        let proof = data
            .prove(pw)
            .expect("witness should satisfy the empty circuit");
        data.verify(proof).expect("proof should verify");
    }

    #[test]
    fn test_verify_merkle_proof_accepts_valid_proof() {
        let credentials = vec![
            credential_from_seed(10),
            credential_from_seed(11),
            credential_from_seed(12),
            credential_from_seed(13),
        ];
        let tree = Tree::<{ issuer::database::SIZE }, F>::from(&credentials).unwrap();
        let credential = credentials[2].clone();
        let proof = tree.prove(&credential).unwrap();
        let root = tree.root();

        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let credential_t = builder.add_virtual_credential_target();
        let proof_t = builder.add_virtual_merkle_proof_target();
        let root_t = builder.add_virtual_hash_target();

        builder.check_merkle_proof(&credential_t, proof_t, root_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_credential_target(credential_t, credential.to_field())
            .unwrap();
        pw.set_merkle_proof_target(proof_t, proof).unwrap();
        pw.set_hash_target(root_t, root).unwrap();

        let data = builder.build::<Cfg>();
        let proof = data.prove(pw).expect("prove should pass");
        data.verify(proof).expect("verify should pass");
    }

    #[test]
    fn test_verify_merkle_proof_rejects_invalid_proof() {
        let credentials = vec![
            credential_from_seed(10),
            credential_from_seed(11),
            credential_from_seed(12),
            credential_from_seed(13),
        ];
        let tree = Tree::<{ issuer::database::SIZE }, F>::from(&credentials).unwrap();
        let credential = credentials[2].clone();
        let mut proof = tree.prove(&credential).unwrap();
        proof.positions[0] = !proof.positions[0];
        let root = tree.root();

        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let credential_t = builder.add_virtual_credential_target();
        let proof_t = builder.add_virtual_merkle_proof_target();
        let root_t = builder.add_virtual_hash_target();

        builder.check_merkle_proof(&credential_t, proof_t, root_t);

        let mut pw = PartialWitness::<F>::new();
        pw.set_credential_target(credential_t, credential.to_field())
            .unwrap();
        pw.set_merkle_proof_target(proof_t, proof).unwrap();
        pw.set_hash_target(root_t, root).unwrap();

        let data = builder.build::<Cfg>();
        let proof = data.prove(pw);
        assert!(proof.is_err())
    }
}
