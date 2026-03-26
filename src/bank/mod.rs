use rand::{rngs::StdRng, Rng, SeedableRng};

// FIXME: generate nonce correctly, this is totally insecure
pub fn nonce() -> String {
    // TODO: unify this with string generation for credential tests
    let mut rng = StdRng::seed_from_u64(42);
    let len = 19;
    let mut res = String::with_capacity(len);
    for _ in 1..len {
        res.push((b'A' + rng.random_range(0..26)) as char);
    }
    res
}

pub fn service() -> String {
    String::from("ZBanK")
}

pub fn verify_client_proof(
    circuit: &Circuit,
    proof: ZkProof,
    // claimed pseudonym for the client
    pseudonym: encoding::Pseudonym<circuit::F>,
) -> anyhow::Result<()> {
    let issuer_root = issuer::database::for_tests::DATABASE.root();
    let public_inputs = circuit::inputs::Public {
        cutoff18_days: date::cutoff18_from_today().to_field(),
        nationality: Nationality::FR.to_field(),
        issuer_pk: issuer::keys::public().0.to_field(),
        nonce: nonce().to_field(),
        service: service().to_field(),
        pseudonym,
        merkle_root: issuer_root,
    };
    circuit::verify(&circuit.circuit, proof, public_inputs)
}