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
