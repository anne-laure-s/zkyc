use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::Hasher,
};

use crate::{core::credential::Credential, encoding::LEN_CREDENTIAL};

// FIXME: add tags
// FIXME: centralize every hash of the repository (this, schnorr, etc)
pub const LEN_HASH: usize = 4;
pub type Hash<F> = [F; LEN_HASH];

pub fn empty<F: RichField>() -> Hash<F> {
    [F::ZERO; LEN_HASH]
}

pub fn poseidon<F: RichField>(base_inputs: &[F]) -> Hash<F> {
    PoseidonHash::hash_no_pad(base_inputs).elements
}
pub fn credential<F: RichField>(credential: &Credential) -> Hash<F> {
    let message: [F; LEN_CREDENTIAL] = (&credential.to_field()).into();
    poseidon(&message)
}

fn merge_with_buffer<F: RichField>(
    buffer: &mut [F; LEN_HASH * 2],
    h1: &Hash<F>,
    h2: &Hash<F>,
) -> Hash<F> {
    buffer[..LEN_HASH].copy_from_slice(h1);
    buffer[LEN_HASH..].copy_from_slice(h2);
    poseidon(buffer)
}

fn merge<F: RichField>(h1: &Hash<F>, h2: &Hash<F>) -> Hash<F> {
    merge_with_buffer(&mut [F::ZERO; 2 * LEN_HASH], h1, h2)
}

pub(crate) fn merge_left_right<F: RichField>(
    node: &Hash<F>,
    neighbor: &Hash<F>,
    node_index: usize,
) -> Hash<F> {
    if node_index.is_multiple_of(2) {
        merge(node, neighbor)
    } else {
        merge(neighbor, node)
    }
}

pub(crate) fn hash_vec<F: RichField>(inputs: &[Hash<F>]) -> Vec<Hash<F>> {
    let mut res = Vec::with_capacity(inputs.len() / 2);
    let mut buffer = [F::ZERO; 2 * LEN_HASH];
    for l in inputs.chunks(2) {
        res.push(merge_with_buffer(&mut buffer, &l[0], &l[1]));
    }
    res
}
