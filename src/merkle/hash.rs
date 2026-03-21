use crate::encoding::{Hash, LEN_HASH};
use crate::{core::credential::Credential, encoding::LEN_CREDENTIAL};
use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::Hasher,
};

// FIXME: add tags

pub fn empty<F: RichField>() -> Hash<F> {
    Hash([F::ZERO; LEN_HASH])
}

pub fn poseidon<F: RichField>(base_inputs: &[F]) -> Hash<F> {
    Hash(PoseidonHash::hash_no_pad(base_inputs).elements)
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
    buffer[..LEN_HASH].copy_from_slice(&h1.0);
    buffer[LEN_HASH..].copy_from_slice(&h2.0);
    poseidon(buffer)
}

fn merge<F: RichField>(h1: &Hash<F>, h2: &Hash<F>) -> Hash<F> {
    merge_with_buffer(&mut [F::ZERO; 2 * LEN_HASH], h1, h2)
}

pub(crate) fn merge_left_right<F: RichField>(
    node: &Hash<F>,
    is_left: bool,
    neighbor: &Hash<F>,
) -> Hash<F> {
    if is_left {
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
