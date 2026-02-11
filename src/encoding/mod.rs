// FIXME: arbitrary limit of 20 chars for now, each char is 1/4 of u32 -> 5 field elements (of 32 bits, to avoid overfow)

// TODO: add tests for lengths

pub mod conversion;

pub const LEN_STRING: usize = 5;
pub const LEN_PASSPORT_NUMBER: usize = 3;
pub const LEN_EXTENSION_FIELD: usize = 5;

/// size of a credential<T> in number of T elements
pub const LEN_CREDENTIAL: usize =
    3 * LEN_STRING + LEN_PASSPORT_NUMBER + 4 + 4 * LEN_EXTENSION_FIELD;

/// Representation of a credential inside a circuit
#[derive(Clone)]
pub struct Credential<T> {
    pub first_name: [T; LEN_STRING],
    pub family_name: [T; LEN_STRING],
    pub birth_date: T, // number of days since origin
    pub place_of_birth: [T; LEN_STRING],
    pub gender: T,
    pub nationality: T,
    pub passport_number: [T; LEN_PASSPORT_NUMBER], // assumed to be french (9 u8)
    pub expiration_date: T,
    pub issuer: Point<T>,
}

// 1 u32 = 4 ascii chars

#[derive(Clone)]
pub struct Point<T> {
    pub x: [T; LEN_EXTENSION_FIELD],
    pub z: [T; LEN_EXTENSION_FIELD],
    pub u: [T; LEN_EXTENSION_FIELD],
    pub t: [T; LEN_EXTENSION_FIELD],
}

impl<T> From<Credential<T>> for [T; LEN_CREDENTIAL] {
    fn from(value: Credential<T>) -> Self {
        let mut res = Vec::with_capacity(LEN_CREDENTIAL);
        res.extend(value.first_name);
        res.extend(value.family_name);
        res.push(value.birth_date);
        res.extend(value.place_of_birth);
        res.push(value.gender);
        res.push(value.nationality);
        res.extend(value.passport_number);
        res.push(value.expiration_date);
        res.extend(value.issuer.x);
        res.extend(value.issuer.z);
        res.extend(value.issuer.u);
        res.extend(value.issuer.t);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given credential don't fit the right length"))
    }
}
