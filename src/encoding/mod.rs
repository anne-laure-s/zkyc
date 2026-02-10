// FIXME: arbitrary limit of 20 chars for now, each char is 1/4 of u32 -> 5 field elements (of 32 bits, to avoid overfow)

// TODO: add tests for lengths

pub mod conversion;

/// size of a credential<T> in number of T elements
pub const LEN_CREDENTIAL: usize = 42;

/// Representation of a credential inside a circuit
#[derive(Clone)]
pub struct Credential<T> {
    pub first_name: [T; 5],
    pub family_name: [T; 5],
    pub birth_date: T, // number of days since origin
    pub place_of_birth: [T; 5],
    pub gender: T,
    pub nationality: T,
    pub passport_number: [T; 3], // assumed to be french (9 u8)
    pub expiration_date: T,
    pub issuer: Point<T>,
}

// 1 u32 = 4 ascii chars

#[derive(Clone)]
pub struct Point<T> {
    pub x: [T; 5],
    pub z: [T; 5],
    pub u: [T; 5],
    pub t: [T; 5],
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
