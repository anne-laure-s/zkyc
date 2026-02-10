use std::fmt::Write;

use chrono::{Datelike, NaiveDate};
use plonky2::field::types::Field;
use rand::Rng;

use crate::{
    circuit,
    core::{
        conversion::{ToField, ToPointField, ToSingleField},
        date::{
            days_from_origin, generate_birth_date, generate_birth_date_minor,
            generate_expiration_date,
        },
    },
    issuer,
    schnorr::{
        keys::{PublicKey, SecretKey},
        signature::{Context, Signature},
    },
};

pub struct Credential {
    first_name: Name,
    family_name: Name,
    birth_date: NaiveDate,
    place_of_birth: Place,
    gender: Gender,
    nationality: Nationality,
    passport_number: PassportNumber,
    expiration_date: NaiveDate,
    issuer: Issuer, // TODO: public_key instead
}

// ----

#[derive(Debug)]
struct Name(String);

#[derive(Debug)]
struct Place(String);

struct Issuer(PublicKey);

#[derive(Debug)]
enum Gender {
    M,
    F,
}

#[derive(Debug)]
pub enum Nationality {
    FR,
    // EN,
}

#[derive(Debug)]
enum PassportNumber {
    French(FrenchPassportNumber),
}

#[derive(Debug)]
struct FrenchPassportNumber([u8; 9]);

impl<F: Field> ToSingleField<F> for Gender {
    fn to_field(&self) -> F {
        match self {
            Self::M => F::ZERO,
            Self::F => F::ONE,
        }
    }
}

impl<F: Field> ToSingleField<F> for Nationality {
    fn to_field(&self) -> F {
        self.code().to_field()
    }
}

impl<F: Field> ToSingleField<F> for NaiveDate {
    fn to_field(&self) -> F {
        days_from_origin(*self).to_field()
    }
}

impl<F: Field> ToPointField<F> for Issuer {
    fn to_field(&self) -> crate::circuit::Point<F> {
        crate::circuit::Point::from_point(&self.0 .0)
    }
}

impl<F: Field> ToField<F, 3> for PassportNumber {
    fn to_field(&self) -> [F; 3] {
        match self {
            Self::French(n) => n.to_field(),
        }
    }
}

impl<F: Field> ToField<F, 3> for FrenchPassportNumber {
    fn to_field(&self) -> [F; 3] {
        let fst = {
            let bytes_32: [u8; 4] = self.0[..4].try_into().unwrap();
            u32::from_le_bytes(bytes_32)
        };
        let snd = {
            let bytes_32: [u8; 4] = self.0[4..8].try_into().unwrap();
            u32::from_le_bytes(bytes_32)
        };
        let trd = self.0[8] as u32; // le conversion of the last byte
        vec![fst.to_field(), snd.to_field(), trd.to_field()]
            .try_into()
            .unwrap()
    }
}

/// for now, 20 chars max, encoded on u32 converted to field elements
impl<F: Field> ToField<F, 5> for String {
    fn to_field(&self) -> [F; 5] {
        let mut res = [F::ZERO; 5];
        let mut buffer = [0; 4];
        for (i, c) in self.chars().enumerate() {
            let i_mod = i % 4;
            buffer[i_mod] = c as u8;
            if i_mod == 3 {
                // FIXME: we expect this to fail if string is bigger than 5 field elements, but we should throw a proper error
                res[i / 4] = u32::from_le_bytes(buffer).to_field()
            }
        }
        res
    }
}

impl Gender {
    fn rnd(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..2) {
            0 => Self::M,
            1 => Self::F,
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for Gender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::F => f.write_str("F"),
            Self::M => f.write_str("M"),
        }
    }
}

// TODO: We may be able to use country code, or smth similar instead
impl Nationality {
    // TODO: smoother way to deal with nationalities
    fn rnd(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..1) {
            0 => Self::FR,
            // 1 => Self::EN,
            _ => unreachable!(),
        }
    }
    pub fn code(&self) -> u16 {
        match self {
            Nationality::FR => 250,
        }
    }
}

impl std::fmt::Display for Nationality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FR => f.write_str("FR"),
        }
    }
}

impl PassportNumber {
    fn rnd(rng: &mut impl Rng) -> Self {
        Self::French(FrenchPassportNumber::rnd(rng))
    }
}

impl std::fmt::Display for PassportNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassportNumber::French(number) => number.fmt(f),
        }
    }
}

impl FrenchPassportNumber {
    fn rnd(rng: &mut impl Rng) -> Self {
        let mut res = [0; 9];
        res[0..2]
            .iter_mut()
            .for_each(|z| *z = b'0' + rng.random_range(0..10) as u8);
        res[2..4]
            .iter_mut()
            .for_each(|z| *z = b'A' + (rng.random_range(0..26) as u8));
        res[4..9]
            .iter_mut()
            .for_each(|z| *z = b'0' + rng.random_range(0..10) as u8);
        FrenchPassportNumber(res)
    }
    fn check(&self) -> bool {
        self.0[0..2].iter().all(u8::is_ascii_digit)
            && self.0[2..4].iter().all(u8::is_ascii_uppercase)
            && self.0[4..9].iter().all(u8::is_ascii_digit)
    }
}

impl std::fmt::Display for FrenchPassportNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &b in self.0.iter() {
            f.write_char(b as char)?
        }
        Ok(())
    }
}

impl Credential {
    pub fn nationality(&self) -> &Nationality {
        &self.nationality
    }
    pub fn birth_date(&self) -> &NaiveDate {
        &self.birth_date
    }
    pub fn random(rng: &mut impl Rng) -> Self {
        fn generate_name(rng: &mut impl Rng) -> String {
            let len = rng.random_range(3..20);
            let mut res = String::with_capacity(len);
            res.push((b'A' + rng.random_range(0..26)) as char);
            for _ in 1..len {
                res.push((b'a' + rng.random_range(0..26)) as char);
            }
            res
        }
        Credential {
            first_name: Name(generate_name(rng)),
            family_name: Name(generate_name(rng)),
            birth_date: generate_birth_date(rng),
            place_of_birth: Place(generate_name(rng)),
            gender: Gender::rnd(rng),
            nationality: Nationality::rnd(rng),
            passport_number: PassportNumber::rnd(rng),
            expiration_date: generate_expiration_date(rng),
            issuer: Issuer(issuer::keys::public()),
        }
    }
    pub fn random_minor(rng: &mut impl Rng) -> Self {
        fn generate_name(rng: &mut impl Rng) -> String {
            let len = rng.random_range(3..20);
            let mut res = String::with_capacity(len);
            res.push((b'A' + rng.random_range(0..26)) as char);
            for _ in 1..len {
                res.push((b'a' + rng.random_range(0..26)) as char);
            }
            res
        }
        Credential {
            first_name: Name(generate_name(rng)),
            family_name: Name(generate_name(rng)),
            birth_date: generate_birth_date_minor(rng),
            place_of_birth: Place(generate_name(rng)),
            gender: Gender::rnd(rng),
            nationality: Nationality::rnd(rng),
            passport_number: PassportNumber::rnd(rng),
            expiration_date: generate_expiration_date(rng),
            issuer: Issuer(issuer::keys::public()),
        }
    }

    // TODO: fn new, with relevant checks (especially that everything is ascii, and not too long; dates’ year non negative (will overflow otherwise))

    // assumes every field is less than 255 bytes in size
    /// TODO: a versioning bytes could be added as a heading
    /// Everything is represented as big endian
    pub fn as_bytes(&self) -> Vec<u8> {
        fn push_str(res: &mut Vec<u8>, s: &str) {
            res.push(s.len() as u8); // everything is ascii so s.len() == s.as_bytes().len()
            res.extend_from_slice(s.as_bytes());
        }
        fn push_date(res: &mut Vec<u8>, date: &NaiveDate) {
            let y = date.year() as u32;
            let m = date.month();
            let d = date.day();
            let v = y * 10_000 + m * 100 + d;
            res.extend_from_slice(&v.to_le_bytes());
        }
        let mut res = vec![];
        push_str(&mut res, &self.first_name.0);
        push_str(&mut res, &self.family_name.0);
        push_date(&mut res, &self.birth_date);
        push_str(&mut res, &self.place_of_birth.0);
        res.push(match self.gender {
            Gender::M => 0,
            Gender::F => 1,
        });
        res.extend_from_slice(self.nationality.code().to_le_bytes().as_slice());
        push_str(&mut res, &self.passport_number.to_string());
        push_date(&mut res, &self.expiration_date);
        res.extend_from_slice(&self.issuer.0 .0.to_affine().x.encode());
        res.extend_from_slice(&self.issuer.0 .0.to_affine().u.encode());
        res
    }

    pub fn sign(&self, sk: &SecretKey, pk: &PublicKey) -> Signature {
        Signature::sign(sk, &Context::new(pk, self.as_bytes()))
    }

    pub fn check(&self, pk: &PublicKey, signature: &Signature) -> bool {
        signature.verify(&Context::new(pk, self.as_bytes()))
    }

    pub fn to_field<F: Field>(&self) -> circuit::credential::Credential<F> {
        circuit::credential::Credential {
            first_name: self.first_name.0.to_field(),
            family_name: self.family_name.0.to_field(),
            birth_date: self.birth_date.to_field(),
            place_of_birth: self.place_of_birth.0.to_field(),
            gender: self.gender.to_field(),
            nationality: self.nationality.to_field(),
            passport_number: self.passport_number.to_field(),
            expiration_date: self.expiration_date.to_field(),
            issuer: self.issuer.to_field(),
        }
    }
}
