use std::fmt::Write;

use chrono::{Datelike, NaiveDate};
use rand::Rng;

use crate::{
    core::date::{generate_birth_date, generate_birth_date_minor, generate_expiration_date},
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
}
