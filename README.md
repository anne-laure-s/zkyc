# zKYC

This project is a PoC for a zero-knowledge-powered KYC system. It aims to allow institutions like banks to verify the identity of their customers without having to store personal information, which is subject to leaks.

## Participants and roles

There are 3 participants in this system:
- User (citizen): the user creates zero-knowledge proofs of their identity
- Government: it issues passports and credentials, and stores the correspondence between credentials and the user's public key
- Bank (and other institutions that need KYC): it checks users’ proofs against government information

## Credential

The credential contains identity information as well as the user’s public key. Relevant information in this project includes:
* First name
* Family name
* Date of birth
* Place of birth
* Gender
* Nationality
* Passport number
* Expiration date
* Issuer

The credential is issued and signed by the government.

## Protocol

### Passport issuing

When a citizen asks for a credential, and after their identity is verified by traditional methods, they must provide a public key (for which they know the secret key). The government will then issue a credential containing identity information and this public key, and sign the credential.

In this project, it is the responsibility of the citizen to create and store their secret key, because the government does not know it (we don’t want the government to be able to sign on behalf of citizens).

### Proving KYC

A zKYC proof proves the following statements:
1. The user knows a credential that matches the required information.
2. This credential has been signed by the State.
3. This credential has not been revoked.
4. The user knows the secret key corresponding to the public key in the credential.
5. TODO: anonymization: the derived public key is correctly derived from the secret/public key of the credential.

#### Base information

The circuit simply checks that the credential identity fulfills the KYC requirements.

#### Signature checks

Signatures must be checked inside the circuit. This means that the signature scheme has to be zk-friendly.

#### Non-revocation

We expect the credential of a person who dies to no longer be valid. The State maintains a Merkle tree of valid credentials and updates it every day. Generated proofs are made with respect to this commitment.

TODO: Each update involves a change in the Merkle path. The user needs a way to retrieve their Merkle path when needed.

## Stack

Many of the following choices are made to optimize:
- ZK-friendliness
- Plonky2 compatibility

### Proof system

In this PoC, we use Plonky2. Note that the soundness might not be sufficient for production, but we accept this trade-off for this PoC. If this project is pushed further, changing or adapting the proof system will probably be necessary.

Many other choices rely on their compatibility with Plonky2.

### Curve & Field

For the curve, we chose [EcGFp5](https://github.com/pornin/ecgfp5/blob/main/doc/ecgfp5.pdf), whose base field is a degree-5 extension of Goldilocks, the foundational field of Plonky2.

[This implementation](https://github.com/pornin/ecgfp5/tree/main/rust/src) is used and vendored in `src/arith`. The RNG has been changed for tests, and some functions have been added for our use case:
- in `scalar.rs`:
  - `random`
  - `from_gfp5`
- in `curve.rs`:
  - `to_affine`

### Hash

Poseidon.

### Signature scheme

For a ZK-friendly signature scheme, we use Schnorr.

## TODO

- [x] Base Schnorr implementation
- [ ] Issuer signature verification (will add consistency between the credential and verified properties)
- [ ] Authentication verification
- [ ] Derive one key per service
