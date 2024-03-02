use crate::SCALAR_FIELD_ORDER;
use blstrs::Scalar;
use num_bigint::BigUint;
use num_integer::Integer;
use sha3::Digest;

pub(crate) mod biguint;
pub(crate) mod fiat_shamir;
pub mod random;
pub(crate) mod serialization;

#[inline]
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1) == 0)
}

/// Hashes the specified `msg` and domain separation tag `dst` into a `Scalar` by computing a 512-bit
/// number as SHA3-512(SHA3-512(dst) || msg) and reducing it modulo the order of the field.
/// (Same design as in `curve25519-dalek` explained here https://crypto.stackexchange.com/questions/88002/how-to-map-output-of-hash-algorithm-to-a-finite-field)
///
/// TODO(Security): Domain separation from other SHA3-512 calls in our system is left up to the caller, who must use a `dst`. I think this is okay.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst);
    let binding = hasher.finalize();
    let dst_hash = binding.as_slice();

    let mut hasher = sha3::Sha3_512::new();
    hasher.update(dst_hash);
    hasher.update(msg);
    let binding = hasher.finalize();
    let bytes = binding.as_slice();

    assert_eq!(bytes.len(), 64);

    let bignum = BigUint::from_bytes_le(&bytes);
    let remainder = bignum.mod_floor(&SCALAR_FIELD_ORDER);

    biguint::biguint_to_scalar(&remainder)
}
