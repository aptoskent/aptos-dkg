use crate::pvss::scrape::public_parameters::PublicParameters;
use crate::pvss::scrape::DealtPubKey;
use crate::pvss::scrape::DealtSecretKey;
use crate::pvss::traits;
use crate::utils::random::random_scalar;
use aptos_crypto::traits::Uniform;
use aptos_crypto_derive::{SilentDebug, SilentDisplay};
use blstrs::Scalar;
use rand_core::{CryptoRng, RngCore};
use std::ops::Mul;

/// The *input secret* that will be given as input to the PVSS dealing algorithm. This will be of a
/// different type than the *dealt secret* that will be returned by the PVSS reconstruction algorithm.
///
/// This secret will NOT need to be stored by validators because a validator (1) picks such a secret
/// and (2) deals it via the PVSS. If the validator crashes during dealing, the entire task will be
/// restarted with a freshly-generated input secret.
#[derive(SilentDebug, SilentDisplay, PartialEq)]
pub struct InputSecret {
    /// The actual secret being dealt; a scalar $a \in F$.
    a: Scalar,
}

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(InputSecret: Clone);

//
// InputSecret implementation
//

impl InputSecret {
    pub fn get_secret_a(&self) -> &Scalar {
        &self.a
    }
}

impl Uniform for InputSecret {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let a = random_scalar(rng);

        InputSecret { a }
    }
}

impl traits::Convert<DealtSecretKey, PublicParameters> for InputSecret {
    fn to(&self, pp: &PublicParameters) -> DealtSecretKey {
        DealtSecretKey::new(pp.get_encryption_key_base().mul(self.get_secret_a()))
    }
}

impl traits::Convert<DealtPubKey, PublicParameters> for InputSecret {
    /// Computes the public key associated with the given input secret.
    /// NOTE: In the SCRAPE PVSS, a `DealtPublicKey` cannot be computed from a `DealtSecretKey` directly.
    fn to(&self, pp: &PublicParameters) -> DealtPubKey {
        DealtPubKey::new(pp.get_commitment_base().mul(self.get_secret_a()))
    }
}

#[cfg(test)]
mod test {}
