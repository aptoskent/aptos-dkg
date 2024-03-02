use crate::pvss::traits::transcript::Transcript;
use crate::pvss::traits::{Convert, HasEncryptionPublicParams, SecretSharingConfig};
use crate::pvss::ThresholdConfig;
use aptos_crypto::Uniform;
use rand::prelude::ThreadRng;
use rand::thread_rng;

/// Helper function that returns an (sc, pp, dks, eks, s) tuple. Useful in tests and benchmarks when
/// wanting to quickly deal & verify a transcript.
pub fn setup_dealing<T: Transcript>(
    sc: &T::SecretSharingConfig,
) -> (
    T::PvssPublicParameters,
    Vec<T::DecryptPrivKey>,
    Vec<T::EncryptPubKey>,
    T::InputSecret,
    T::DealtSecretKey,
) {
    let mut rng = thread_rng();

    let pp = T::PvssPublicParameters::default();
    let dks = (0..sc.get_total_num_players())
        .map(|_| T::DecryptPrivKey::generate(&mut rng))
        .collect::<Vec<T::DecryptPrivKey>>();
    let eks = dks
        .iter()
        .map(|dk| dk.to(&pp.get_encryption_public_params()))
        .collect();
    let s = T::InputSecret::generate(&mut rng);
    let sk: <T as Transcript>::DealtSecretKey = s.to(&pp);

    (pp, dks, eks, s, sk)
}

pub fn get_threshold_config_and_rng(t: usize, n: usize) -> (ThresholdConfig, ThreadRng) {
    let sc = ThresholdConfig::new(t, n);

    (sc, thread_rng())
}
