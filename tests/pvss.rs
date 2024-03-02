//! PVSS scheme-independent testing
use aptos_dkg::constants::{
    BEST_CASE_N, BEST_CASE_THRESHOLD, DST_PVSS_TESTING_APP, G1_PROJ_NUM_BYTES, G2_PROJ_NUM_BYTES,
    SCALAR_NUM_BYTES, WORST_CASE_N, WORST_CASE_THRESHOLD,
};
use aptos_dkg::pvss;
use aptos_dkg::pvss::traits::transcript::Transcript;
use aptos_dkg::pvss::traits::{Reconstructable, SecretSharingConfig};
use aptos_dkg::pvss::{scrape, test_utils};
use aptos_dkg::pvss::{Player, ThresholdConfig};
use rand::thread_rng;

#[test]
fn all_pvss_bvt() {
    // SCRAPE unweighted
    for sc in get_threshold_configs_for_testing() {
        pvss_bvt::<pvss::scrape::Transcript>(&sc);
    }
}

#[test]
fn scrape_transcript_size() {
    for (t, n) in [
        (BEST_CASE_THRESHOLD, BEST_CASE_N),
        (WORST_CASE_THRESHOLD, WORST_CASE_N),
    ] {
        transcript_size::<pvss::scrape::Transcript>(t, n);
        expected_vanilla_scrape_transcript_size(t, n);
    }
}

//
// Helper functions
//

fn get_threshold_configs_for_testing() -> Vec<ThresholdConfig> {
    let mut scs = vec![];

    for t in [1, 2, 3, 4, 5, 6, 7, 8] {
        for n in t..3 * (t - 1) + 1 {
            scs.push(ThresholdConfig::new(t, n))
        }
    }

    scs
}

fn pvss_bvt<T: Transcript>(sc: &T::SecretSharingConfig) {
    pvss_deal_verify_and_reconstruct::<T>(sc);
}

/// 1. Deals a secret, creating a transcript
/// 2. Verifies the transcript.
/// 3. Ensures the a sufficiently-large random subset of the players can recover the dealt secret
fn pvss_deal_verify_and_reconstruct<T: Transcript>(sc: &T::SecretSharingConfig) {
    let (pp, dks, eks, s, sk) = test_utils::setup_dealing::<T>(sc);

    let mut rng = thread_rng();
    let trx = T::deal(&sc, &pp, &eks, s, &DST_PVSS_TESTING_APP[..], &mut rng);
    assert!(trx.verify(&sc, &pp, &eks, &DST_PVSS_TESTING_APP[..]));

    // Test reconstruction from t random shares
    let players_and_shares = sc
        .get_random_subset_of_capable_players(&mut rng)
        .into_iter()
        .map(|p| {
            let (sk, _) = trx.decrypt_own_share(&sc, &p, &dks[p.get_id()]);

            (p, sk)
        })
        .collect::<Vec<(Player, T::DealtSecretKeyShare)>>();

    let sk_reconstruct = T::DealtSecretKey::reconstruct(&sc, &players_and_shares);

    assert_eq!(sk, sk_reconstruct);
}

fn transcript_size<T: Transcript<SecretSharingConfig = ThresholdConfig>>(t: usize, n: usize) {
    let (sc, mut rng) = test_utils::get_threshold_config_and_rng(t, n);

    let trx = T::generate(&sc, &mut rng);
    let actual_size = trx.to_bytes().len();
    let name = T::scheme_name();

    // NOTE: We leave the extra two spaces after "actual" for to align the output here with the
    // output from `expected_*_transcript_size` calls, which print the same thing but start with
    // "expected."
    println!("Actual   transcript size for {t}-out-of-{n} {name}: {actual_size} bytes");
}

fn expected_vanilla_scrape_transcript_size(t: usize, n: usize) -> usize {
    let name = scrape::Transcript::scheme_name();

    let expected_size =
        G2_PROJ_NUM_BYTES + n * (G2_PROJ_NUM_BYTES + G1_PROJ_NUM_BYTES) + t * G1_PROJ_NUM_BYTES;

    println!("Expected transcript size for {t}-out-of-{n} {name}: {expected_size} bytes");
    expected_size
}

#[allow(unused)]
fn expected_dleq_scrape_transcript_size(t: usize, n: usize) -> usize {
    let name = "DLEQ-SCRAPE"; // TODO: change to function call once updated

    let vanilla_expected_size =
        G2_PROJ_NUM_BYTES + n * (G2_PROJ_NUM_BYTES + G1_PROJ_NUM_BYTES) + t * G1_PROJ_NUM_BYTES;

    let expected_size =
        vanilla_expected_size + n * (G2_PROJ_NUM_BYTES + G1_PROJ_NUM_BYTES + SCALAR_NUM_BYTES);

    println!("Expected transcript size for {t}-out-of-{n} {name}: {expected_size} bytes");
    expected_size
}
