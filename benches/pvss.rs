use aptos_crypto::Uniform;
use aptos_dkg::constants::{
    BEST_CASE_N, BEST_CASE_THRESHOLD, DST_PVSS_TESTING_APP, WORST_CASE_N, WORST_CASE_THRESHOLD,
};
use aptos_dkg::pvss;
use aptos_dkg::pvss::traits::transcript::Transcript;
use aptos_dkg::pvss::traits::SecretSharingConfig;
use aptos_dkg::pvss::{test_utils, ThresholdConfig};
use criterion::measurement::WallTime;
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, Criterion,
    Throughput,
};
use rand::thread_rng;

pub fn all_groups(c: &mut Criterion) {
    pvss_group::<pvss::scrape::Transcript>(
        &ThresholdConfig::new(BEST_CASE_THRESHOLD, BEST_CASE_N),
        c,
    );
    pvss_group::<pvss::scrape::Transcript>(
        &ThresholdConfig::new(WORST_CASE_THRESHOLD, WORST_CASE_N),
        c,
    );
}

pub fn pvss_group<T: Transcript>(sc: &T::SecretSharingConfig, c: &mut Criterion) {
    let name = T::scheme_name();
    let mut group = c.benchmark_group(format!("pvss/{}", name));

    pvss_transcript_random::<T, WallTime>(sc, &mut group);
    pvss_deal::<T, WallTime>(sc, &mut group);
    pvss_aggregate::<T, WallTime>(sc, &mut group);
    pvss_verify::<T, WallTime>(sc, &mut group);
    pvss_decrypt_own_share::<T, WallTime>(sc, &mut group);

    group.finish();
}

fn pvss_deal<T: Transcript, M: Measurement>(
    sc: &T::SecretSharingConfig,
    g: &mut BenchmarkGroup<M>,
) {
    g.throughput(Throughput::Elements(sc.get_total_num_shares() as u64));

    let (pp, _, eks, _, _) = test_utils::setup_dealing::<T>(sc);
    let mut rng = thread_rng();

    g.bench_function(format!("deal/{}", sc), move |b| {
        b.iter_with_setup(
            || {
                let s = T::InputSecret::generate(&mut rng);
                (s, rng)
            },
            |(s, mut rng)| T::deal(&sc, &pp, &eks, s, &DST_PVSS_TESTING_APP[..], &mut rng),
        )
    });
}

fn pvss_aggregate<T: Transcript, M: Measurement>(
    sc: &T::SecretSharingConfig,
    g: &mut BenchmarkGroup<M>,
) {
    g.throughput(Throughput::Elements(sc.get_total_num_shares() as u64));
    let mut rng = thread_rng();

    g.bench_function(format!("aggregate/{}", sc), move |b| {
        b.iter_with_setup(
            || {
                let trx = T::generate(&sc, &mut rng);
                (trx.clone(), trx)
            },
            |(mut first, second)| {
                first.aggregate_with(&sc, &second);
            },
        )
    });
}

fn pvss_verify<T: Transcript, M: Measurement>(
    sc: &T::SecretSharingConfig,
    g: &mut BenchmarkGroup<M>,
) {
    g.throughput(Throughput::Elements(sc.get_total_num_shares() as u64));

    let (pp, _, eks, _, _) = test_utils::setup_dealing::<T>(sc);
    let mut rng = thread_rng();

    g.bench_function(format!("verify/{}", sc), move |b| {
        b.iter_with_setup(
            || {
                let s = T::InputSecret::generate(&mut rng);
                T::deal(&sc, &pp, &eks, s, &DST_PVSS_TESTING_APP[..], &mut rng)
            },
            |trx| {
                assert!(trx.verify(&sc, &pp, &eks, &DST_PVSS_TESTING_APP[..]));
            },
        )
    });
}

fn pvss_decrypt_own_share<T: Transcript, M: Measurement>(
    sc: &T::SecretSharingConfig,
    g: &mut BenchmarkGroup<M>,
) {
    g.throughput(Throughput::Elements(sc.get_total_num_shares() as u64));

    let (pp, dks, eks, _, _) = test_utils::setup_dealing::<T>(sc);
    let mut rng = thread_rng();

    g.bench_function(format!("decrypt-share/{}", sc), move |b| {
        b.iter_with_setup(
            || {
                let s = T::InputSecret::generate(&mut rng);
                T::deal(&sc, &pp, &eks, s, &DST_PVSS_TESTING_APP[..], &mut rng)
            },
            |trx| {
                trx.decrypt_own_share(&sc, &sc.get_player(0), &dks[0]);
            },
        )
    });
}

fn pvss_transcript_random<T: Transcript, M: Measurement>(
    sc: &T::SecretSharingConfig,
    g: &mut BenchmarkGroup<M>,
) {
    g.throughput(Throughput::Elements(sc.get_total_num_shares() as u64));

    let mut rng = thread_rng();

    g.bench_function(format!("transcript-random/{}", sc), move |b| {
        b.iter(|| T::generate(&sc, &mut rng))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    //config = Criterion::default();
    targets = all_groups);
criterion_main!(benches);
