use crate::algebra::evaluation_domain::BatchEvaluationDomain;
use crate::algebra::fft::{fft, fft_assign};
use crate::algebra::lagrange::{
    all_lagrange_denominators, all_n_lagrange_coefficients, lagrange_coefficients,
};
use crate::pvss::encryption_dlog;
use crate::pvss::player::Player;
use crate::pvss::scrape;
use crate::pvss::scrape::fiat_shamir::FiatShamirProtocol;
use crate::pvss::threshold_config::ThresholdConfig;
use crate::pvss::traits;
use crate::utils::is_power_of_two;
use crate::utils::random::{random_g1_point, random_g2_point, random_scalars};
use aptos_crypto::{CryptoMaterialError, ValidCryptoMaterial};
use blstrs::{Bls12, G1Affine, G1Projective, G2Prepared, G2Projective, Gt, Scalar};
use ff::Field;
use group::{Curve, Group};
use pairing::{MillerLoopResult, MultiMillerLoop};
use serde::{Deserialize, Serialize};
use std::ops::{Mul, Neg};

/// Returns the dual code word for the SCRAPE low-degree test on a polynomial of degree `d`
/// evaluated over all $n$ roots of unity in `batch_dom`.
#[allow(unused)]
pub fn get_dual_code_word<R: rand_core::RngCore + rand_core::CryptoRng>(
    deg: usize,
    batch_dom: &BatchEvaluationDomain,
    n: usize,
    mut rng: &mut R,
) -> Vec<Scalar> {
    // The degree-(t-1) polynomial p(X) that shares our secret
    // So, deg = t-1 => t = deg + 1
    // The "dual" polynomial f(X) of degree n - t - 1 = n - (deg + 1) - 1 = n - deg - 2
    let mut f = random_scalars(n - deg - 2, &mut rng);

    // Compute f(\omega^i) for all i's
    let dom = batch_dom.get_subdomain(n);
    fft_assign(&mut f, &dom);
    f.truncate(n);

    // Compute v_i = 1 / \prod_{j \ne i, j \in [0, n-1]} (\omega^i - \omega^j), for all i's
    let v = all_lagrange_denominators(&batch_dom, n);

    // Compute v_i * f(\omega^i), for all i's
    let vf = f
        .iter()
        .zip(v.iter())
        .map(|(v, f)| v.mul(f))
        .collect::<Vec<Scalar>>();

    vf
}

/// A SCRAPE PVSS *transcript*.
///
/// We use the normal serde `Serialize` and `Deserialize` macros because `aptos_crypto`'s `SerializeKey`
/// macros overr    ide serde's serialization to call into `ValidCryptoMaterial::to_bytes()`. This makes
/// it difficult to serialize complex types because if we call serde serialization inside `to_bytes`
/// on the struct itself, it triggers infinite recursion by having `serde` call back into `to_bytes`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[allow(non_snake_case)]
pub struct Transcript {
    /// Commitment to $f(0)$: $\hat{u}_2 = \hat{u}_1^{a_0}$
    u2_hat: G2Projective,
    /// Commitments to the $t$ coefficients of $f(X)$: $g_1^{a_i}$
    /// TODO: the SCRAPE low-degree test can remove this from the transcript (except for F[0], which we still want since it has the PK)
    F: Vec<G1Projective>,
    /// Commitments to the $n$ evaluations of $f(X)$: $g_1^{f(\omega^i)}$
    A: Vec<G1Projective>,
    /// $n$ encryptions, one for each player's share of $f(X)$: $ek^{f(\omega^i)}, \forall i\in[0,n)$
    Y_hat: Vec<G2Projective>,
}

impl ValidCryptoMaterial for Transcript {
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(&self).expect("unexpected error during SCRAPE PVSS transcript serialization")
    }
}

impl TryFrom<&[u8]> for Transcript {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bcs::from_bytes::<Transcript>(bytes).map_err(|_| CryptoMaterialError::DeserializationError)
    }
}

impl traits::Transcript for Transcript {
    type SecretSharingConfig = ThresholdConfig;
    type PvssPublicParameters = scrape::PublicParameters;
    type DealtSecretKeyShare = scrape::DealtSecretKeyShare;
    type DealtPubKeyShare = scrape::DealtPubKeyShare;
    type DealtSecretKey = scrape::DealtSecretKey;
    type DealtPubKey = scrape::DealtPubKey;
    type InputSecret = scrape::InputSecret;
    type EncryptPubKey = encryption_dlog::g2::EncryptPubKey;
    type DecryptPrivKey = encryption_dlog::g2::DecryptPrivKey;

    fn scheme_name() -> String {
        "vanilla_scrape_sk_in_g2".to_string()
    }

    fn deal<R: rand_core::RngCore + rand_core::CryptoRng>(
        sc: &ThresholdConfig,
        pp: &Self::PvssPublicParameters,
        eks: &Vec<Self::EncryptPubKey>,
        s: Self::InputSecret,
        _dst: &'static [u8], // TODO: probably not applicable in pairing-based scrape, since no Fiat-Shamir
        rng: &mut R,
    ) -> Self {
        assert_eq!(eks.len(), sc.n);

        // A random, degree t-1 polynomial $f(X) = [a_0, \dots, a_{t-1}]$, with $a_0$ set to `s.a`
        let mut f = random_scalars(sc.t, rng);
        f[0] = *s.get_secret_a();

        // Evaluate $f$ at all the $N$th roots of unity.
        let mut f_evals = fft(&f, sc.get_evaluation_domain());
        f_evals.truncate(sc.n);

        let g1 = pp.get_commitment_base();
        let u1_hat = pp.get_public_key_base();

        Transcript {
            u2_hat: u1_hat.mul(f[0]),
            F: (0..sc.t).map(|i| g1.mul(f[i])).collect(),
            A: (0..sc.n).map(|i| g1.mul(f_evals[i])).collect(),
            Y_hat: (0..sc.n)
                .map(|i| Into::<G2Projective>::into(&eks[i]).mul(f_evals[i]))
                .collect(),
        }
    }

    /// TODO(Performance): This can be sped-up; we are not actually doing the SCRAPE dual-code check here. See notes on [GJM+21] and in [CD17]
    fn verify(
        &self,
        sc: &ThresholdConfig,
        pp: &Self::PvssPublicParameters,
        eks: &Vec<Self::EncryptPubKey>,
        dst: &'static [u8],
    ) -> bool {
        if eks.len() != sc.n {
            return false;
        }

        for &len in [&self.A.len(), &self.Y_hat.len()] {
            if len != sc.n {
                return false;
            }
        }

        if self.F.len() != sc.t {
            return false;
        }

        // Derive challenges deterministically via Fiat-Shamir; it's easier to debug for distributed systems
        let (alpha, r) = self.fiat_shamir(sc, pp, eks, dst);

        let lagr = if is_power_of_two(sc.n) {
            // NOTE: There's barely any wasted computation here: we have \alpha^{t-1} and
            // `all_n_lagrange_coefficients` will recompute it as part of computing \alpha^n
            // but it will do it very fast via doublings since n = 2^k.
            all_n_lagrange_coefficients(sc.get_batch_evaluation_domain(), &alpha)
        } else {
            let all_points = (0..sc.n).collect::<Vec<usize>>();
            lagrange_coefficients(
                sc.get_batch_evaluation_domain(),
                all_points.as_slice(),
                &alpha,
            )
        };

        // \alpha^0, \alpha^1, \ldots, \alpha^{t-1}
        let mut alphas = Vec::with_capacity(sc.t);
        alphas.push(Scalar::one());
        for _ in 1..sc.t {
            alphas.push(alphas.last().unwrap() * alpha);
        }
        debug_assert_eq!(alphas.len(), sc.t);

        //
        // Need to do a multiexp to verify consistency of coefficient commitments with evaluation
        // commitments:
        //
        //      \prod_{i \in [n]} A_i^{lagr[i]} = \prod_{j\in [0,t)} F_j^{\alpha^j}
        //
        // We reorganize it as:
        //
        //      \prod_{i \in [n]} A_i^{lagr[i]} \prod_{j\in [0,t)} F_j^{-\alpha^j}
        //
        let bases = self
            .A
            .iter()
            .map(|p| p.clone())
            .chain(self.F.iter().map(|p| p.clone()))
            .collect::<Vec<G1Projective>>();
        let scalars = lagr
            .into_iter()
            .chain(alphas.iter().map(|a| a.neg()))
            .collect::<Vec<Scalar>>();

        debug_assert_eq!(bases.len(), scalars.len());

        let res = G1Projective::multi_exp(&bases, &scalars);
        if res != G1Projective::identity() {
            return false;
        }

        //
        // Correctness of encryptions check
        // (This could be done via DLEQ proofs too.)
        //

        // We need to check the following equations hold:
        //
        //     e(g_1, \hat{Y}_i) = e(A_i, ek_i), \forall i \in [0,n) <=>
        //     e(g_1^{-1}, \hat{Y}_i) e(A_i, ek_i) = 1, \forall i \in [0,n) <=>
        //
        //     \prod_{i\in[0,n)} e(g_1^{-r_i}, \hat{Y}_i) e(A_i^{r_i}, ek_i) = 1
        //     TODO(Performance): rewrite as
        //     e(g_1, \prod_{i\in[0,n)} \hat{Y}_i^{-r_i}) \prod_{i\in[0,n)} e(A_i^{r_i}, ek_i) = 1

        // We can also add the last pairing equation into the product above by appending a term:
        //
        //     e(F_0^{r_n}, \hat{u}_1) e(g_1^{-r_n}, \hat{u}_2)
        //
        // We let r_i = r^i, for a random r.

        // TODO(Performance): Do affine representations help?
        let g1_inverse = pp.get_commitment_base().neg();
        let mut r_i = Vec::with_capacity(sc.n + 1);
        r_i.push(Scalar::one());

        // `lhs` is a vector of the left inputs to the pairing:
        // - g_1^{-r_i}, \forall i \in [0,n)
        // - A_i^{r_i}, \forall i\in [0,n)
        // - F_0^{r_n}
        // - g_1^{-r_n}

        // First, compute r_i = r^i, for all i \in [0, n]
        for _ in 0..sc.n {
            r_i.push(r_i.last().unwrap().mul(&r));
        }

        let lhs = (0..sc.n)
            .map(|i| g1_inverse.mul(r_i[i]).to_affine())
            .chain((0..sc.n).map(|i| self.A[i].mul(r_i[i]).to_affine()))
            .chain([self.F[0].mul(r_i[sc.n]).to_affine()].into_iter())
            .chain([g1_inverse.mul(r_i[sc.n]).to_affine()].into_iter());

        // `rhs` is a vector of the left inputs to the pairing:
        // - \hat{Y}_i, \forall i\in [0,n)
        // - ek_i, \forall i\in [0,n)
        // - \hat{u}_1
        // - \hat{u}_2

        let rhs = self
            .Y_hat
            .iter()
            .map(|p| G2Prepared::from(p.to_affine()))
            .chain(
                eks.iter()
                    .map(|ek| G2Prepared::from(Into::<G2Projective>::into(ek).to_affine())),
            )
            .chain([G2Prepared::from(pp.get_public_key_base().to_affine())].into_iter())
            .chain([G2Prepared::from(self.u2_hat.to_affine())].into_iter());

        let pairs = lhs.zip(rhs).collect::<Vec<(G1Affine, G2Prepared)>>();

        let res = <Bls12 as MultiMillerLoop>::multi_miller_loop(
            pairs
                .iter()
                .map(|(g1, g2)| (g1, g2))
                .collect::<Vec<(&G1Affine, &G2Prepared)>>()
                .as_slice(),
        );
        let one = res.final_exponentiation();

        if one != Gt::identity() {
            return false;
        }

        return true;
    }

    fn aggregate_with(&mut self, sc: &ThresholdConfig, other: &Transcript) {
        self.u2_hat += other.u2_hat;

        for i in 0..sc.n {
            self.A[i] += other.A[i];
            self.Y_hat[i] += other.Y_hat[i];
        }

        //assert_eq!(self.F.len(), sc.t);
        //assert_eq!(other.F.len(), sc.t);
        for i in 0..sc.t {
            self.F[i] += other.F[i];
        }
    }

    fn get_dealt_public_key(&self) -> scrape::DealtPubKey {
        // TODO: we could use the Aurora univariate sumcheck trick: f(0) = \sum_{i\in [n]} f(\omega^i) but that assume we have n roots of unity.
        // Instead, see [GJM+21] Fig 1 comments for how to embed the check of F_0 into the check of the A_i's efficiently
        scrape::DealtPubKey::new(self.F[0])
    }

    fn decrypt_own_share(
        &self,
        _sc: &ThresholdConfig,
        player_id: &Player,
        dk: &Self::DecryptPrivKey,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let ctxt = self.Y_hat[player_id.id]; // \hat{Y}_i = \ek_i^{f(\omega^i)}
        let secret_key_share = ctxt.mul(dk.dk); // Y_i^{\dk_i} = \hat{h}_1^{f(\omega^i)} (because \ek_i = \hat{h}_1^{\dk_i^{-1}})
        let verification_key_share = self.A[player_id.id]; // g_1^{f(\omega^i})

        (
            scrape::DealtSecretKeyShare(Self::DealtSecretKey::new(secret_key_share)),
            scrape::DealtPubKeyShare(Self::DealtPubKey::new(verification_key_share)),
        )
    }

    fn generate<R>(sc: &ThresholdConfig, rng: &mut R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        //
        // TODO(rand_core_hell): Since our random_g1_point and random_g2_point functions are
        // slower than we want. We cannot pick everything randomly. Instead, we generate a
        // kind-of-random-looking transcript from a few random elliptic curve points by doubling them.
        //
        let g2 = random_g2_point(rng);

        let mut acc_g2 = g2;
        let g2_vec = (0..sc.n)
            .map(|_| {
                acc_g2 = acc_g2.double();
                acc_g2
            })
            .collect::<Vec<G2Projective>>();

        let mut acc_g1 = random_g1_point(rng);
        let g1_vec = (0..sc.n)
            .map(|_| {
                acc_g1 = acc_g1.double();
                acc_g1
            })
            .collect::<Vec<G1Projective>>();

        let r2 = random_g2_point(rng);
        let r1a = random_g1_point(rng);
        let r1b = random_g1_point(rng);

        Transcript {
            u2_hat: g2,
            F: g1_vec.iter().take(sc.t).map(|p| p + r1a).collect(),
            A: g1_vec.iter().map(|p| p + r1b).collect(),
            Y_hat: g2_vec.iter().map(|p| p + r2).collect(),
        }
    }
}

impl Transcript {
    /// Securely derives a Fiat-Shamir challenge via Merlin.
    fn fiat_shamir(
        &self,
        sc: &ThresholdConfig,
        pp: &scrape::PublicParameters,
        eks: &Vec<encryption_dlog::g2::EncryptPubKey>,
        dst: &'static [u8],
    ) -> (Scalar, Scalar) {
        // TODO(Security): Audit this
        let mut fs_t = merlin::Transcript::new(dst);
        fs_t.pvss_domain_sep(sc);
        fs_t.append_public_parameters(pp);
        fs_t.append_encryption_keys(eks);

        fs_t.append_transcript(&self);
        (
            fs_t.challenge_lagrange_scalar(),
            fs_t.challenge_multipairing_scalar(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::algebra::evaluation_domain::BatchEvaluationDomain;
    use crate::algebra::fft::fft_assign;
    use crate::pvss::scrape::transcript::get_dual_code_word;
    use crate::pvss::scrape::Transcript;
    use crate::pvss::test_utils::get_threshold_config_and_rng;
    use crate::pvss::threshold_config::ThresholdConfig;
    use crate::pvss::traits::transcript::Transcript as UniformTranscript;
    use crate::utils::random::random_scalars;
    use aptos_crypto::ValidCryptoMaterial;
    use blstrs::Scalar;
    use ff::Field;
    use rand::thread_rng;
    use std::ops::Mul;

    #[test]
    fn transcript_serialization() {
        let sc = ThresholdConfig::new(10, 20);
        let mut rng = thread_rng();

        let trx = Transcript::generate(&sc, &mut rng);

        let serialized = trx.to_bytes();
        let deserialized = Transcript::try_from(serialized.as_slice())
            .expect("serialized SCRAPE transcript should deserialize correctly");

        assert_eq!(trx, deserialized);
    }

    #[test]
    // Compute the dual code word, as per Section 2.1 in [CD17e].
    //
    // [CD17e] SCRAPE: Scalable Randomness Attested by Public Entities; by Ignacio Cascudo and
    // Bernardo David; in Cryptology ePrint Archive, Report 2017/216; 2017;
    // https://eprint.iacr.org/2017/216
    fn dual_code_word_test() {
        let (sc, mut rng) = get_threshold_config_and_rng(10, 20);

        // The degree t-1 polynomial that shares our secret
        let mut p = random_scalars(sc.t, &mut rng);
        let batch_dom = BatchEvaluationDomain::new(sc.n);

        // Compute p(\omega^i) for all i's
        let dom = batch_dom.get_subdomain(sc.n);
        fft_assign(&mut p, &dom);
        p.truncate(sc.n);

        let vf = get_dual_code_word(sc.t - 1, &batch_dom, sc.n, &mut rng);

        // Compute \sum_i p(\omega^i) v_i f(\omega^i), which should be zero
        let zero: Scalar = p.iter().zip(vf.iter()).map(|(p, vf)| p.mul(vf)).sum();

        assert_eq!(zero, Scalar::zero());
    }
}
