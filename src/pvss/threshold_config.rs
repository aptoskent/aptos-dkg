use crate::algebra::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};
use crate::pvss::{traits, Player};
use rand::seq::IteratorRandom;
use rand_core::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};

/// Encodes the *threshold configuration* for a normal/unweighted PVSS: i.e., the threshold $t$ and
/// the number of players $n$ such that any $t$ or more players can reconstruct a dealt secret given
/// a PVSS transcript.
pub struct ThresholdConfig {
    /// The reconstruction threshold $t$ that must be exceeded in order to reconstruct the dealt
    /// secret; i.e., $t$ or more shares are needed
    pub(crate) t: usize,
    /// The total number of players involved in the PVSS protocol
    pub(crate) n: usize,
    /// Evaluation domain consisting of the $N$th root of unity and other auxiliary information
    /// needed to compute an FFT of size $N$.
    dom: EvaluationDomain,
    /// Batch evaluation domain, consisting of all the $N$th roots of unity (in the scalar field),
    /// where N is the smallest power of two such that n <= N.
    batch_dom: BatchEvaluationDomain,
}

impl ThresholdConfig {
    /// Creates a new $t$ out of $n$ secret sharing configuration where any subset of $t$ or more
    /// players can reconstruct the secret.
    pub fn new(t: usize, n: usize) -> Self {
        let batch_dom = BatchEvaluationDomain::new(n);
        let dom = batch_dom.get_subdomain(n);
        ThresholdConfig {
            n,
            t,
            dom,
            batch_dom,
        }
    }

    /// Returns the threshold $t$. Recall that $\ge t$ shares are needed to reconstruct.
    pub fn get_threshold(&self) -> usize {
        self.t
    }

    pub fn get_batch_evaluation_domain(&self) -> &BatchEvaluationDomain {
        &self.batch_dom
    }

    pub fn get_evaluation_domain(&self) -> &EvaluationDomain {
        &self.dom
    }
}

impl Display for ThresholdConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-out-of-{}/threshold", self.t, self.n)
    }
}

impl traits::SecretSharingConfig for ThresholdConfig {
    fn get_random_subset_of_capable_players<R>(&self, mut rng: &mut R) -> Vec<Player>
    where
        R: RngCore + CryptoRng,
    {
        (0..self.get_total_num_shares())
            .choose_multiple(&mut rng, self.t)
            .into_iter()
            .map(|i| self.get_player(i))
            .collect::<Vec<Player>>()
    }

    fn get_total_num_players(&self) -> usize {
        self.n
    }

    fn get_total_num_shares(&self) -> usize {
        self.n
    }
}
