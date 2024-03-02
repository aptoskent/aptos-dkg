use crate::algebra::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};
use rand_core::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};
// use crate::algebra::evaluation_domain::{BatchEvaluationDomain, EvaluationDomain};
use crate::pvss::traits::SecretSharingConfig;
use crate::pvss::{traits, Player, ThresholdConfig};

/// Encodes the *threshold configuration* for a *weighted* PVSS: i.e., the minimum weight $w$ and
/// the total weight $W$ such that any subset of players with weight $\ge w$ can reconstruct a
/// dealt secret given a PVSS transcript.
#[allow(non_snake_case)]
pub struct WeightedConfig {
    /// A weighted config is a $w$-out-of-$W$ threshold config, where $w$ is the minimum weight
    /// needed to reconstruct the secret and $W$ is the total weight.
    tc: ThresholdConfig,
    /// The total number of players in the protocol.
    n: usize,
    /// Each player's weight
    weight: Vec<usize>,
    /// Player's starting index `a` in a vector of all `W` shares, such that this player owns shares
    /// `W[a, a + weight[player])`. Useful during weighted secret reconstruction.
    starting_index: Vec<usize>,
    // /// Evaluation domain consisting of the $N$th root of unity and other auxiliary information
    // /// needed to compute an FFT of size $N$.
    // dom: EvaluationDomain,
    // /// Batch evaluation domain, consisting of all the $N$th roots of unity (in the scalar field),
    // /// where N is the smallest power of two such that n <= N.
    // batch_dom: BatchEvaluationDomain,
}

impl WeightedConfig {
    #[allow(non_snake_case)]
    pub fn new(w: usize, n: usize, weight: Vec<usize>) -> Self {
        let W = weight.iter().sum();

        // e.g., Suppose the weights for players 0, 1 and 2 are [2, 4, 3]
        // Then, there will be a vector of 2 + 4 + 3 = 9 shares.
        // Player 0 will own the shares at indices [0..2)
        // Player 1 will own the shares at indices [2..2 + 4) = [2..6)
        // Player 2 will own the shares at indices [6, 6 + 3) = [6..9)
        let mut starting_index = Vec::with_capacity(weight.len() + 1);
        starting_index.push(0);
        for w in weight.iter() {
            starting_index.push(starting_index.last().unwrap() + w);
        }
        starting_index.pop();

        // let batch_dom = BatchEvaluationDomain::new(n);
        // let dom = batch_dom.get_subdomain(n);
        let tc = ThresholdConfig::new(w, W);
        WeightedConfig {
            tc,
            n,
            weight,
            starting_index,
        }
    }

    pub fn get_threshold_config(&self) -> &ThresholdConfig {
        &self.tc
    }

    pub fn get_threshold_weight(&self) -> usize {
        self.tc.t
    }

    pub fn get_total_weight(&self) -> usize {
        self.tc.n
    }

    pub fn get_player_weight(&self, player: &Player) -> usize {
        self.weight[player.id]
    }

    /// In an unweighted secret sharing scheme, each player has one share. We can whey such a scheme
    /// by splitting a player into as many "virtual" players as that player's weight, assigning one
    /// share per "virtual player."
    ///
    /// This function returns the "virtual" player associated with the $i$th sub-share of this player.
    pub fn get_virtual_player(&self, player: &Player, i: usize) -> Player {
        self.get_player(self.starting_index[player.id] + i)
    }

    pub fn get_batch_evaluation_domain(&self) -> &BatchEvaluationDomain {
        &self.tc.get_batch_evaluation_domain()
    }

    pub fn get_evaluation_domain(&self) -> &EvaluationDomain {
        &self.tc.get_evaluation_domain()
    }
}

impl Display for WeightedConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-out-of-{}/{}-players/weighted",
            self.tc.t, self.tc.n, self.n
        )
    }
}

impl traits::SecretSharingConfig for WeightedConfig {
    fn get_random_subset_of_capable_players<R>(&self, mut _rng: &mut R) -> Vec<Player>
    where
        R: RngCore + CryptoRng,
    {
        // (0..sc.get_total_num_shares())
        //     .choose_multiple(&mut rng, self.t)
        //     .into_iter()
        //     .map(|i| {
        //         sc.get_player(i)
        //     })
        //     .collect::<Vec<Player>>()
        todo!()
    }

    fn get_total_num_players(&self) -> usize {
        self.n
    }

    fn get_total_num_shares(&self) -> usize {
        self.tc.n
    }
}
