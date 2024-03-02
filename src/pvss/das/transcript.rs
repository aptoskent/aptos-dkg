// use blstrs::G2Projective;
// use serde::{Deserialize, Serialize};

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
// #[allow(non_snake_case)]
// pub struct Transcript {
//     /// ElGamal encryption randomness $g_2^r \in G_2$
//     hat_w: G2Projective,
//     /// Commitments to the $n$ evaluations of $p(X)$: $g_2^{p(\omega^i)}$
//     V: Vec<G2Projective>,
//     /// ElGamal encryptions of the shares:
//     ///  - $C_0 = g_1^r$
//     ///  - $C_i = $h_1^{p(\omega^i)} ek^r, \forall i \in [n]$
//     C: Vec<G2Projective>,
// }
//
// // TODO(Performance): for verification, can we get any speed-ups when a lot of the PKs are the same?
