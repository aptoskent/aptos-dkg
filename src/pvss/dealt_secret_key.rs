macro_rules! dealt_secret_key_impl {
    (
        $GT_PROJ_NUM_BYTES:ident,
        $gt_proj_from_bytes:ident,
        $GTProjective:ident,
        $gt:ident
    ) => {
        use crate::algebra::lagrange::lagrange_coefficients_at_zero;
        use crate::constants::$GT_PROJ_NUM_BYTES;
        use crate::pvss::dealt_secret_key_share::$gt::DealtSecretKeyShare;
        use crate::pvss::player::Player;
        use crate::pvss::threshold_config::ThresholdConfig;
        use crate::pvss::traits;
        use crate::pvss::traits::SecretSharingConfig;
        use crate::utils::serialization::$gt_proj_from_bytes;
        use aptos_crypto::CryptoMaterialError;
        use aptos_crypto_derive::{SilentDebug, SilentDisplay};
        use blstrs::$GTProjective;
        use more_asserts::{assert_ge, assert_le};

        /// The size of a serialized *dealt secret key*.
        pub(crate) const DEALT_SK_NUM_BYTES: usize = $GT_PROJ_NUM_BYTES;

        /// The *dealt secret key* that will be output by the PVSS reconstruction algorithm. This will be of
        /// a different type than the *input secret* that was given as input to PVSS dealing.
        ///
        /// This secret key will never be reconstructed in plaintext. Instead, we will use a simple/efficient
        /// multiparty computation protocol to reconstruct a function of this secret (e.g., a verifiable
        /// random function evaluated on an input `x` under this secret).
        ///
        /// NOTE: We do not implement (de)serialization for this because a dealt secret key `sk` will never be
        /// materialized in our protocol. Instead, we always use some form of efficient multi-party computation
        /// MPC protocol to materialize a function of `sk`, such as `f(sk, m)` where `f` is a verifiable random
        /// function (VRF), for example.
        #[derive(SilentDebug, SilentDisplay, PartialEq, Clone)]
        pub struct DealtSecretKey {
            /// A group element $\hat{h}^a \in G$, where $G$ is $G_1$, $G_2$ or $G_T$
            h_hat: $GTProjective,
        }

        #[cfg(feature = "assert-private-keys-not-cloneable")]
        static_assertions::assert_not_impl_any!(DealtSecretKey: Clone);

        //
        // DealtSecretKey implementation & traits
        //

        impl DealtSecretKey {
            pub fn new(h_hat: $GTProjective) -> Self {
                Self { h_hat }
            }

            pub fn to_bytes(&self) -> [u8; DEALT_SK_NUM_BYTES] {
                self.h_hat.to_compressed()
            }
        }

        impl TryFrom<&[u8]> for DealtSecretKey {
            type Error = CryptoMaterialError;

            fn try_from(bytes: &[u8]) -> std::result::Result<DealtSecretKey, Self::Error> {
                $gt_proj_from_bytes(bytes).map(|h_hat| DealtSecretKey { h_hat })
            }
        }

        impl traits::IsSecretShareable for DealtSecretKey {
            type Share = DealtSecretKeyShare;
        }

        impl traits::Reconstructable for DealtSecretKey {
            type SecretSharingConfig = ThresholdConfig;

            /// Reconstructs the `DealtSecretKey` given a sufficiently-large subset of shares from players.
            /// Mainly used for testing the PVSS transcript dealing and decryption.
            fn reconstruct(sc: &ThresholdConfig, shares: &Vec<(Player, Self::Share)>) -> Self {
                assert_ge!(shares.len(), sc.get_threshold());
                assert_le!(shares.len(), sc.get_total_num_players());

                let ids = shares.iter().map(|(p, _)| p.id).collect::<Vec<usize>>();
                let lagr =
                    lagrange_coefficients_at_zero(sc.get_batch_evaluation_domain(), ids.as_slice());
                let bases = shares
                    .iter()
                    .map(|(_, share)| share.0.h_hat)
                    .collect::<Vec<$GTProjective>>();

                assert_eq!(lagr.len(), bases.len());

                DealtSecretKey {
                    h_hat: $GTProjective::multi_exp(bases.as_slice(), lagr.as_slice()),
                }
            }
        }
    };
}

pub mod g1 {}

pub mod g2 {
    dealt_secret_key_impl!(G2_PROJ_NUM_BYTES, g2_proj_from_bytes, G2Projective, g2);
}
