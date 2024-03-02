use crate::pvss::traits::{
    Convert, IsSecretShareable, Reconstructable, SecretSharingConfig, Transcript,
};
use crate::pvss::{Player, ThresholdConfig, WeightedConfig};
use aptos_crypto::{CryptoMaterialError, Uniform, ValidCryptoMaterial};
use aptos_crypto_derive::{SilentDebug, SilentDisplay};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
/// A weighting wrapper around a `Transcript` type `T`. Given an implementation of an [unweighted
/// PVSS] `Transcript` for `T`, this wrapper can be used to easily obtain a *weighted* PVSS abiding
/// by the same `Transcript` trait.
pub struct Weighted<T> {
    trx: T,
}

#[derive(SilentDebug, SilentDisplay, PartialEq)]
/// Wrapper around a key, whether a `Transcript::DealtSecretKey`, a `Transcript::DealtSecretKeyShare`,
/// or a `Transcript::InputSecret`. Helps us override the `Reconstructable` trait for a weighted
/// dealt secret key, which is implemented as a `Wrapper<Transcript::DealtSecretKey>` an has a
/// `Vec<Transcript::DealtSecretKeyShare>` as its associated `Share` type (via the `IsSecretShareable`
/// trait).
pub struct Wrapped<Key> {
    key: Key,
}

impl<InputSecret: Uniform> Uniform for Wrapped<InputSecret> {
    fn generate<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Wrapped {
            key: InputSecret::generate(rng),
        }
    }
}

/// Implements conversion from `Wrapped<T::InputSecret>` to `Wrapped<T::DealtSecretKey>` and
/// `Wrapped<T::DealtPubKey>` where `T` is an unweighted `Transcript`.
impl<InputSecret, Key, PublicParameters> Convert<Wrapped<Key>, PublicParameters>
    for Wrapped<InputSecret>
where
    InputSecret: Convert<Key, PublicParameters>,
{
    fn to(&self, with: &PublicParameters) -> Wrapped<Key> {
        Wrapped {
            key: self.key.to(with),
        }
    }
}

/// In a weighted PVSS transcript, each player gets a number of shares proportional to that player's
/// weight. As a result, the typing of a *weighted* dealt secret key share needs to now be a vector
/// of *unweighted* dealt secret key shares.
///
/// Associates `Vec<SK::Share>` as the dealt secret key share type of a `Wrapped<T::SK>`, where `T`
/// is in an unweighted `Transcript`.
impl<SK: IsSecretShareable> IsSecretShareable for Wrapped<SK> {
    type Share = Vec<SK::Share>;
}

/// Implements weighted reconstruction of a secret `Wrapped<SK>` through the existing unweighted
/// reconstruction implementation of `SK`.
impl<SK: IsSecretShareable + Reconstructable<SecretSharingConfig = ThresholdConfig>> Reconstructable
    for Wrapped<SK>
{
    type SecretSharingConfig = WeightedConfig;

    fn reconstruct(sc: &Self::SecretSharingConfig, shares: &Vec<(Player, Self::Share)>) -> Self {
        let mut flattened_shares = Vec::with_capacity(sc.get_total_weight());

        for (player, sub_shares) in shares {
            for (pos, share) in sub_shares.iter().enumerate() {
                let virtual_player = sc.get_virtual_player(player, pos);

                // TODO(Performance): Avoiding the cloning here might be nice
                flattened_shares.push((virtual_player, (*share).clone()));
            }
        }

        Wrapped {
            key: SK::reconstruct(sc.get_threshold_config(), &flattened_shares),
        }
    }
}

impl<T: Transcript> ValidCryptoMaterial for Weighted<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.trx.to_bytes()
    }
}

impl<T: Transcript> TryFrom<&[u8]> for Weighted<T> {
    type Error = CryptoMaterialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        T::try_from(bytes).map(|trx| Self { trx })
    }
}

impl<T: Transcript> Weighted<T> {
    fn to_weighted_encryption_keys(
        sc: &WeightedConfig,
        eks: &Vec<T::EncryptPubKey>,
    ) -> Vec<T::EncryptPubKey> {
        // Re-organize the encryption key vector so that we deal multiple shares to each player,
        // proportional to their weight.
        let mut duplicated_eks = Vec::with_capacity(sc.get_total_weight());

        for (player_id, ek) in eks.iter().enumerate() {
            let player = sc.get_player(player_id);
            let num_shares = sc.get_player_weight(&player);
            for _ in 0..num_shares {
                duplicated_eks.push(ek.clone());
            }
        }

        duplicated_eks
    }
}

impl<T: Transcript<SecretSharingConfig = ThresholdConfig>> Transcript for Weighted<T> {
    type SecretSharingConfig = WeightedConfig;
    type PvssPublicParameters = T::PvssPublicParameters;

    /// In a weighted PVSS, an SK share is represented as a vector of SK shares in the unweighted
    /// PVSS, whose size is proportional to the weight of the owning player.
    type DealtSecretKeyShare = Vec<T::DealtSecretKeyShare>;
    type DealtPubKeyShare = Vec<T::DealtPubKeyShare>;
    type DealtSecretKey = Wrapped<T::DealtSecretKey>;
    type DealtPubKey = Wrapped<T::DealtPubKey>;
    type InputSecret = Wrapped<T::InputSecret>;
    type EncryptPubKey = T::EncryptPubKey;
    type DecryptPrivKey = T::DecryptPrivKey;

    fn scheme_name() -> String {
        format!("weighted_{}", T::scheme_name())
    }

    fn deal<R: RngCore + CryptoRng>(
        sc: &Self::SecretSharingConfig,
        pp: &Self::PvssPublicParameters,
        eks: &Vec<Self::EncryptPubKey>,
        s: Self::InputSecret,
        dst: &'static [u8],
        rng: &mut R,
    ) -> Self {
        let duplicated_eks = Weighted::<T>::to_weighted_encryption_keys(sc, eks);

        Weighted {
            trx: T::deal(
                sc.get_threshold_config(),
                pp,
                &duplicated_eks,
                s.key,
                dst,
                rng,
            ),
        }
    }

    fn verify(
        &self,
        sc: &Self::SecretSharingConfig,
        pp: &Self::PvssPublicParameters,
        eks: &Vec<Self::EncryptPubKey>,
        dst: &'static [u8],
    ) -> bool {
        let duplicated_eks = Weighted::<T>::to_weighted_encryption_keys(sc, eks);

        T::verify(
            &self.trx,
            sc.get_threshold_config(),
            pp,
            &duplicated_eks,
            dst,
        )
    }

    fn aggregate_with(&mut self, sc: &Self::SecretSharingConfig, other: &Self) {
        T::aggregate_with(&mut self.trx, sc.get_threshold_config(), &other.trx)
    }

    fn get_dealt_public_key(&self) -> Self::DealtPubKey {
        Wrapped {
            key: T::get_dealt_public_key(&self.trx),
        }
    }

    fn decrypt_own_share(
        &self,
        sc: &Self::SecretSharingConfig,
        player_id: &Player, // TODO: could make Player keep track of its weight and avoid passing `Self::SecretSharingConfig`
        dk: &Self::DecryptPrivKey,
    ) -> (Self::DealtSecretKeyShare, Self::DealtPubKeyShare) {
        let weight = sc.get_total_weight();

        let mut weighted_dsk_share = Vec::with_capacity(weight);
        let mut weighted_dpk_share = Vec::with_capacity(weight);

        for i in 0..weight {
            let virtual_player = sc.get_virtual_player(player_id, i);
            let (dsk_share, dpk_share) =
                T::decrypt_own_share(&self.trx, sc.get_threshold_config(), &virtual_player, dk);
            weighted_dsk_share.push(dsk_share);
            weighted_dpk_share.push(dpk_share);
        }

        (weighted_dsk_share, weighted_dpk_share)
    }

    fn generate<R>(sc: &Self::SecretSharingConfig, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        Weighted {
            trx: T::generate(sc.get_threshold_config(), rng),
        }
    }
}
