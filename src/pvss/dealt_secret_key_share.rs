macro_rules! dealt_secret_key_share_impl {
    (
        $gt:ident
    ) => {
        use crate::pvss::dealt_secret_key::$gt::DealtSecretKey;
        use crate::pvss::dealt_secret_key::$gt::DEALT_SK_NUM_BYTES;
        use aptos_crypto::{
            CryptoMaterialError, ValidCryptoMaterial, ValidCryptoMaterialStringExt,
        };
        use aptos_crypto_derive::{DeserializeKey, SerializeKey, SilentDebug, SilentDisplay};

        /// The size of a serialized *dealt secret key share*.
        const DEALT_SK_SHARE_NUM_BYTES: usize = DEALT_SK_NUM_BYTES;

        /// A player's *share* of the secret key that was dealt via the PVSS transcript.
        #[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay, PartialEq, Clone)]
        pub struct DealtSecretKeyShare(pub(crate) DealtSecretKey);

        #[cfg(feature = "assert-private-keys-not-cloneable")]
        static_assertions::assert_not_impl_any!(DealtSecretKeyShare: Clone);

        //
        // DealtSecretKeyShare implementation & traits
        //

        impl DealtSecretKeyShare {
            pub fn to_bytes(&self) -> [u8; DEALT_SK_SHARE_NUM_BYTES] {
                self.0.to_bytes()
            }
        }

        impl ValidCryptoMaterial for DealtSecretKeyShare {
            fn to_bytes(&self) -> Vec<u8> {
                self.to_bytes().to_vec()
            }
        }

        impl TryFrom<&[u8]> for DealtSecretKeyShare {
            type Error = CryptoMaterialError;

            fn try_from(bytes: &[u8]) -> std::result::Result<DealtSecretKeyShare, Self::Error> {
                DealtSecretKey::try_from(bytes).map(|sk| DealtSecretKeyShare(sk))
            }
        }
    };
}

pub mod g1 {}

pub mod g2 {
    dealt_secret_key_share_impl!(g2);
}
