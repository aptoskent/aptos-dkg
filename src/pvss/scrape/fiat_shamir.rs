use crate::pvss::encryption_dlog::g2::EncryptPubKey;
use crate::pvss::scrape;
use crate::pvss::scrape::public_parameters::PublicParameters;
use crate::pvss::threshold_config::ThresholdConfig;
use crate::utils::fiat_shamir;
use crate::utils::hash_to_scalar;
use aptos_crypto::ValidCryptoMaterial;
use blstrs::{G2Projective, Scalar};

pub const PVSS_DOM_SEP: &[u8; 21] = b"APTOS_SCRAPE_PVSS_DST";
pub const PVSS_HASH_TO_SCALAR_DST: &[u8; 36] = b"APTOS_SCRAPE_PVSS_HASH_TO_SCALAR_DST";

#[allow(non_snake_case)]
pub trait FiatShamirProtocol {
    /// Append a domain separator for the PVSS protocol, consisting of a sharing configuration `sc`,
    /// which locks in the $t$ out of $n$ threshold.
    fn pvss_domain_sep(&mut self, sc: &ThresholdConfig);

    /// Append the public parameters `pp`.
    fn append_public_parameters(&mut self, pp: &PublicParameters);

    /// Append the encryption keys `eks`.
    fn append_encryption_keys(&mut self, eks: &Vec<EncryptPubKey>);

    /// Appends the transcript
    fn append_transcript(&mut self, trx: &scrape::Transcript);

    /// Compute the Fiat-Shamir challenge `\alpha` for doing the Lagrange-based consistency check
    fn challenge_lagrange_scalar(&mut self) -> Scalar;

    /// Compute the Fiat-Shamir challenge `r` for combining pairings in the multipairing using
    /// coefficients $1, r, r^2, r^3, \ldots$
    fn challenge_multipairing_scalar(&mut self) -> Scalar;
}

#[allow(non_snake_case)]
// TODO(Security): Audit this
impl FiatShamirProtocol for merlin::Transcript {
    fn pvss_domain_sep(&mut self, sc: &ThresholdConfig) {
        self.append_message(b"dom-sep", PVSS_DOM_SEP);
        self.append_u64(b"t", sc.t as u64);
        self.append_u64(b"n", sc.n as u64);
    }

    fn append_public_parameters(&mut self, pp: &PublicParameters) {
        self.append_message(b"pp", pp.to_bytes().as_slice());
    }

    fn append_encryption_keys(&mut self, eks: &Vec<EncryptPubKey>) {
        fiat_shamir::append_g2_vector(
            self,
            b"encryption-keys",
            &eks.iter()
                .map(|ek| Into::<G2Projective>::into(ek))
                .collect::<Vec<G2Projective>>(),
        )
    }

    fn append_transcript(&mut self, trx: &scrape::Transcript) {
        self.append_message(b"transcript", trx.to_bytes().as_slice());
    }

    fn challenge_lagrange_scalar(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(b"challenge_alpha", &mut buf);

        hash_to_scalar(buf.as_slice(), PVSS_HASH_TO_SCALAR_DST)
    }

    fn challenge_multipairing_scalar(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(b"challenge_multipairing", &mut buf);

        hash_to_scalar(buf.as_slice(), PVSS_HASH_TO_SCALAR_DST)
    }
}
