use dep::aztec::prelude::{PrivateContext, SharedMutable};
use dep::aztec::protocol_types::traits::{Deserialize, FromField, Packable, Serialize, ToField};
use std::hash::poseidon2;

global SCHEDULED_DELAY_CHANGE: u32 = 3;
global GOOGLE_PUBLIC_KEY_LIMBS_LEN: u32 = 36;
global EMAIL_LEN: u32 = 64;

#[derive(Serialize, Deserialize, Packable)]
pub struct GooglePublicKeyHashs {
    hash: [Field; 2],
}

impl ToField for GooglePublicKeyHashs {
    fn to_field(self) -> Field {
        // Hash both fields together to create a single field
        poseidon2::Poseidon2::hash(self.hash, 2)
    }
}

impl FromField for GooglePublicKeyHashs {
    fn from_field(value: Field) -> Self {
        // Since we can't reconstruct two unique fields from one,
        // we'll use the same value for both hashes
        GooglePublicKeyHashs { hash: [value, value] }
    }
}

impl Eq for GooglePublicKeyHashs {
    fn eq(self, other: Self) -> bool {
        let first_equal = self.hash[0] == other.hash[0];
        let second_equal = self.hash[1] == other.hash[1];
        if first_equal {
            second_equal
        } else {
            false
        }
    }
}

pub fn bytes_to_fields<let N: u32>(bytes: [u8; N]) -> [Field; N] {
    let mut fields = [0 as Field; N];
    for i in 0..N {
        fields[i] = bytes[i] as Field;
    }
    fields
}

pub fn verifyGooglePublicKey(
    location: SharedMutable<GooglePublicKeyHashs, SCHEDULED_DELAY_CHANGE, &mut PrivateContext>,
    public_key_limbs: [Field; 18],
    public_key_redc_limbs: [Field; 18],
) {
    let google_public_key_hashs = location.get_current_value();

    let limbs = public_key_limbs.concat(public_key_redc_limbs);
    let hash = poseidon2::Poseidon2::hash(limbs, GOOGLE_PUBLIC_KEY_LIMBS_LEN);

    let matches_first = hash == google_public_key_hashs.hash[0];
    let matches_second = hash == google_public_key_hashs.hash[1];

    assert(
        matches_first | matches_second,
        "public key hash does not match either of the stored hashes",
    );
}

pub fn emailHashFromBytes(email_bytes: [u8; EMAIL_LEN]) -> Field {
    let email_bytes_to_field: [Field; EMAIL_LEN] = bytes_to_fields(email_bytes);
    let email_hash = poseidon2::Poseidon2::hash(email_bytes_to_field, EMAIL_LEN);

    email_hash
}

