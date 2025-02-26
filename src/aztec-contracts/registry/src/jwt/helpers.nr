use dep::aztec::prelude::{PrivateContext, SharedMutable};
use dep::aztec::protocol_types::traits::{Deserialize, FromField, Packable, Serialize, ToField};
use std::hash::poseidon2;

global SCHEDULED_DELAY_CHANGE: u32 = 3;
global GOOGLE_PUBLIC_KEY_LIMBS_LEN: u32 = 36;
global EMAIL_LEN: u32 = 64;
global E_LEN: u32 = 1;

pub fn bytes_to_fields<let N: u32>(bytes: [u8; N]) -> [Field; N] {
    let mut fields = [0 as Field; N];
    for i in 0..N {
        fields[i] = bytes[i] as Field;
    }
    fields
}

pub fn verifyPublicKey(
    location: SharedMutable<bool, SCHEDULED_DELAY_CHANGE, &mut PrivateContext>,
    jwt_id: Field,
    public_key_limbs: [Field; 18],
    public_key_redc_limbs: [Field; 18],
    public_key_e: Field,
) {
    let jwt_id_valid = location.get_current_value();
    assert(jwt_id_valid, "google public key hash not found");

    let public_key_limbs = public_key_limbs.concat(public_key_redc_limbs);
    let public_key_limbs_and_e = public_key_limbs.concat([public_key_e]);
    let hash =
        poseidon2::Poseidon2::hash(public_key_limbs_and_e, (GOOGLE_PUBLIC_KEY_LIMBS_LEN + E_LEN));

    assert(hash == jwt_id, "public key hash does not match the stored hash");
}

pub fn emailHashFromBytes(email_bytes: [u8; EMAIL_LEN]) -> Field {
    let email_bytes_to_field: [Field; EMAIL_LEN] = bytes_to_fields(email_bytes);
    let email_hash = poseidon2::Poseidon2::hash(email_bytes_to_field, EMAIL_LEN);

    email_hash
}

