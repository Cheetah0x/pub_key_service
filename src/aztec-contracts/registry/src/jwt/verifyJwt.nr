use crate::jwt::lib::{assert_verify_jwt, assert_verify_jwt_payload};
use dep::aztec::protocol_types::traits::{Deserialize, Serialize};

global JWT_HEADER_MAX_LEN: u32 = 256;
comptime global JWT_PAYLOAD_JSON_MAX_LEN: u32 = 768;
global JWT_PAYLOAD_MAX_LEN: u32 = comptime { nodash::div_ceil(JWT_PAYLOAD_JSON_MAX_LEN, 3) * 4 };
global JWT_NONCE_LEN: u32 = 64;
global EMAIL_LEN: u32 = 64;
global JWT_AUD_MAX_LEN: u32 = 128;

#[derive(Serialize, Deserialize)]
pub struct JWTInput {
    header_and_payload: BoundedVec<u8, JWT_HEADER_MAX_LEN + 1 + JWT_PAYLOAD_MAX_LEN>,
    payload_json: [u8; JWT_PAYLOAD_JSON_MAX_LEN], // TODO: get payload_json from header_and_payload
    signature_limbs: [Field; 18],
    jwt_iat: u64,
    public_key_hash: Field,
    public_key_limbs: [Field; 18],
    public_key_redc_limbs: [Field; 18],
    jwt_nonce: [u8; JWT_NONCE_LEN],
    email_bytes: [u8; EMAIL_LEN],
}

fn verify_jwt(jwt: JWTInput) {
    assert_verify_jwt::<JWT_HEADER_MAX_LEN + 1 + JWT_PAYLOAD_MAX_LEN, JWT_PAYLOAD_JSON_MAX_LEN, JWT_PAYLOAD_MAX_LEN>(
        jwt.header_and_payload,
        jwt.payload_json,
        jwt.public_key_limbs,
        jwt.public_key_redc_limbs,
        jwt.signature_limbs,
    );

    assert_verify_jwt_payload(
        jwt.payload_json,
        jwt.jwt_iat,
        jwt.jwt_nonce,
        jwt.email_bytes,
    );
}
