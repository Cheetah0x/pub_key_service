use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::{rsa::verify_sha256_pkcs1v15, types::RBN2048};

// TODO: use official noir base64 library when it supports base64url
mod noir_base64;

use std::hash::poseidon2;

// Note: keep in sync with JS
// TODO(security): if sub is too long, account is lost
global JWT_SUB_MAX_LEN: u32 = 64; // UUID is 36 chars but we add some buffer to be safe
// Note: keep in sync with JS
global JWT_NONCE_LEN: u32 = 64; // 32 bytes
// Add this with the other constants
global EMAIL_LEN: u32 = 64;
global JWT_AUD_MAX_LEN: u32 = 128;
global JWT_ISS_MAX_LEN: u32 = 32;

global AUD_BYTES: [u8; JWT_AUD_MAX_LEN] = [
    // "1034085538051-hlu3dd6l0gguos52pjjkns2h0rjothqi.apps.googleusercontent.com"
    49, 48, 51, 52, 48, 56, 53, 53, 51, 56, 48, 53, 49, 45, 104, 108, 117, 51, 100, 100, 54, 108,
    48, 103, 103, 117, 111, 115, 53, 50, 112, 106, 106, 107, 110, 115, 50, 104, 48, 114, 106, 111,
    116, 104, 113, 105, 46, 97, 112, 112, 115, 46, 103, 111, 111, 103, 108, 101, 117, 115, 101, 114,
    99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];

global GOOGLE_ISS_BYTES: [u8; JWT_ISS_MAX_LEN] = [
    104, 116, 116, 112, 115, 58, 47, 47, 97, 99, 99, 111, 117, 110, 116, 115, 46, 103, 111, 111,
    103, 108, 101, 46, 99, 111, 109, 0, 0, 0, 0, 0,
];

//TODO: global APPLE_ISS_BYTES

pub fn assert_verify_jwt<let HeaderAndPayloadMaxLen: u32, let PayloadJsonMaxLen: u32, let PayloadJsonBase64MaxLen: u32>(
    header_and_payload: BoundedVec<u8, HeaderAndPayloadMaxLen>,
    // padded with spaces, so JSON parser can parse it
    payload_json_padded: [u8; PayloadJsonMaxLen],
    pubkey_limbs: [Field; 18],
    pubkey_redc_limbs: [Field; 18],
    signature: [Field; 18],
) {
    assert_payloads_match::<HeaderAndPayloadMaxLen, PayloadJsonMaxLen, PayloadJsonBase64MaxLen>(
        header_and_payload,
        payload_json_padded,
    );

    // Verify RSA signature
    let hash = std::hash::sha256_var(header_and_payload.storage, header_and_payload.len() as u64);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, pubkey_limbs, pubkey_redc_limbs);
    let signature: RBN2048 = RBN2048::from_array(params, signature);
    let result = verify_sha256_pkcs1v15(hash, signature, 65537);
    assert(result, "jwt verification failed: signature");
}

pub fn assert_verify_jwt_payload<let N: u32>(
    payload_json_padded: [u8; N],
    expected_jwt_iat: u64,
    expected_jwt_nonce: [u8; JWT_NONCE_LEN],
    expected_email_bytes: [u8; EMAIL_LEN],
) {
    // TODO(security): haystack size should be based on N
    assert(N <= 1024, "payload_json length must be less than 1024");
    let haystack: string_search::StringBody1024 =
        string_search::StringBody::new(payload_json_padded, payload_json_padded.len());

    //another option is to assert the iss domain to make sure that it comes from google or apple.
    {
        let iss_bytes: [u8; JWT_ISS_MAX_LEN] = extract_jwt_payload_field_str(haystack, "iss");
        assert(iss_bytes == GOOGLE_ISS_BYTES, "iss mismatch");
    }

    //assert the aud is ours, just to make it permissioned from us in the contract
    //we can have this option where it is hardcoded or we can allow other people to use it
    {
        let check_aud_bytes: [u8; JWT_AUD_MAX_LEN] = extract_jwt_payload_field_str(haystack, "aud");
        assert(check_aud_bytes == AUD_BYTES, "aud mismatch");
    }

    {
        //verify email
        let email_bytes: [u8; EMAIL_LEN] = extract_jwt_payload_field_str(haystack, "email");
        assert(
            email_bytes == expected_email_bytes,
            f"email mismatch: expected {expected_email_bytes}, got {email_bytes}",
        );
    }
    //TODO: does this need to be turned to bytes at all?

    {
        // verify "jwt.nonce"
        let jwt_nonce: [u8; JWT_NONCE_LEN] = extract_jwt_payload_field_str(haystack, "nonce");
        assert(
            jwt_nonce == expected_jwt_nonce,
            f"jwt.nonce mismatch: expected {expected_jwt_nonce}, got {jwt_nonce}",
        );
    }

    {
        // verify "jwt.iat"
        let needle_text = "\"iat\":".as_bytes();
        let needle: string_search::SubString32 =
            string_search::SubString::new(needle_text, needle_text.len());
        let (result, match_position) = haystack.substring_match(needle);
        assert(result, "jwt.iat not found");
        let mut data = [0 as u8; 20];
        let mut stop = false;
        for i in 0..20 {
            let chr = payload_json_padded[match_position + needle_text.len() + i];
            if chr == ",".as_bytes()[0] {
                stop = true;
            }
            if !stop {
                data[i] = chr;
            }
        }
        assert(stop, "jwt.iat is too long");
        let iat = nodash::str_to_u64(data);
        assert(expected_jwt_iat == iat, "jwt.iat mismatch");
    }
}

fn extract_jwt_payload_field_str<let N: u32, let H: u32>(
    haystack: string_search::StringBody1024,
    needle_text: str<H>,
) -> [u8; N] {
    // `needle` -> `"needle": "`
    let needle_text = "\"".as_bytes().concat(needle_text.as_bytes()).concat("\":\"".as_bytes());

    let needle: string_search::SubString32 =
        string_search::SubString::new(needle_text, needle_text.len());
    let (result, match_position) = haystack.substring_match(needle);
    assert(result, "jwt field not found");
    let mut data = [0 as u8; N];
    let mut stop = false;
    for i in 0..N {
        let chr = haystack.body[match_position + needle_text.len() + i];
        if chr == "\"".as_bytes()[0] {
            stop = true;
        }
        if !stop {
            data[i] = chr;
        }
    }
    assert(
        stop | (haystack.body[match_position + needle_text.len() + N] == "\"".as_bytes()[0]),
        "jwt field is too long",
    );
    data
}

fn assert_payloads_match<let N: u32, let M: u32, let M2: u32>(
    header_and_payload: BoundedVec<u8, N>,
    payload_json_padded: [u8; M],
) {
    assert(M2 == nodash::div_ceil(M, 3) * 4, "payload_json_padded length mismatch");
    let from_index = unsafe {
        let dot_index = find_dot(header_and_payload.storage);
        assert(header_and_payload.storage[dot_index] == ".".as_bytes()[0], "dot not found");
        dot_index + 1
    };

    // noir team switched it up, decode is encode
    let encoded: [u8; M2] = noir_base64::base64url_decode(payload_json_padded);

    for i in 0..M2 {
        let j = from_index + i;
        // TODO(security): assert that the rest of the json payload is empty
        if j < header_and_payload.len() - 1 {
            assert(header_and_payload.storage[j] == encoded[i], "payload mismatch");
        }
    }
}

unconstrained fn find_dot<let N: u32>(input: [u8; N]) -> u32 {
    let mut result = 0;
    let mut found = false;
    for i in 0..N {
        if (input[i] == ".".as_bytes()[0]) {
            result = i;
            found = true;
            break;
        }
    }
    assert(found, "dot not found");
    result
}


