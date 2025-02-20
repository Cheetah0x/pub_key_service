// The EmailRegistry contract allows users to associate hashed email addresses with their Aztec addresses. Key features:
//      - Email Hash Registration: Users can link a hashed email to their address.
//      - Lookup Functionality: Retrieve the Aztec address associated with a given email hash.

// mod test;
mod jwt;
use dep::aztec::macros::aztec;

//TODO:
// Have some storage that stored the current google public keys to verify that the jwt comes from google
//something the admin can update
//otherwise the anyone can register an email with their own signed email.
#[aztec]
contract EmailRegistry {
    use crate::jwt::helpers::{
        bytes_to_fields, emailHashFromBytes, GooglePublicKeyHashs, verifyGooglePublicKey,
    };
    use crate::jwt::verifyJwt::{JWTInput, verify_jwt};
    use dep::aztec::{
        macros::{functions::{initializer, internal, private, public, view}, storage::storage},
        oracle::debug_log::{debug_log, debug_log_format},
        prelude::{AztecAddress, Map, PublicImmutable, PublicMutable, SharedMutable},
    };
    use std::hash::poseidon2;

    global ZERO_ADDRESS: AztecAddress = AztecAddress::from_field(
        0x0000000000000000000000000000000000000000000000000000000000000000,
    );
    global EMAIL_LEN: u32 = 64;
    global JWT_HEADER_MAX_LEN: u32 = 256;
    global JWT_PAYLOAD_JSON_MAX_LEN: u32 = 768;
    global JWT_PAYLOAD_MAX_LEN: u32 =
        comptime { nodash::div_ceil(JWT_PAYLOAD_JSON_MAX_LEN, 3) * 4 };
    global JWT_NONCE_LEN: u32 = 64;
    global SCHEDULED_DELAY_CHANGE: u32 = 3; //3 blocks to align with porcos findings with devnet
    global GOOGLE_PUBLIC_KEY_LIMBS_LEN: u32 = 36;

    //TODO: change, this is for testing
    global ALLOWED_DELAY: u64 = 1000000;

    #[storage]
    struct Storage<Context> {
        admin: PublicImmutable<AztecAddress, Context>,
        emails: Map<Field, PublicMutable<AztecAddress, Context>, Context>,
        google_public_key_hashs: SharedMutable<GooglePublicKeyHashs, SCHEDULED_DELAY_CHANGE, Context>,
    }

    #[public]
    #[initializer]
    fn constructor(admin: AztecAddress) {
        storage.admin.initialize(admin);
    }

    #[public]
    fn update_google_public_key_hashs(google_public_key_hashs: GooglePublicKeyHashs) {
        let admin = storage.admin.read();
        assert(context.msg_sender() == admin, "only admin can update the google public key hash");
        debug_log_format(
            "updating google public key hash {}",
            [google_public_key_hashs.to_field()],
        );

        storage.google_public_key_hashs.schedule_value_change(google_public_key_hashs);
    }

    #[private]
    fn add_email(jwt: JWTInput) {
        let address = context.msg_sender();
        assert(address != ZERO_ADDRESS, "cannot be zero address");

        //get the google public key hash from storage
        let location = storage.google_public_key_hashs;
        verifyGooglePublicKey(location, jwt.public_key_limbs, jwt.public_key_redc_limbs);

        verify_jwt(jwt);

        let email_hash = emailHashFromBytes(jwt.email_bytes);

        EmailRegistry::at(context.this_address())
            ._add_email_pub(email_hash, jwt.jwt_iat, address)
            .enqueue(&mut context);
    }

    #[public]
    #[internal]
    fn _add_email_pub(email_hash: Field, iat: u64, address: AztecAddress) {
        let existing_address: AztecAddress = storage.emails.at(email_hash).read();

        if (existing_address != ZERO_ADDRESS) {
            assert(false, "Email already exists");
        }

        let timestamp = context.timestamp();
        debug_log_format("timestamp {}", [timestamp.to_field()]);
        //timestamp can be within a few minutes of the iat
        assert(iat < timestamp & timestamp <= (iat + ALLOWED_DELAY), "Timestamp mismatch");

        storage.emails.at(email_hash).write(address);
    }

    #[private]
    fn change_email(old_email_hash: Field, jwt: JWTInput) {
        //Assert that the msg.sender is valid.
        let address = context.msg_sender();
        assert(address != ZERO_ADDRESS, "cannot be zero address");

        //verify the new email
        let location = storage.google_public_key_hashs;
        verifyGooglePublicKey(location, jwt.public_key_limbs, jwt.public_key_redc_limbs);

        verify_jwt(jwt);

        let email_bytes_to_field: [Field; EMAIL_LEN] = bytes_to_fields(jwt.email_bytes);
        let new_email_hash = poseidon2::Poseidon2::hash(email_bytes_to_field, EMAIL_LEN);

        //enquue public call for ownership of old email to remove
        EmailRegistry::at(context.this_address())
            ._change_email_pub(old_email_hash, new_email_hash, jwt.jwt_iat, address)
            .enqueue(&mut context);
    }

    #[public]
    #[internal]
    fn _change_email_pub(
        old_email_hash: Field,
        new_email_hash: Field,
        iat: u64,
        address: AztecAddress,
    ) {
        let existing_address: AztecAddress = storage.emails.at(old_email_hash).read();
        assert(existing_address == address, "not the owner of the old email");

        let new_existing_address: AztecAddress = storage.emails.at(new_email_hash).read();
        if (new_existing_address != ZERO_ADDRESS) {
            assert(false, "new email already exists");
        }

        let timestamp = context.timestamp();
        //timestamp can be within a few minutes of the iat
        assert(iat < timestamp & timestamp <= (iat + ALLOWED_DELAY), "Timestamp mismatch");

        storage.emails.at(old_email_hash).write(ZERO_ADDRESS);
        storage.emails.at(new_email_hash).write(address);
    }

    #[public]
    fn remove_email(email_hash: Field) {
        assert(context.msg_sender() != ZERO_ADDRESS, "cannot be zero address");
        debug_log_format("address {}", [context.msg_sender().to_field()]);

        let current_address = storage.emails.at(email_hash).read();
        debug_log_format("current_address {}", [current_address.to_field()]);
        assert(current_address == context.msg_sender(), "not the owner of the email");

        storage.emails.at(email_hash).write(ZERO_ADDRESS);
    }

    #[view]
    #[public]
    fn get_associated_address(email_hash: Field) -> AztecAddress {
        let address = storage.emails.at(email_hash).read();

        assert(address != ZERO_ADDRESS, "address does not exist");

        address
    }

    #[view]
    #[public]
    fn get_google_public_key_hashs() -> GooglePublicKeyHashs {
        storage.google_public_key_hashs.get_current_value()
    }
}
