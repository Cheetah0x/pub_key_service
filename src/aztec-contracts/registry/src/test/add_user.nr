use crate::EmailRegistry;
use crate::test::utils;

use dep::aztec::{
    oracle::{execution::get_contract_address, random::random},
    prelude::{AztecAddress, NoteHeader},
    protocol_types::storage::map::derive_storage_slot_in_map,
    test::helpers::{cheatcodes, test_environment::TestEnvironment},
};
use dep::std::hash::poseidon2::{self, Poseidon2};
use dep::std::println;

// #[test]
// pub unconstrained fn add_user() {
//     let (env, admin, user, registry_address) = utils::setup();

//     //for long emails, we are going to have to use field compressed strings i think

//     let email = "gamergoober@gmail.com";
//     let email_field = [email.to_field()];
//     let email_hash = poseidon2::Poseidon2::hash(email_field, 1);

//     env.impersonate(user);

//     println("adding email");

//     let email_add =
//         EmailRegistry::at(registry_address).add_email(email_hash).call(&mut env.public());

//     env.advance_block_by(1);

//     println("added email");

//     //view the email
//     let get_address = EmailRegistry::at(registry_address).get_associated_address(email_hash).view(
//         &mut env.public(),
//     );

//     assert(get_address == user, "Email not associated with user");
// }
