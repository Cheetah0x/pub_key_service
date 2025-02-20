//test the email registry, can do it in the end to end tests in TS aswell.

use crate::EmailRegistry;

use dep::aztec::{
    oracle::{execution::get_contract_address, random::random},
    prelude::{AztecAddress, NoteHeader},
    protocol_types::storage::map::derive_storage_slot_in_map,
    test::helpers::{cheatcodes, test_environment::TestEnvironment},
};
use std::hash::poseidon2;

use dep::std::println;

// pub unconstrained fn setup() -> (&mut TestEnvironment, AztecAddress, AztecAddress) {
//     let mut env = TestEnvironment::new();

//     println("checkpoint 1");

//     let admin = env.create_account();
//     let user = env.create_account();

//     env.impersonate(admin);

//     // let initializer = EmailRegistry::interface().constructor(admin);
//     // let registry_deploy = env.deploy_self("EmailRegistry").with_private_initializer(initializer);
//     // let registry_address = registry_deploy.to_address();

//     println("checkpoint 2");

//     (&mut env, admin, user)
// }

// #[test]
// unconstrained fn something() {
//     let (env, admin, user) = setup();

//     let some = poseidon2::Poseidon2::hash([1], 1);
//     println(f"some: {some}");

//     println("checkpoint 3");
// }

#[test]
unconstrained fn publicKeyHasing() {
    let publicKeyLimbs: [Field; 18] = [
        0xc9c4d84a1b613ac7d24c364087fcbd,
        0x033339ebfbaf4e21fd163617a2bb73,
        0xbb3ceb30cf4d67cd701d0b5181bc3a,
        0x90921439c866c32f4654997a6e6752,
        0x59b0fa6d7655efe4ca83d46f4d9b6c,
        0xf5364b097843264deabadfb86dc5e8,
        0x230808a523b574fed1296bb6a0e05f,
        0xa7d8b91e95cad972d6985a589afddb,
        0x1d2599567cb2148387cbac377bc1d4,
        0xa5b2258f6d2c776a45f7ac7ce970cc,
        0x2371a73f3425768ed833ed97d8d337,
        0x48d79ba52972b14ca46022392ea000,
        0x3ebcc23faf5aaa81b9d6836026e76e,
        0x7bb7bc031fbf1cfaa61dc9643a5d19,
        0x2309f8f85718e454f92f9080b98cbc,
        0xf295a9ceabb243cbec431aea54b136,
        0x3f576f8cfc785afedd98779b91a733,
        0xe4,
    ];

    let publicKeyRedCLimbs: [Field; 18] = [
        0x54ebec8c07ce6d0d79cdb98091252b,
        0xbc775423b4cd7ada6f9a16f45af769,
        0xe6b6e3342da86d6ee14fcd1263ea8c,
        0x9119b2203c11ec5e5463e456320ab4,
        0x2241e6495e2f294a962d30f40eaf95,
        0x40641e4b38a328b2d70cfd0f721801,
        0x1a3376b29acd6b20cf2c01262a4d2e,
        0xe461e0cee27b3baf95ede6431c68e5,
        0x19036fc0bc76b45c6927a1844bd216,
        0xdfcabb44ef6c3287d9b835d63954cb,
        0x9fc4243e8fa6271b7904b261783fd5,
        0x7105f9b4d77455b9a5a796f809e698,
        0x980bc3fa5075062cf490da14e90b31,
        0xf1a6090c11601e09bccaa7295dab8a,
        0xda77f3a91e16f376fa95434779c2d0,
        0x36ba2233825558876dd177f11efa50,
        0x0834ab245772c369fe784e5d2dd2eb,
        0x11f2,
    ];

    let googleHash1 = 0x2aea5fc990063f5f9007609c87cad3b9703520fe4dc583cab35c440a94c7311d;
    let googleHash2 = 0x0791f79baea84efa9cf53f7e0b49ba37306014fb0adda76cf9734f3a4bcc0fd3;

    println(f"googleHash1: {googleHash1}");
    println(f"googleHash2: {googleHash2}");

    let joinedLimbs = publicKeyLimbs.concat(publicKeyRedCLimbs);
    println(f"joinedLimbs: {joinedLimbs}");

    let publicKeyHash = poseidon2::Poseidon2::hash(joinedLimbs, 36);
    println(f"publicKeyHash: {publicKeyHash}");

    assert(publicKeyHash == googleHash1, "public key hash mismatch");
}
