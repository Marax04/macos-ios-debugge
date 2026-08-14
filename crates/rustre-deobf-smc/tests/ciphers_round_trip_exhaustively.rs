//! Inverse-pair properties, checked over their **entire** input domain.
//!
//! `XorChainStep::apply`/`reverse` and `AddRolCipher::encrypt_byte`/
//! `decrypt_byte` are mathematical inverses, and a byte transform has only 256
//! possible inputs — so this is not sampling, it is exhaustion. Combined with
//! every parameter each transform accepts, the whole behaviour space is covered
//! and no oracle is needed: the property *is* the specification.
//!
//! This matters more than a typical regression guard. These pairs are what turns
//! an encrypted payload back into code; a one-sided change (say, a rotation
//! direction) would leave `encrypt` working, `decrypt` producing plausible
//! garbage, and nothing crashing.

use rustre_deobf_smc::{AddRolCipher, XorChain, XorChainStep};

#[test]
fn every_xor_chain_step_is_exactly_reversible_for_every_byte() {
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    // `pre_op` is documented as 0 = none, 1 = NOT, 2 = ROL, 3 = ROR; 4 and 255
    // exercise the "unknown op" fall-through, which must also round trip.
    for pre_op in [0u8, 1, 2, 3, 4, 255] {
        for rot_amount in 0u8..=8 {
            for key in [0u8, 1, 0x42, 0xFF] {
                let step = XorChainStep { key, pre_op, rot_amount };
                for byte in 0u8..=255 {
                    let back = step.reverse(step.apply(byte));
                    if back != byte {
                        divergences.push(format!(
                            "pre_op={pre_op} rot={rot_amount} key={key:#04x}: \
                             {byte:#04x} -> {:#04x} -> {back:#04x}",
                            step.apply(byte)
                        ));
                    }
                    checked += 1;
                }
            }
        }
    }

    assert_eq!(
        checked,
        6 * 9 * 4 * 256,
        "anti-vacuity: the full parameter/byte space must be exercised"
    );
    // Report every divergence at once: a one-sided change usually breaks a
    // whole family of parameters, and the shape of the failure is the diagnosis.
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_multi_step_chain_decrypts_what_it_encrypts() {
    // Order matters as much as the per-step inverse: `decrypt` must fold the
    // steps in reverse. A chain of steps that are individually reversible can
    // still fail to round trip if the order is not undone.
    let mut chain = XorChain::new();
    chain.push(XorChainStep { key: 0x5A, pre_op: 2, rot_amount: 3 });
    chain.push(XorChainStep { key: 0xC3, pre_op: 1, rot_amount: 0 });
    chain.push(XorChainStep { key: 0x0F, pre_op: 3, rot_amount: 5 });

    let plain: Vec<u8> = (0u8..=255).collect();
    let cipher = chain.encrypt(&plain);
    let back = chain.decrypt(&cipher);

    assert_eq!(back, plain, "the chain did not decrypt its own output");
    assert_ne!(
        cipher, plain,
        "premise: a three-step chain must actually change the data"
    );
}

#[test]
fn add_rol_is_exactly_reversible_for_every_byte_and_parameter() {
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for add_first in [false, true] {
        // Rotation amounts past 7 are exercised deliberately: `rol8`/`ror8` mask
        // internally, and the pair must stay inverse for the masked values too.
        for rol_amount in 0u8..=9 {
            for add_key in [0u8, 1, 0x7F, 0xFF] {
                let cipher = AddRolCipher::new(add_key, rol_amount, add_first);
                for byte in 0u8..=255 {
                    let back = cipher.decrypt_byte(cipher.encrypt_byte(byte));
                    if back != byte {
                        divergences.push(format!(
                            "add_first={add_first} rol={rol_amount} add_key={add_key:#04x}: \
                             {byte:#04x} -> {:#04x} -> {back:#04x}",
                            cipher.encrypt_byte(byte)
                        ));
                    }
                    checked += 1;
                }
            }
        }
    }

    assert_eq!(
        checked,
        2 * 10 * 4 * 256,
        "anti-vacuity: the full parameter/byte space must be exercised"
    );
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn the_ciphers_actually_transform_their_input() {
    // Premise: the round trips above are not passing because both directions
    // are the identity.
    let step = XorChainStep { key: 0x42, pre_op: 2, rot_amount: 3 };
    assert_ne!(step.apply(0x01), 0x01, "premise: the step must change the byte");

    let cipher = AddRolCipher::new(0x11, 3, true);
    assert_ne!(
        cipher.encrypt_byte(0x01),
        0x01,
        "premise: the cipher must change the byte"
    );
}
