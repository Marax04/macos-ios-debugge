//! SONDA #4400 — prova (o smentisce) la COLLISIONE DEI NOMI DEI TEMPORANEI.
//!
//! Ipotesi da #4370/#4380: `disassemble_and_lift` costruisce un `X86Lifter` NUOVO per
//! ogni istruzione, il contatore dei temporanei riparte da 0, e il nome e' `tmp{n}`
//! (`rustre-il-llil/src/lib.rs:158`) ⇒ istruzioni diverse producono lo STESSO nome.
//!
//! Caso reale: `sample6_c.exe` a 0x1400015d5 — `cmp $1,%r10d` seguito da
//! `sbb $0xFFFFFFFF,%eax` (idioma «incrementa se il flag e' settato»).
//! Il `cmp` materializza la sua sottrazione; l'`sbb` materializza `cf_in`.
//! Se entrambi ricevono `Temporary(0)`, la collisione e' PROVATA.
//!
//! ⚠ La sonda NON asserisce l'ipotesi: STAMPA i fatti. Se i due insiemi di indici
//! fossero disgiunti, l'ipotesi sarebbe FALSIFICATA — ed e' il risultato che conta.

use rustre_il_llil::{LlilInstruction, LlilRegister};

/// Raccoglie gli indici dei `Temporary` scritti da una singola istruzione.
fn temporanei_scritti(hex: &[u8], ip: u64) -> Vec<u32> {
    let lifted = rustre_arch_x86::disassemble_and_lift(hex, ip, 64);
    let mut ids = Vec::new();
    for (_, ops) in &lifted {
        for op in ops {
            if let LlilInstruction::SetReg { dest: LlilRegister::Temporary(n), .. } = &op.instr {
                ids.push(*n);
            }
        }
    }
    ids
}

#[test]
fn sonda_collisione_temporanei_fra_istruzioni() {
    // cmp $1, %r10d
    let cmp = [0x41u8, 0x83, 0xFA, 0x01];
    // sbb $0xFFFFFFFF, %eax
    let sbb = [0x83u8, 0xD8, 0xFF];

    let t_cmp = temporanei_scritti(&cmp, 0x1_4000_15d5);
    let t_sbb = temporanei_scritti(&sbb, 0x1_4000_15d9);

    println!("SONDA4400 cmp  temporanei = {t_cmp:?}");
    println!("SONDA4400 sbb  temporanei = {t_sbb:?}");

    let comuni: Vec<u32> = t_cmp.iter().copied().filter(|n| t_sbb.contains(n)).collect();
    println!("SONDA4400 INDICI IN COMUNE = {comuni:?}");
    println!(
        "SONDA4400 ESITO = {}",
        if comuni.is_empty() { "DISGIUNTI (ipotesi FALSIFICATA)" } else { "COLLISIONE CONFERMATA" }
    );

    // Controprova sulla SEQUENZA: le due istruzioni liftate INSIEME, come fa il driver.
    let insieme = [0x41u8, 0x83, 0xFA, 0x01, 0x83, 0xD8, 0xFF];
    let t_seq = temporanei_scritti(&insieme, 0x1_4000_15d5);
    println!("SONDA4400 sequenza (cmp+sbb insieme) temporanei = {t_seq:?}");
    let mut unici = t_seq.clone();
    unici.sort_unstable();
    unici.dedup();
    println!(
        "SONDA4400 sequenza: {} scritture, {} indici DISTINTI ⇒ {}",
        t_seq.len(),
        unici.len(),
        if t_seq.len() == unici.len() { "nessun riuso" } else { "RIUSO DELLO STESSO INDICE" }
    );
}

/// #4420 — la correzione, provata per PARAMETRO (non per variabile d'ambiente).
///
/// `lift_to_llil_from_base` deve rendere i temporanei UNICI fra istruzioni successive.
/// Il test vale perche' contiene il **rifiuto**: la prima asserzione ri-dimostra che
/// SENZA base filata la collisione c'e' (se sparisse da sola, il test fallirebbe e
/// direbbe che la premessa e' cambiata).
#[test]
fn base_filata_elimina_la_collisione_dei_temporanei() {
    use iced_x86::{Decoder, DecoderOptions};

    let bytes = [0x41u8, 0x83, 0xFA, 0x01, 0x83, 0xD8, 0xFF]; // cmp $1,%r10d ; sbb $-1,%eax
    let mut dec = Decoder::with_ip(64, &bytes, 0x1_4000_15d5, DecoderOptions::NONE);
    let i_cmp = dec.decode();
    let i_sbb = dec.decode();

    let ids = |ops: &[rustre_il_llil::LlilAnnotatedInstr]| -> Vec<u32> {
        ops.iter()
            .filter_map(|op| match &op.instr {
                LlilInstruction::SetReg { dest: LlilRegister::Temporary(n), .. } => Some(*n),
                _ => None,
            })
            .collect()
    };

    // RIFIUTO: senza base filata, la collisione DEVE esserci (premessa del lavoro).
    let a0 = ids(&rustre_arch_x86::lift_to_llil_with_bits(&i_cmp, 64));
    let b0 = ids(&rustre_arch_x86::lift_to_llil_with_bits(&i_sbb, 64));
    assert!(
        a0.iter().any(|n| b0.contains(n)),
        "premessa CAMBIATA: senza base filata non c'e' piu' collisione ({a0:?} vs {b0:?})"
    );

    // CORREZIONE: filando la base, gli insiemi devono essere DISGIUNTI.
    let (ops_cmp, next) = rustre_arch_x86::lift_to_llil_from_base(&i_cmp, 64, 0);
    let (ops_sbb, _) = rustre_arch_x86::lift_to_llil_from_base(&i_sbb, 64, next);
    let a1 = ids(&ops_cmp);
    let b1 = ids(&ops_sbb);
    println!("SONDA4420 con base filata: cmp={a1:?} sbb={b1:?} (next={next})");
    assert!(
        !a1.iter().any(|n| b1.contains(n)),
        "la base filata NON ha eliminato la collisione: {a1:?} vs {b1:?}"
    );
    assert!(next > 0, "temp_count deve riportare quanti temporanei ha allocato il cmp");
}
