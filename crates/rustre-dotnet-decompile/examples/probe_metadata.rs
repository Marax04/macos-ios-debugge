//! Run the real-metadata bridge over a .NET assembly and print what it found.
//!
//! Usage: `probe_metadata <assembly.dll> [Type] [Method]`
//!
//! Everything printed is read from the image; when nothing can be recovered the
//! reason is printed instead.

use rustre_dotnet_decompile::metadata_bridge::{
    ImageView, decompile_async_from_metadata, lambda_from_metadata, linq_summary_from_metadata,
    recover_all_async_from_image, state_machine_from_metadata,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: probe_metadata <assembly.dll> [Type] [Method]");
        std::process::exit(2);
    };
    let ty = args.next();
    let method = args.next();

    let bytes = std::fs::read(&path).expect("read assembly");
    let view = match ImageView::parse(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("not a managed image: {e}");
            std::process::exit(1);
        }
    };

    println!("types   : {}", view.reader().tables.type_def.len());
    println!("methods : {}", view.reader().tables.method_def.len());
    println!("fields  : {}", view.reader().tables.field.len());

    println!("\n-- type names --");
    for row in 1..=u32::try_from(view.reader().tables.type_def.len()).unwrap_or(0) {
        if let Some(n) = view.type_def_full_name(row) {
            println!("  [{row}] {n}");
        }
    }

    println!("\n-- async methods found --");
    for r in recover_all_async_from_image(&view) {
        match r {
            Ok(f) => println!("  OK  {f}"),
            Err(e) => println!("  ERR {e}"),
        }
    }

    if let (Some(t), Some(m)) = (ty.as_deref(), method.as_deref()) {
        println!("\n-- state machine for {t}::{m} --");
        match state_machine_from_metadata(&view, t, m) {
            Ok(sm) => {
                println!("  class      : {}", sm.full_name);
                println!("  interfaces : {:?}", sm.interfaces);
                for f in &sm.fields {
                    println!("  field      : {} : {}", f.name, f.ty);
                }
                for mm in &sm.methods {
                    println!("  method     : {} ({} insns)", mm.name, mm.instructions.len());
                }
                if let Some(mn) = sm.find_method("MoveNext") {
                    println!("  -- MoveNext IL (first 40) --");
                    for i in mn.instructions.iter().take(40) {
                        println!("    {:#06x}: {}", i.offset, i.insn);
                    }
                }
            }
            Err(e) => println!("  ERR {e}"),
        }
        println!("\n-- decompile_async --");
        match decompile_async_from_metadata(&view, t, m) {
            Ok(f) => println!("{f}"),
            Err(e) => println!("  ERR {e}"),
        }
    }

    if let Some(t) = ty.as_deref() {
        println!("\n-- LINQ summary for {t}::Filter --");
        match linq_summary_from_metadata(&view, t, "Filter") {
            Ok(s) => {
                println!("  chains  : {}", s.chains.len());
                for (c, fields) in &s.captures_by_closure {
                    println!("  closure : {c} -> {fields:?}");
                }
            }
            Err(e) => println!("  ERR {e}"),
        }
    }

    println!("\n-- lambdas in closure classes --");
    for row in 1..=u32::try_from(view.reader().tables.type_def.len()).unwrap_or(0) {
        let Some(full) = view.type_def_full_name(row) else { continue };
        let short = full.rsplit('.').next().unwrap_or(&full).to_string();
        let Ok(td) = view.type_def(row) else { continue };
        for m in &td.methods {
            let simple = m.name.rsplit("::").next().unwrap_or(&m.name).to_string();
            if !simple.contains("b__") {
                continue;
            }
            match lambda_from_metadata(&view, &short, &simple) {
                Ok(l) => println!(
                    "  {short}::{simple} -> {} params={:?} captures={}",
                    l.delegate_type.unwrap_or_default(),
                    l.params.iter().map(|p| p.ty.clone()).collect::<Vec<_>>(),
                    l.captures.len()
                ),
                Err(e) => println!("  {short}::{simple} ERR {e}"),
            }
        }
    }
}
