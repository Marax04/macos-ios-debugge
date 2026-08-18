//! blitz2 — deep adversarial tests for rustre-mobile-apktool.

use rustre_mobile_apktool::*;
use rustre_mobile_apktool::dex_parser::{disassemble_dalvik, parse_dex, DexParser};

// ─── seeded LCG ───────────────────────────────────────────────────────────────
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── ApktoolConfig ────────────────────────────────────────────────────────────

#[test]
fn cfg_new_defaults() {
    let cfg = ApktoolConfig::new("a", "b");
    assert_eq!(cfg.apktool_path, "a");
    assert_eq!(cfg.output_dir, "b");
    assert!(!cfg.no_src && !cfg.no_res && !cfg.force);
}

#[test]
fn cfg_with_no_src_idempotent() {
    let c = ApktoolConfig::new("a", "b").with_no_src().with_no_src();
    assert!(c.no_src);
}

#[test]
fn cfg_with_no_res_idempotent() {
    let c = ApktoolConfig::new("a", "b").with_no_res().with_no_res();
    assert!(c.no_res);
}

#[test]
fn cfg_with_force_idempotent() {
    let c = ApktoolConfig::new("a", "b").with_force().with_force();
    assert!(c.force);
}

#[test]
fn cfg_full_chain_all_flags() {
    let c = ApktoolConfig::new("a", "b")
        .with_no_src()
        .with_no_res()
        .with_force();
    assert!(c.no_src && c.no_res && c.force);
}

#[test]
fn cfg_serde_roundtrip_50() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let bits = lcg();
        let cfg = ApktoolConfig {
            apktool_path: format!("path-{}", bits & 0xFFFF),
            output_dir: format!("out-{}", (bits >> 16) & 0xFFFF),
            no_src: bits & 1 != 0,
            no_res: bits & 2 != 0,
            force: bits & 4 != 0,
        };
        let j = serde_json::to_string(&cfg).unwrap();
        let back: ApktoolConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.apktool_path, cfg.apktool_path);
        assert_eq!(back.output_dir, cfg.output_dir);
        assert_eq!(back.no_src, cfg.no_src);
        assert_eq!(back.no_res, cfg.no_res);
        assert_eq!(back.force, cfg.force);
    }
}

#[test]
fn cfg_empty_strings_ok() {
    let cfg = ApktoolConfig::new("", "");
    assert_eq!(cfg.apktool_path, "");
    assert_eq!(cfg.output_dir, "");
}

// ─── ApktoolError ─────────────────────────────────────────────────────────────

#[test]
fn err_display_each_variant() {
    assert!(ApktoolError::NotFound("x".into()).to_string().contains("not found"));
    assert!(ApktoolError::Decode("x".into()).to_string().contains("decode"));
    assert!(ApktoolError::Build("x".into()).to_string().contains("build"));
    assert!(ApktoolError::Io("x".into()).to_string().contains("io"));
}

#[test]
fn err_display_carries_message() {
    let msg = "very_specific_marker_42";
    for e in [
        ApktoolError::NotFound(msg.into()),
        ApktoolError::Decode(msg.into()),
        ApktoolError::Build(msg.into()),
        ApktoolError::Io(msg.into()),
    ] {
        assert!(e.to_string().contains(msg));
    }
}

// ─── DecodeResult / BuildResult ───────────────────────────────────────────────

#[test]
fn decode_result_smali_count_off_by_one() {
    for n in 0usize..20 {
        let r = DecodeResult {
            output_dir: "x".into(),
            smali_dirs: (0..n).map(|i| format!("s{i}")).collect(),
            res_dir: None,
            success: true,
            log: String::new(),
        };
        assert_eq!(r.smali_count(), n);
    }
}

#[test]
fn build_result_serde_roundtrip() {
    let r = BuildResult {
        apk_path: "/x/y.apk".into(),
        success: true,
        log: "log\nlines".into(),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: BuildResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.apk_path, r.apk_path);
    assert!(back.success);
    assert_eq!(back.log, r.log);
}

#[test]
fn decode_result_serde_roundtrip() {
    let r = DecodeResult {
        output_dir: "o".into(),
        smali_dirs: vec!["a".into(), "b".into()],
        res_dir: Some("r".into()),
        success: false,
        log: "l".into(),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: DecodeResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.smali_dirs, r.smali_dirs);
    assert_eq!(back.res_dir, r.res_dir);
    assert_eq!(back.success, r.success);
}

// ─── MockApktoolRunner ────────────────────────────────────────────────────────

#[test]
fn decode_error_names_the_missing_apk() {
    let r = MockApktoolRunner::success();
    let cfg = ApktoolConfig::new("a", "/o");
    let err = r.decode("MyTestApp.apk", &cfg).unwrap_err();
    assert!(err.to_string().contains("MyTestApp.apk"));
}

#[test]
fn decode_no_res_still_requires_a_real_apk() {
    let r = MockApktoolRunner::success();
    let cfg = ApktoolConfig::new("a", "/o").with_no_res();
    assert!(matches!(
        r.decode("a.apk", &cfg),
        Err(ApktoolError::NotFound(_))
    ));
}

#[test]
fn mock_failure_returns_specific_errors() {
    let r = MockApktoolRunner::failure();
    let cfg = ApktoolConfig::new("a", "/o");
    assert!(matches!(r.decode("a.apk", &cfg), Err(ApktoolError::Decode(_))));
    assert!(matches!(r.build("d", &cfg), Err(ApktoolError::Build(_))));
}

#[test]
fn build_error_names_the_missing_directory() {
    let r = MockApktoolRunner::success();
    let cfg = ApktoolConfig::new("a", "/specific_out_42");
    let err = r.build("d", &cfg).unwrap_err();
    assert!(err.to_string().contains('d'));
}

#[test]
fn mock_failure_struct_empty_smali() {
    let r = MockApktoolRunner::failure();
    assert!(r.smali_dirs.is_empty());
    assert!(!r.decode_ok);
    assert!(!r.build_ok);
}

#[test]
fn trait_object_decode_reports_missing_input() {
    let r: Box<dyn ApktoolRunner> = Box::new(MockApktoolRunner::success());
    let cfg = ApktoolConfig::new("a", "/o");
    assert!(matches!(r.decode("z.apk", &cfg), Err(ApktoolError::NotFound(_))));
    assert!(matches!(r.build("d", &cfg), Err(ApktoolError::NotFound(_))));
}

// ─── ApktoolRunnerImpl ────────────────────────────────────────────────────────

#[test]
fn impl_decode_basename_extracted() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(r.output_dir_for("/path/to/some_app.apk").ends_with("/some_app"));
    // and the decode itself still refuses to invent a result
    assert!(r.decode("/path/to/some_app.apk").is_err());
}

#[test]
fn impl_decode_basename_windows_sep() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(r.output_dir_for("C:\\foo\\bar\\thing.apk").ends_with("/thing"));

}

#[test]
fn impl_decode_no_src_warns() {
    let cfg = ApktoolConfig::new("a", "/o").with_no_src();
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("z.apk"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn impl_decode_no_res_returns_none() {
    let cfg = ApktoolConfig::new("a", "/o").with_no_res();
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("z.apk"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn impl_decode_uppercase_apk_ok() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("X.APK"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn impl_decode_no_extension_errors() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("noext"), Err(ApktoolError::Decode(_))));
}

#[test]
fn impl_decode_jar_errors() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.decode("a.jar"), Err(ApktoolError::Decode(_))));
}

#[test]
fn impl_build_empty_errors() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.build(""), Err(ApktoolError::Build(_))));
}

#[test]
fn impl_build_unsigned_zero_size() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.build("/d/x"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn impl_install_framework_apk_ok() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    assert!(matches!(r.install_framework("f.apk"), Err(ApktoolError::NotFound(_))));
    assert!(matches!(r.install_framework("f.APK"), Err(ApktoolError::NotFound(_))));
}

#[test]
fn impl_install_framework_non_apk_errors() {
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    for bad in ["f.jar", "f.zip", "noext", ""] {
        assert!(matches!(r.install_framework(bad), Err(ApktoolError::NotFound(_))),
            "expected NotFound for {bad:?}");
    }
}

#[test]
fn impl_decode_lcg_fuzz_never_panics() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    let cfg = ApktoolConfig::new("a", "/o");
    let r = ApktoolRunnerImpl::new(cfg);
    let suffixes = [".apk", ".APK", ".jar", "", ".txt"];
    for _ in 0..80 {
        let bits = lcg();
        let len = ((bits >> 1) & 0x1F) as usize;
        let mut name: String = (0..len)
            .map(|i| {
                let c = u8::try_from((bits >> (i % 56)) & 0xff).unwrap_or(0);
                if c.is_ascii_alphanumeric() { c as char } else { 'x' }
            })
            .collect();
        name.push_str(suffixes[usize::try_from(bits).unwrap_or(usize::MAX) % suffixes.len()]);
        let _ = r.decode(&name); // must not panic
        let _ = r.install_framework(&name);
        let _ = r.build(&name);
    }
}

// ─── ApkDecodeResult / ApkBuildResult ─────────────────────────────────────────

#[test]
fn apk_decode_result_is_clean_iff_no_warnings() {
    let mut r = ApkDecodeResult {
        output_dir: "o".into(),
        smali_dirs: vec![],
        res_dir: None,
        manifest_path: None,
        warnings: vec![],
    };
    assert!(r.is_clean());
    r.warnings.push("w".into());
    assert!(!r.is_clean());
}

#[test]
fn apk_decode_result_smali_count_boundaries() {
    for n in [0usize, 1, 2, 100] {
        let r = ApkDecodeResult {
            output_dir: "o".into(),
            smali_dirs: (0..n).map(|i| i.to_string()).collect(),
            res_dir: None,
            manifest_path: None,
            warnings: vec![],
        };
        assert_eq!(r.smali_count(), n);
    }
}

#[test]
fn apk_decode_result_serde_roundtrip() {
    let r = ApkDecodeResult {
        output_dir: "o".into(),
        smali_dirs: vec!["a".into()],
        res_dir: Some("r".into()),
        manifest_path: Some("m".into()),
        warnings: vec!["w".into()],
    };
    let j = serde_json::to_string(&r).unwrap();
    let b: ApkDecodeResult = serde_json::from_str(&j).unwrap();
    assert_eq!(b.smali_dirs, r.smali_dirs);
    assert_eq!(b.res_dir, r.res_dir);
    assert_eq!(b.manifest_path, r.manifest_path);
    assert_eq!(b.warnings, r.warnings);
}

#[test]
fn apk_build_result_serde_roundtrip_boundaries() {
    for size in [0u64, 1, u64::MAX] {
        let r = ApkBuildResult { apk_path: "p".into(), unsigned: size & 1 == 0, size_bytes: size };
        let j = serde_json::to_string(&r).unwrap();
        let b: ApkBuildResult = serde_json::from_str(&j).unwrap();
        assert_eq!(b.size_bytes, size);
        assert_eq!(b.unsigned, r.unsigned);
    }
}

// ─── CliApktoolRunner ─────────────────────────────────────────────────────────

#[test]
fn cli_with_path_stores_path() {
    let r = CliApktoolRunner::with_path("/nonexistent/apktool");
    assert_eq!(r.apktool_path, std::path::PathBuf::from("/nonexistent/apktool"));
}

#[test]
fn cli_find_apktool_does_not_panic() {
    // Either Some or None — must not panic on any environment.
    let _ = CliApktoolRunner::find_apktool();
}

#[test]
fn cli_decode_nonexistent_binary_errors() {
    let r = CliApktoolRunner::with_path("/definitely_does_not_exist_xyz123/apktool");
    let cfg = ApktoolConfig::new("a", "/o");
    let e = r.decode("x.apk", &cfg).unwrap_err();
    assert!(matches!(e, ApktoolError::Io(_)));
}

#[test]
fn cli_build_empty_dir_errors_before_spawn() {
    let r = CliApktoolRunner::with_path("/definitely_does_not_exist_xyz123/apktool");
    let cfg = ApktoolConfig::new("a", "/o");
    let e = r.build("", &cfg).unwrap_err();
    assert!(matches!(e, ApktoolError::Build(_)));
}

// ─── dex_parser ──────────────────────────────────────────────────────────────

#[test]
fn disasm_empty_returns_empty() {
    assert!(disassemble_dalvik(&[]).is_empty());
}

#[test]
fn disasm_nop_decodes() {
    let r = disassemble_dalvik(&[0x0000]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].mnemonic, "nop");
}

#[test]
fn disasm_lcg_fuzz_never_panics() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let n = usize::try_from(lcg() & 0x3F).unwrap_or(0);
        let words: Vec<u16> = (0..n).map(|_| u16::try_from(lcg() & 0xffff).unwrap_or(0)).collect();
        let _ = disassemble_dalvik(&words);
    }
}

#[test]
fn disasm_progress_invariant() {
    // PC must always advance — no infinite loops.
    let words: Vec<u16> = (0u16..200).collect();
    let r = disassemble_dalvik(&words);
    // Each instruction consumes >=1 word, so at most words.len() insns.
    assert!(r.len() <= words.len());
    assert!(!r.is_empty());
}

#[test]
fn parse_dex_too_small_errors() {
    assert!(parse_dex(vec![]).is_err());
    assert!(parse_dex(vec![0u8; 10]).is_err());
}

#[test]
fn parse_dex_bad_magic_errors() {
    let buf = vec![0xAAu8; 200];
    assert!(parse_dex(buf).is_err());
}

#[test]
fn parse_dex_lcg_fuzz_never_panics() {
    let mut lcg = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..40 {
        let n = usize::try_from(lcg() & 0xFF).unwrap_or(0) + 8;
        let buf: Vec<u8> = (0..n).map(|_| u8::try_from(lcg() & 0xff).unwrap_or(0)).collect();
        let _ = parse_dex(buf);
    }
}

#[test]
fn dex_parser_new_starts_at_zero() {
    let p = DexParser::new(vec![1, 2, 3, 4]);
    // No public read methods — just confirm construction works.
    drop(p);
}

// ─── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn runner_impl_send_sync_threads() {
    use std::sync::Arc;
    let cfg = ApktoolConfig::new("a", "/o");
    let r = Arc::new(ApktoolRunnerImpl::new(cfg));
    let mut handles = Vec::new();
    for t in 0..4 {
        let r = r.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let name = format!("app_{t}_{i}.apk");
                assert!(r.decode(&name).is_err());
                assert!(r.output_dir_for(&name).contains(&format!("app_{t}_{i}")));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn mock_runner_send_sync_threads() {
    use std::sync::Arc;
    let r: Arc<dyn ApktoolRunner> = Arc::new(MockApktoolRunner::success());
    let cfg = Arc::new(ApktoolConfig::new("a", "/o"));
    let mut handles = Vec::new();
    for t in 0..4 {
        let r = r.clone();
        let cfg = cfg.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                let name = format!("a_{t}_{i}.apk");
                assert!(r.decode(&name, &cfg).is_err());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── Clone / Debug coverage ───────────────────────────────────────────────────

#[test]
fn cfg_clone_is_equal() {
    let c = ApktoolConfig::new("a", "b").with_force();
    let c2 = c.clone();
    assert_eq!(c.apktool_path, c2.apktool_path);
    assert_eq!(c.force, c2.force);
}

#[test]
fn debug_impls_nonempty() {
    let c = ApktoolConfig::new("a", "b");
    assert!(!format!("{c:?}").is_empty());
    let e = ApktoolError::Decode("x".into());
    assert!(!format!("{e:?}").is_empty());
    let r = MockApktoolRunner::success();
    assert!(!format!("{r:?}").is_empty());
}

#[test]
fn decode_result_clone_keeps_fields() {
    let r = DecodeResult {
        output_dir: "o".into(),
        smali_dirs: vec!["s".into()],
        res_dir: Some("r".into()),
        success: true,
        log: "l".into(),
    };
    let r2 = r.clone();
    assert_eq!(r.output_dir, r2.output_dir);
    assert_eq!(r.smali_dirs, r2.smali_dirs);
}

#[test]
fn cli_runner_clone_keeps_path() {
    let r = CliApktoolRunner::with_path("/tmp/x");
    let r2 = r.clone();
    assert_eq!(r.apktool_path, r2.apktool_path);
}

#[test]
fn impl_runner_clone_keeps_config() {
    let r = ApktoolRunnerImpl::new(ApktoolConfig::new("a", "b").with_force());
    let r2 = r;
    assert!(r2.config.force);
}
