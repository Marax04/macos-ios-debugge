//! Library version detection for FLIRT.
//!
//! Provides [`LibraryDetector`] and [`LibraryDb`] with 50+ common library entries
//! covering OpenSSL, zlib, libpng, libjpeg, libcurl, Boost, Qt, MFC, ATL, STL, etc.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Platform / Arch ─────────────────────────────────────────────────────────

/// Target platform for a library.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    Android,
    Ios,
    FreeBsd,
    Any,
}

impl Platform {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
            Self::Android => "Android",
            Self::Ios => "iOS",
            Self::FreeBsd => "FreeBSD",
            Self::Any => "Any",
        }
    }
}

/// CPU architecture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    Ppc,
    Any,
}

impl Arch {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "ARM",
            Self::Arm64 => "ARM64",
            Self::Mips => "MIPS",
            Self::Mips64 => "MIPS64",
            Self::Ppc => "PPC",
            Self::Any => "Any",
        }
    }
}

// ─── LibrarySignature ────────────────────────────────────────────────────────

/// A set of identifying characteristics for a specific library version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySignature {
    /// Library name (e.g. "openssl").
    pub name: String,
    /// Version string (e.g. "1.1.1t").
    pub version: String,
    /// Target architecture.
    pub arch: Arch,
    /// Target platform.
    pub platform: Platform,
    /// Characteristic function names that identify this library version.
    pub marker_functions: Vec<String>,
    /// Characteristic string constants found in this library.
    pub marker_strings: Vec<String>,
    /// Characteristic imported/exported symbol patterns.
    pub symbol_patterns: Vec<String>,
    /// Additional notes.
    pub notes: String,
}

impl LibrarySignature {
    /// Create a minimal library signature.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        arch: Arch,
        platform: Platform,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            arch,
            platform,
            marker_functions: Vec::new(),
            marker_strings: Vec::new(),
            symbol_patterns: Vec::new(),
            notes: String::new(),
        }
    }

    /// Add a marker function name.
    #[must_use]
    pub fn with_function(mut self, f: impl Into<String>) -> Self {
        self.marker_functions.push(f.into());
        self
    }

    /// Add a marker string constant.
    #[must_use]
    pub fn with_string(mut self, s: impl Into<String>) -> Self {
        self.marker_strings.push(s.into());
        self
    }

    /// Add a symbol pattern.
    #[must_use]
    pub fn with_symbol(mut self, s: impl Into<String>) -> Self {
        self.symbol_patterns.push(s.into());
        self
    }

    /// Add notes.
    #[must_use]
    pub fn with_notes(mut self, n: impl Into<String>) -> Self {
        self.notes = n.into();
        self
    }
}

// ─── LibraryMatch ────────────────────────────────────────────────────────────

/// A matched library with confidence information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryMatch {
    /// Library name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Architecture.
    pub arch: Arch,
    /// Platform.
    pub platform: Platform,
    /// Match confidence [0.0, 1.0].
    pub confidence: f64,
    /// Which markers were matched.
    pub matched_markers: Vec<String>,
    /// Notes from the signature.
    pub notes: String,
}

impl LibraryMatch {
    /// Return a display string.
    #[must_use]
    pub fn display(&self) -> String {
        format!(
            "{} {} ({}/{}) confidence={:.0}%",
            self.name,
            self.version,
            self.arch.label(),
            self.platform.label(),
            self.confidence * 100.0
        )
    }
}

// ─── LibraryDb ───────────────────────────────────────────────────────────────

/// Database of library signatures used by [`LibraryDetector`].
pub struct LibraryDb {
    signatures: Vec<LibrarySignature>,
}

impl LibraryDb {
    /// Create an empty database.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Create a database pre-populated with 50+ common library signatures.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut db = Self::empty();
        db.populate_builtins();
        db
    }

    /// Add a signature to the database.
    pub fn add(&mut self, sig: LibrarySignature) {
        self.signatures.push(sig);
    }

    /// Return the number of signatures in the database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Return true if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Return all signatures matching a library name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&LibrarySignature> {
        self.signatures
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case(name))
            .collect()
    }

    /// Return all unique library names in the database.
    #[must_use]
    pub fn library_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .signatures
            .iter()
            .map(|s| s.name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }

    fn populate_builtins(&mut self) {
        self.populate_builtins_ssl();
        self.populate_builtins_compression();
        self.populate_builtins_imaging_and_xml();
        self.populate_builtins_networking();
        self.populate_builtins_windows_native();
        self.populate_builtins_system_libs();
        self.populate_builtins_misc_libs();
    }

    fn populate_builtins_ssl(&mut self) {
        // ── OpenSSL ──────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("openssl", "1.0.2u", Arch::X86_64, Platform::Any)
                .with_function("SSL_CTX_new")
                .with_function("SSL_connect")
                .with_function("EVP_EncryptInit")
                .with_string("OpenSSL 1.0.2u")
                .with_notes("Legacy OpenSSL 1.0.2 LTS branch"),
        );
        self.add(
            LibrarySignature::new("openssl", "1.1.1t", Arch::X86_64, Platform::Any)
                .with_function("SSL_CTX_new")
                .with_function("OPENSSL_init_ssl")
                .with_function("TLS_method")
                .with_string("OpenSSL 1.1.1t")
                .with_notes("OpenSSL 1.1.1 LTS"),
        );
        self.add(
            LibrarySignature::new("openssl", "3.0.8", Arch::X86_64, Platform::Any)
                .with_function("OSSL_PROVIDER_load")
                .with_function("EVP_MD_fetch")
                .with_string("OpenSSL 3.0.8")
                .with_notes("OpenSSL 3.0 LTS"),
        );
        self.add(
            LibrarySignature::new("openssl", "3.1.0", Arch::X86_64, Platform::Any)
                .with_function("OSSL_PROVIDER_load")
                .with_string("OpenSSL 3.1.0")
                .with_notes("OpenSSL 3.1"),
        );

    }

    fn populate_builtins_compression(&mut self) {
        // ── zlib ─────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("zlib", "1.2.11", Arch::Any, Platform::Any)
                .with_function("deflate")
                .with_function("inflate")
                .with_function("deflateInit_")
                .with_string("1.2.11")
                .with_string("deflate 1.2.11")
                .with_notes("zlib 1.2.11"),
        );
        self.add(
            LibrarySignature::new("zlib", "1.2.13", Arch::Any, Platform::Any)
                .with_function("deflate")
                .with_function("inflate")
                .with_string("1.2.13")
                .with_notes("zlib 1.2.13"),
        );
        self.add(
            LibrarySignature::new("zlib", "1.3.1", Arch::Any, Platform::Any)
                .with_function("deflate")
                .with_function("inflate")
                .with_string("1.3.1")
                .with_notes("zlib 1.3.1"),
        );

    }

    fn populate_builtins_imaging_and_xml(&mut self) {
        // ── libpng ───────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libpng", "1.6.39", Arch::Any, Platform::Any)
                .with_function("png_create_read_struct")
                .with_function("png_read_image")
                .with_string("libpng version 1.6.39")
                .with_notes("libpng 1.6.39"),
        );
        self.add(
            LibrarySignature::new("libpng", "1.6.40", Arch::Any, Platform::Any)
                .with_function("png_create_read_struct")
                .with_string("libpng version 1.6.40")
                .with_notes("libpng 1.6.40"),
        );

        // ── libjpeg / libjpeg-turbo ──────────────────────────────────────────
        self.add(
            LibrarySignature::new("libjpeg", "9e", Arch::Any, Platform::Any)
                .with_function("jpeg_CreateDecompress")
                .with_function("jpeg_start_decompress")
                .with_string("JPEG")
                .with_notes("libjpeg 9e"),
        );
        self.add(
            LibrarySignature::new("libjpeg-turbo", "2.1.4", Arch::Any, Platform::Any)
                .with_function("jpeg_CreateDecompress")
                .with_function("tjDecompress2")
                .with_string("libjpeg-turbo")
                .with_notes("libjpeg-turbo 2.1.4"),
        );
        self.add(
            LibrarySignature::new("libjpeg-turbo", "3.0.0", Arch::Any, Platform::Any)
                .with_function("jpeg_CreateDecompress")
                .with_function("tjDecompress3")
                .with_string("libjpeg-turbo 3.0.0")
                .with_notes("libjpeg-turbo 3.0"),
        );

    }

    fn populate_builtins_networking(&mut self) {
        // ── libcurl ──────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libcurl", "7.88.1", Arch::Any, Platform::Any)
                .with_function("curl_easy_init")
                .with_function("curl_easy_perform")
                .with_function("curl_global_init")
                .with_string("libcurl/7.88.1")
                .with_notes("libcurl 7.88.1"),
        );
        self.add(
            LibrarySignature::new("libcurl", "8.0.1", Arch::Any, Platform::Any)
                .with_function("curl_easy_init")
                .with_string("libcurl/8.0.1")
                .with_notes("libcurl 8.0.1"),
        );
        self.add(
            LibrarySignature::new("libcurl", "8.4.0", Arch::Any, Platform::Any)
                .with_function("curl_easy_init")
                .with_string("libcurl/8.4.0")
                .with_notes("libcurl 8.4.0"),
        );

    }

    fn populate_builtins_windows_native(&mut self) {
        // ── Boost ────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("boost", "1.81.0", Arch::Any, Platform::Any)
                .with_symbol("boost::filesystem")
                .with_symbol("boost::asio")
                .with_function(
                    "_ZN5boost10filesystem6detail10status_apiERKNS0_4pathEPNS_6system10error_codeE",
                )
                .with_notes("Boost 1.81 (Linux mangled symbols)"),
        );
        self.add(
            LibrarySignature::new("boost", "1.83.0", Arch::Any, Platform::Any)
                .with_symbol("boost::filesystem")
                .with_function("boost::filesystem::directory_iterator")
                .with_notes("Boost 1.83"),
        );
        self.add(
            LibrarySignature::new("boost.asio", "1.83.0", Arch::Any, Platform::Any)
                .with_symbol("boost::asio::io_context")
                .with_function("boost::asio::detail::scheduler::run")
                .with_notes("Boost.Asio 1.83"),
        );

        // ── Qt ───────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("qt", "5.15.11", Arch::Any, Platform::Any)
                .with_function("_ZN7QString5clearEv")
                .with_function("_ZN10QByteArray5clearEv")
                .with_string("Qt 5.15.11")
                .with_notes("Qt5 LTS"),
        );
        self.add(
            LibrarySignature::new("qt", "6.4.3", Arch::Any, Platform::Any)
                .with_function("_ZN7QString5clearEv")
                .with_string("Qt 6.4.3")
                .with_notes("Qt6"),
        );
        self.add(
            LibrarySignature::new("qt", "6.6.1", Arch::Any, Platform::Any)
                .with_function("_ZN7QString5clearEv")
                .with_string("Qt 6.6.1")
                .with_notes("Qt 6.6.1"),
        );

        // ── MFC ──────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("mfc", "14.0", Arch::X86, Platform::Windows)
                .with_function("?CreateEx@CWnd@@QAEHKKPBGHHHPAU__SECURITY_ATTRIBUTES@@PAX@Z")
                .with_function("AfxGetApp")
                .with_string("MFC")
                .with_notes("MFC 14.0 (VS 2015)"),
        );
        self.add(
            LibrarySignature::new("mfc", "14.3", Arch::X86_64, Platform::Windows)
                .with_function("AfxGetApp")
                .with_function("AfxMessageBox")
                .with_notes("MFC 14.3 (VS 2022)"),
        );

        // ── ATL ──────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("atl", "14.0", Arch::X86, Platform::Windows)
                .with_function("?GetWndExStyle@CWindow@@QBEKXZ")
                .with_symbol("ATL::")
                .with_notes("ATL 14.0"),
        );
        self.add(
            LibrarySignature::new("atl", "14.3", Arch::X86_64, Platform::Windows)
                .with_symbol("ATL::CComObject")
                .with_function("AtlComModuleRegisterServer")
                .with_notes("ATL 14.3"),
        );

        // ── STL / MSVC CRT ───────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("msvcrt", "14.0", Arch::X86_64, Platform::Windows)
                .with_function("__std_exception_destroy")
                .with_function("__acrt_iob_func")
                .with_symbol("VCRUNTIME140")
                .with_notes("MSVC 2015 runtime"),
        );
        self.add(
            LibrarySignature::new("msvcrt", "14.3", Arch::X86_64, Platform::Windows)
                .with_function("__std_exception_destroy")
                .with_symbol("VCRUNTIME140")
                .with_notes("MSVC 2022 runtime"),
        );
        self.add(
            LibrarySignature::new("ucrt", "10.0", Arch::X86_64, Platform::Windows)
                .with_function("_set_thread_local_invalid_parameter_handler")
                .with_function("__acrt_iob_func")
                .with_symbol("ucrtbase")
                .with_notes("Universal CRT"),
        );

    }

    fn populate_builtins_system_libs(&mut self) {
        // ── glibc ────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("glibc", "2.35", Arch::X86_64, Platform::Linux)
                .with_function("__libc_start_main")
                .with_function("__cxa_finalize")
                .with_string("GLIBC_2.35")
                .with_notes("GNU C Library 2.35 (Ubuntu 22.04)"),
        );
        self.add(
            LibrarySignature::new("glibc", "2.38", Arch::X86_64, Platform::Linux)
                .with_function("__libc_start_main")
                .with_string("GLIBC_2.38")
                .with_notes("GNU C Library 2.38"),
        );

        // ── musl libc ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("musl", "1.2.4", Arch::X86_64, Platform::Linux)
                .with_function("__init_libc")
                .with_string("musl libc")
                .with_notes("musl libc 1.2.4"),
        );

        // ── libstdc++ ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libstdc++", "12.3", Arch::X86_64, Platform::Linux)
                .with_symbol("GLIBCXX_3.4.30")
                .with_function("_ZdlPvm")
                .with_notes("libstdc++ GCC 12"),
        );

    }

    fn populate_builtins_misc_libs(&mut self) {
        self.populate_builtins_misc_libs_a();
        self.populate_builtins_misc_libs_b();
    }

    fn populate_builtins_misc_libs_a(&mut self) {
        // ── SQLite ───────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("sqlite", "3.42.0", Arch::Any, Platform::Any)
                .with_function("sqlite3_open_v2")
                .with_function("sqlite3_prepare_v2")
                .with_string("3.42.0")
                .with_notes("SQLite 3.42.0"),
        );
        self.add(
            LibrarySignature::new("sqlite", "3.44.0", Arch::Any, Platform::Any)
                .with_function("sqlite3_open_v2")
                .with_string("3.44.0")
                .with_notes("SQLite 3.44.0"),
        );

        // ── protobuf ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("protobuf", "3.21.12", Arch::Any, Platform::Any)
                .with_symbol("google::protobuf")
                .with_function("_ZN6google8protobuf8internal26WireFormatLite")
                .with_notes("protobuf 3.21.x (libprotobuf)"),
        );
        self.add(
            LibrarySignature::new("protobuf", "4.23.3", Arch::Any, Platform::Any)
                .with_symbol("google::protobuf")
                .with_notes("protobuf 4.23.x"),
        );

        // ── OpenCV ──────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("opencv", "4.8.0", Arch::Any, Platform::Any)
                .with_function("_ZN2cv3MatC1ERKNS_5InputArrayE")
                .with_symbol("opencv_core")
                .with_string("OpenCV")
                .with_notes("OpenCV 4.8.0"),
        );

        // ── libressl ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libressl", "3.7.3", Arch::Any, Platform::Any)
                .with_function("TLS_client_method")
                .with_string("LibreSSL")
                .with_notes("LibreSSL 3.7.3"),
        );

        // ── Detours ─────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("detours", "4.0.1", Arch::X86_64, Platform::Windows)
                .with_function("DetourAttach")
                .with_function("DetourDetach")
                .with_function("DetourTransactionBegin")
                .with_notes("Microsoft Detours 4.0.1"),
        );

        // ── mimalloc ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("mimalloc", "2.1.2", Arch::Any, Platform::Any)
                .with_function("mi_malloc")
                .with_function("mi_free")
                .with_function("mi_realloc")
                .with_notes("mimalloc 2.1.2"),
        );

        // ── jemalloc ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("jemalloc", "5.3.0", Arch::Any, Platform::Any)
                .with_function("je_malloc")
                .with_function("je_free")
                .with_string("jemalloc")
                .with_notes("jemalloc 5.3.0"),
        );

        // ── mbedTLS ─────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("mbedtls", "3.4.0", Arch::Any, Platform::Any)
                .with_function("mbedtls_ssl_init")
                .with_function("mbedtls_ssl_handshake")
                .with_function("mbedtls_entropy_init")
                .with_notes("Mbed TLS 3.4.0"),
        );

        // ── WolfSSL ─────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("wolfssl", "5.6.3", Arch::Any, Platform::Any)
                .with_function("wolfSSL_new")
                .with_function("wolfSSL_connect")
                .with_string("wolfSSL")
                .with_notes("wolfSSL 5.6.3"),
        );

    }

    fn populate_builtins_misc_libs_b(&mut self) {
        // ── LZ4 ─────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("lz4", "1.9.4", Arch::Any, Platform::Any)
                .with_function("LZ4_compress_default")
                .with_function("LZ4_decompress_safe")
                .with_notes("LZ4 1.9.4"),
        );

        // ── zstd ────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("zstd", "1.5.5", Arch::Any, Platform::Any)
                .with_function("ZSTD_compress")
                .with_function("ZSTD_decompress")
                .with_string("zstd")
                .with_notes("Zstandard 1.5.5"),
        );

        // ── fmt ─────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("fmtlib", "10.1.1", Arch::Any, Platform::Any)
                .with_symbol("fmt::format")
                .with_function("_ZN3fmt2v106detail15vformat_to_implEv")
                .with_notes("{fmt} 10.1.1"),
        );

        // ── spdlog ──────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("spdlog", "1.12.0", Arch::Any, Platform::Any)
                .with_symbol("spdlog::")
                .with_function("_ZN6spdlog6logger3logENS_5level10level_enumENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE")
                .with_notes("spdlog 1.12.0"),
        );

        // ── yaml-cpp ────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("yaml-cpp", "0.7.0", Arch::Any, Platform::Any)
                .with_symbol("YAML::")
                .with_function("_ZN4YAML4NodeC1Ev")
                .with_notes("yaml-cpp 0.7.0"),
        );

        // ── nlohmann/json ────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("nlohmann-json", "3.11.2", Arch::Any, Platform::Any)
                .with_symbol("nlohmann::")
                .with_string("basic_json")
                .with_notes("nlohmann/json 3.11.2 (header-only, may appear inlined)"),
        );

        // ── Poco ────────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("poco", "1.12.4", Arch::Any, Platform::Any)
                .with_symbol("Poco::")
                .with_function("Poco::Net::HTTPClientSession")
                .with_notes("POCO C++ Libraries 1.12.4"),
        );

        // ── PCRE2 ───────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("pcre2", "10.42", Arch::Any, Platform::Any)
                .with_function("pcre2_compile")
                .with_function("pcre2_match")
                .with_string("PCRE2")
                .with_notes("PCRE2 10.42"),
        );

        // ── libssh2 ─────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libssh2", "1.11.0", Arch::Any, Platform::Any)
                .with_function("libssh2_session_init_ex")
                .with_function("libssh2_channel_open_ex")
                .with_notes("libssh2 1.11.0"),
        );

        // ── libxml2 ─────────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libxml2", "2.11.4", Arch::Any, Platform::Any)
                .with_function("xmlParseDocument")
                .with_function("xmlReadFile")
                .with_string("libxml2")
                .with_notes("libxml2 2.11.4"),
        );

        // ── libarchive ──────────────────────────────────────────────────────
        self.add(
            LibrarySignature::new("libarchive", "3.7.1", Arch::Any, Platform::Any)
                .with_function("archive_read_new")
                .with_function("archive_read_open_filename")
                .with_notes("libarchive 3.7.1"),
        );
    }
}

// ─── LibraryDetector ─────────────────────────────────────────────────────────

/// Detects which library versions are embedded in a binary.
pub struct LibraryDetector {
    db: LibraryDb,
    /// Minimum confidence to report a match.
    pub min_confidence: f64,
}

impl LibraryDetector {
    /// Create a detector with the built-in library database.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            db: LibraryDb::with_builtins(),
            min_confidence: 0.4,
        }
    }

    /// Create a detector with a custom database.
    #[must_use]
    pub const fn with_db(db: LibraryDb) -> Self {
        Self {
            db,
            min_confidence: 0.4,
        }
    }

    /// Detect libraries from a set of function names and strings.
    ///
    /// `function_names` — all known function names in the binary.
    /// `strings` — all printable strings extracted from the binary.
    /// `symbols` — all exported/imported symbol names.
    #[must_use]
    pub fn detect(
        &self,
        function_names: &[String],
        strings: &[String],
        symbols: &[String],
    ) -> Vec<LibraryMatch> {
        let fn_set: std::collections::HashSet<&str> =
            function_names.iter().map(std::string::String::as_str).collect();
        let str_set: std::collections::HashSet<&str> = strings.iter().map(std::string::String::as_str).collect();
        let sym_set: std::collections::HashSet<&str> = symbols.iter().map(std::string::String::as_str).collect();

        let mut matches = Vec::new();

        for sig in &self.db.signatures {
            let mut found_markers: Vec<String> = Vec::new();
            let marker_count = sig.marker_functions.len()
                + sig.marker_strings.len()
                + sig.symbol_patterns.len();
            if marker_count == 0 {
                continue;
            }
            let total = f64::from(u32::try_from(marker_count).unwrap_or(u32::MAX));

            for f in &sig.marker_functions {
                if fn_set.contains(f.as_str()) || fn_set.contains(f.trim_start_matches('_')) {
                    found_markers.push(format!("fn:{f}"));
                }
            }
            for s in &sig.marker_strings {
                if str_set.iter().any(|st| st.contains(s.as_str())) {
                    found_markers.push(format!("str:{s}"));
                }
            }
            for sym in &sig.symbol_patterns {
                if sym_set.iter().any(|s| s.contains(sym.as_str())) {
                    found_markers.push(format!("sym:{sym}"));
                }
            }

            let confidence = f64::from(u32::try_from(found_markers.len()).unwrap_or(u32::MAX)) / total;
            if confidence >= self.min_confidence {
                matches.push(LibraryMatch {
                    name: sig.name.clone(),
                    version: sig.version.clone(),
                    arch: sig.arch.clone(),
                    platform: sig.platform.clone(),
                    confidence,
                    matched_markers: found_markers,
                    notes: sig.notes.clone(),
                });
            }
        }

        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matches
    }

    /// Return the total number of signatures in the database.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.db.len()
    }

    /// Return the database (immutable).
    #[must_use]
    pub const fn db(&self) -> &LibraryDb {
        &self.db
    }

    /// Group a set of [`LibraryMatch`] results by library name, keeping
    /// the highest-confidence entry per name.
    ///
    /// Useful for deduplicating matches from multiple signature variants
    /// (e.g. several OpenSSL versions matching the same binary).
    #[must_use]
    pub fn group_best_by_name(matches: &[LibraryMatch]) -> HashMap<String, LibraryMatch> {
        let mut best: HashMap<String, LibraryMatch> = HashMap::new();
        for m in matches {
            best.entry(m.name.clone())
                .and_modify(|cur| {
                    if m.confidence > cur.confidence {
                        *cur = m.clone();
                    }
                })
                .or_insert_with(|| m.clone());
        }
        best
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_db_with_builtins_non_empty() {
        let db = LibraryDb::with_builtins();
        assert!(db.len() >= 50);
    }

    #[test]
    fn test_library_db_by_name() {
        let db = LibraryDb::with_builtins();
        let sigs = db.by_name("openssl");
        assert!(!sigs.is_empty());
    }

    #[test]
    fn test_library_db_names_sorted() {
        let db = LibraryDb::with_builtins();
        let names = db.library_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_library_db_contains_zlib() {
        let db = LibraryDb::with_builtins();
        assert!(!db.by_name("zlib").is_empty());
    }

    #[test]
    fn test_library_db_contains_libcurl() {
        let db = LibraryDb::with_builtins();
        assert!(!db.by_name("libcurl").is_empty());
    }

    #[test]
    fn test_library_db_contains_sqlite() {
        let db = LibraryDb::with_builtins();
        assert!(!db.by_name("sqlite").is_empty());
    }

    #[test]
    fn test_detector_openssl_detection() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "SSL_CTX_new".to_owned(),
            "SSL_connect".to_owned(),
            "EVP_EncryptInit".to_owned(),
        ];
        let strs = vec!["OpenSSL 1.0.2u  27 Mar 2018".to_owned()];
        let matches = det.detect(&fns, &strs, &[]);
        
        assert!(matches.iter().any(|m| m.name == "openssl"));
    }

    #[test]
    fn test_detector_zlib_detection() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "deflate".to_owned(),
            "inflate".to_owned(),
            "deflateInit_".to_owned(),
        ];
        let strs = vec!["1.2.11".to_owned()];
        let matches = det.detect(&fns, &strs, &[]);
        let zlib: Vec<_> = matches.iter().filter(|m| m.name == "zlib").collect();
        assert!(!zlib.is_empty());
        assert!(zlib[0].confidence > 0.5);
    }

    #[test]
    fn test_detector_no_match_empty_input() {
        let det = LibraryDetector::with_builtins();
        let matches = det.detect(&[], &[], &[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detector_sorted_by_confidence() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "SSL_CTX_new".to_owned(),
            "deflate".to_owned(),
            "curl_easy_init".to_owned(),
        ];
        let matches = det.detect(&fns, &[], &[]);
        for i in 0..matches.len().saturating_sub(1) {
            assert!(matches[i].confidence >= matches[i + 1].confidence);
        }
    }

    #[test]
    fn test_library_match_display() {
        let m = LibraryMatch {
            name: "openssl".to_owned(),
            version: "3.0.8".to_owned(),
            arch: Arch::X86_64,
            platform: Platform::Linux,
            confidence: 0.95,
            matched_markers: vec!["fn:SSL_CTX_new".to_owned()],
            notes: String::new(),
        };
        let s = m.display();
        assert!(s.contains("openssl"));
        assert!(s.contains("3.0.8"));
        assert!(s.contains("95%"));
    }

    #[test]
    fn test_library_signature_builder() {
        let sig = LibrarySignature::new("testlib", "1.0", Arch::X86, Platform::Windows)
            .with_function("TestFunc")
            .with_string("testlib 1.0")
            .with_symbol("testlib::")
            .with_notes("A test library");
        assert_eq!(sig.marker_functions.len(), 1);
        assert_eq!(sig.marker_strings.len(), 1);
        assert_eq!(sig.symbol_patterns.len(), 1);
        assert!(!sig.notes.is_empty());
    }

    #[test]
    fn test_detector_signature_count() {
        let det = LibraryDetector::with_builtins();
        assert!(det.signature_count() >= 50);
    }

    #[test]
    fn test_arch_labels() {
        assert_eq!(Arch::X86.label(), "x86");
        assert_eq!(Arch::X86_64.label(), "x86_64");
        assert_eq!(Arch::Arm64.label(), "ARM64");
    }

    #[test]
    fn test_platform_labels() {
        assert_eq!(Platform::Windows.label(), "Windows");
        assert_eq!(Platform::Linux.label(), "Linux");
        assert_eq!(Platform::MacOs.label(), "macOS");
    }

    #[test]
    fn test_detector_libcurl_by_string() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "curl_easy_init".to_owned(),
            "curl_easy_perform".to_owned(),
            "curl_global_init".to_owned(),
        ];
        let strs = vec!["libcurl/7.88.1".to_owned()];
        let matches = det.detect(&fns, &strs, &[]);
        let curl: Vec<_> = matches.iter().filter(|m| m.name == "libcurl").collect();
        assert!(!curl.is_empty());
        // Should have a high-confidence match for 7.88.1
        assert!(curl.iter().any(|m| m.version == "7.88.1"));
    }

    #[test]
    fn test_library_db_add() {
        let mut db = LibraryDb::empty();
        assert_eq!(db.len(), 0);
        db.add(LibrarySignature::new(
            "mylib",
            "1.0",
            Arch::Any,
            Platform::Any,
        ));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_detector_detours() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "DetourAttach".to_owned(),
            "DetourDetach".to_owned(),
            "DetourTransactionBegin".to_owned(),
        ];
        let matches = det.detect(&fns, &[], &[]);
        assert!(matches.iter().any(|m| m.name == "detours"));
    }

    #[test]
    fn test_detector_lz4() {
        let det = LibraryDetector::with_builtins();
        let fns = vec![
            "LZ4_compress_default".to_owned(),
            "LZ4_decompress_safe".to_owned(),
        ];
        let matches = det.detect(&fns, &[], &[]);
        assert!(matches.iter().any(|m| m.name == "lz4"));
    }
}
