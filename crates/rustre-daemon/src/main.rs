//! `rustre-daemon` binary entry point.
//!
//! Supports both the legacy sync status/graph-smoke commands and the new
//! §35.1 headless HTTP/JSON-RPC server mode launched via `serve`.

use std::env;
use std::process::ExitCode;

use rustre_core::binary_view::KnowledgeGraph;
use rustre_daemon::{Daemon, DaemonConfig, DaemonState, HttpDaemonConfig, run_daemon};

const NAME: &str = "rustre-daemon";
const ABOUT: &str = "RustRE background service";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        [arg] if matches!(arg.as_str(), "-h" | "--help" | "help") => {
            print_help();
            ExitCode::SUCCESS
        }
        [arg] if matches!(arg.as_str(), "-V" | "--version" | "version") => {
            println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [command] if command == "status" => {
            let cfg = DaemonConfig::new();
            if let Ok(d) = Daemon::new(cfg) {
                let state = d.state();
                println!("{NAME}: {state}");
                if state == DaemonState::Running {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            } else {
                println!("{NAME}: unknown");
                ExitCode::from(1)
            }
        }
        [command] if command == "graph-smoke" => {
            let mut graph = KnowledgeGraph::new();
            graph.annotate("daemon.smoke", r#"{"status":"ok"}"#);
            match graph.get_annotation("daemon.smoke") {
                Some(_) if graph.len() == 1 => {
                    println!("{NAME}: graph smoke ok (annotations=1)");
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("{NAME}: graph smoke failed");
                    ExitCode::FAILURE
                }
            }
        }
        // §35.1 — headless server mode.
        // Usage: rustre-daemon serve [--bind-addr 0.0.0.0:7878] [--log-level debug] ...
        // All flags are forwarded to HttpDaemonConfig via clap.
        [command, rest @ ..] if command == "serve" => {
            // Re-inject "serve" arguments into argv so clap sees them.
            // We strip the "serve" verb and parse the remainder as
            // HttpDaemonConfig flags.
            let fake_argv: Vec<String> = std::iter::once(NAME.to_owned())
                .chain(rest.iter().cloned())
                .collect();

            // Use clap's try_parse_from so we can print a friendly error.
            let config = match <HttpDaemonConfig as clap::Parser>::try_parse_from(&fake_argv) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };

            // Build a tokio runtime with the configured worker count.
            let workers = if config.workers == 0 {
                num_cpus()
            } else {
                config.workers
            };

            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .enable_all()
                .build()
                .expect("tokio runtime");

            match rt.block_on(run_daemon(config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{NAME}: daemon error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [unknown, ..] => {
            eprintln!("{NAME}: unknown argument '{unknown}'");
            eprintln!("Try '{NAME} --help' for usage.");
            ExitCode::from(2)
        }
    }
}

/// Return the number of logical CPUs, falling back to 1.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
}

fn print_help() {
    println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
    println!("{ABOUT}");
    println!();
    println!("Usage:");
    println!("  {NAME} [OPTIONS]");
    println!("  {NAME} <COMMAND>");
    println!();
    println!("Options:");
    println!("  -h, --help       Print help");
    println!("  -V, --version    Print version");
    println!();
    println!("Commands:");
    println!("  status           Print daemon status (IPC layer)");
    println!("  graph-smoke      Exercise the in-memory graph backend");
    println!("  serve [FLAGS]    Start the §35.1 headless HTTP/JSON-RPC server");
    println!();
    println!("Serve flags (§35.1):");
    println!("  --bind-addr <ADDR>       HTTP listen address [default: 127.0.0.1:7878]");
    println!("  --mcp-bind <ADDR>        MCP SSE listen address (optional)");
    println!("  --log-level <LEVEL>      trace/debug/info/warn/error [default: info]");
    println!("  --project-dir <DIR>      Auto-open project on start");
    println!("  --max-connections <N>    Max simultaneous connections [default: 16]");
    println!("  --auth-token <TOKEN>     Bearer token for HTTP auth (optional)");
    println!("  --workers <N>            Tokio worker threads (0 = num_cpus)");
}
