//! `rustre-cli` binary entry point.

use std::env;
use std::process::ExitCode;

use rustre_cli::{Cli, CliError, SubCommand};

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();

    let cli = match Cli::from_argv(argv) {
        Ok(c) => c,
        Err(CliError::UnknownCommand(s)) => {
            eprintln!("rustre-cli: unknown command '{s}'");
            eprintln!("Try 'rustre-cli --help' for usage.");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("rustre-cli: {e}");
            return ExitCode::FAILURE;
        }
    };

    match &cli.args.subcommand {
        SubCommand::Help => {
            cli.print_help();
            ExitCode::SUCCESS
        }
        SubCommand::Version => {
            cli.print_version();
            ExitCode::SUCCESS
        }
        SubCommand::Config => {
            cli.print_config();
            ExitCode::SUCCESS
        }
        SubCommand::GraphSmoke => {
            use rustre_core::binary_view::KnowledgeGraph;
            let mut graph = KnowledgeGraph::new();
            graph.annotate("cli.smoke", r#"{"status":"ok"}"#);
            match graph.get_annotation("cli.smoke") {
                Some(_) if graph.len() == 1 => {
                    println!("rustre-cli: graph smoke ok (annotations=1)");
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("rustre-cli: graph smoke failed");
                    ExitCode::FAILURE
                }
            }
        }
        SubCommand::Interactive => {
            println!("rustre-cli: interactive mode (type 'exit' to quit)");
            ExitCode::SUCCESS
        }
        SubCommand::Analyse { path, .. } => {
            if !cli.args.quiet {
                println!("Analysing: {}", path.display());
            }
            ExitCode::SUCCESS
        }
        SubCommand::Disassemble { path, arch, .. } => {
            if !cli.args.quiet {
                println!("Disassembling: {} (arch={})", path.display(), arch);
            }
            ExitCode::SUCCESS
        }
        SubCommand::Symbols { path } => {
            if !cli.args.quiet {
                println!("Dumping symbols from: {}", path.display());
            }
            ExitCode::SUCCESS
        }
        SubCommand::Export { path, out, format } => {
            if !cli.args.quiet {
                println!(
                    "Exporting {} -> {} (format={})",
                    path.display(),
                    out.display(),
                    format
                );
            }
            ExitCode::SUCCESS
        }
        SubCommand::Import { path } => {
            if !cli.args.quiet {
                println!("Importing: {}", path.display());
            }
            ExitCode::SUCCESS
        }
        SubCommand::Script { path } => {
            if !cli.args.quiet {
                println!("Running script: {}", path.display());
            }
            ExitCode::SUCCESS
        }
    }
}
