//! hello_debug — basic tutorial: attach, backtrace, kill.
//!
//! This example demonstrates the minimal workflow for a scripted debug session:
//!
//! 1. Launch (or attach to) a target process via the [`Debugger`] trait.
//! 2. Wait for the initial stop.
//! 3. Read the backtrace of the stopped thread.
//! 4. Kill / detach the process.
//!
//! # Running
//! ```text
//! cargo run --example hello_debug --release
//! ```
//!
//! On Windows the example uses [`WindowsDebugger`]; on Linux it uses
//! [`LinuxDebugger`].  On any other host it exits with an error naming the
//! host: it used to fall back to `MockScriptContext` and print a fabricated
//! register read, which taught the reader that the example "works" on a
//! platform where no debugging happened at all.
//!
//! # Errors
//! The example prints a human-readable error and exits with code 1 on any
//! failure (binary not found, permission denied, OS not supported).

fn main() {
    #[cfg(any(windows, target_os = "linux"))]
    run_live().unwrap_or_else(|e| {
        eprintln!("hello_debug: {e}");
        std::process::exit(1);
    });

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        eprintln!(
            "hello_debug: no live debugger backend exists for target_os = {:?}              (only windows and linux are implemented). Refusing to print a              fabricated session — there is nothing to attach to.",
            std::env::consts::OS
        );
        std::process::exit(1);
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn run_live() -> anyhow::Result<()> {
    use rustre_debug::scripting_api::block_on;
    use rustre_debug::{Debugger, LaunchOptions};

    // Build the OS-appropriate backend.
    #[cfg(windows)]
    let dbg: Box<dyn Debugger> =
        Box::new(rustre_debug::windows_debugger::WindowsDebugger::new());
    #[cfg(target_os = "linux")]
    let dbg: Box<dyn Debugger> =
        Box::new(rustre_debug::linux_debugger::LinuxDebugger::new());

    // We use the system `hostname` binary (always present) as the target.
    // Override via the RUSTRE_HELLO_TARGET env var.
    let target = std::env::var("RUSTRE_HELLO_TARGET")
        .unwrap_or_else(|_| {
            #[cfg(windows)] { "C:\\Windows\\System32\\hostname.exe".to_string() }
            #[cfg(not(windows))] { "/bin/hostname".to_string() }
        });

    println!("[hello_debug] launching {target}");
    let mut opts = LaunchOptions::new(&target);
    opts.args = vec![];

    let pid = block_on(dbg.launch(opts))
        .map_err(|e| anyhow::anyhow!("launch failed: {e}"))?;
    println!("[hello_debug] pid = {pid}");

    // Run to first stop (initial system breakpoint / entry-point trap).
    let ev = block_on(dbg.continue_execution())
        .map_err(|e| anyhow::anyhow!("continue: {e}"))?;
    println!("[hello_debug] stopped: {:?}", ev.reason);

    let tid = ev.tid;

    // Print backtrace.
    let frames = block_on(dbg.backtrace(tid))
        .unwrap_or_default();
    println!("[hello_debug] backtrace ({} frames):", frames.len());
    for (i, f) in frames.iter().enumerate() {
        println!(
            "  #{i:02} pc={:#018x} name={}",
            f.pc.as_u64(),
            f.function_name.as_deref().unwrap_or("?")
        );
    }

    // Kill the target.
    block_on(dbg.kill())
        .map_err(|e| anyhow::anyhow!("kill: {e}"))?;
    println!("[hello_debug] process killed — done");
    Ok(())
}

