//! Package names must not be able to break out of the shell command.
//!
//! Every `pm …` string this crate builds is handed to `adb shell`, which runs it
//! through the device's shell. A package name is not a trusted value: it is
//! passed in by a caller, and it also comes back from `pm list packages` on the
//! device. Wrapping it in single quotes is not enough — a name containing a
//! single quote closes the string and everything after it is a new command.
//!
//! The crate already knew this. `shell::shell_escape` exists precisely for it,
//! its doctest covers `"it's a test"`, and two call sites in `lib.rs` carry the
//! comment *"cmd-injection: single-quote-escape the package name"*. The command
//! builders below did not use it; several did not even quote.

use rustre_adb::package::{build_install_command, build_uninstall_command};
use rustre_adb::shell::shell_escape;

/// Names that try to escape the quoting, and one that tries to split the
/// command with whitespace alone.
const HOSTILE: &[&str] = &[
    "com.evil'; rm -rf /data; echo '",
    "a'",
    "'",
    "com.foo' && reboot #",
    "com.foo; reboot",
    "com.foo && reboot",
    "com.foo | tee /sdcard/x",
    "com.foo $(reboot)",
    "com.foo `reboot`",
    "com.foo\nreboot",
];

/// Split a command the way a POSIX shell would.
///
/// Counting quotes is not a valid model: correct escaping produces spans like
/// `'a'\'''`, which holds an odd number of quotes and is nonetheless exactly one
/// word — `'a'` and `''` are quoted spans and `\'` is an escaped literal. The
/// property that actually matters is what the shell *sees*, so this splits the
/// string into words and reports the first unquoted metacharacter, which is what
/// an injection needs in order to start a second command.
fn sh_words(command: &str) -> Result<Vec<String>, char> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                started = true;
                let mut closed = false;
                for q in chars.by_ref() {
                    if q == '\'' {
                        closed = true;
                        break;
                    }
                    current.push(q);
                }
                if !closed {
                    return Err('\''); // unterminated quote: the shell would not accept it
                }
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    started = true;
                }
            }
            ';' | '|' | '&' | '$' | '`' | '(' | ')' | '<' | '>' | '\n' => return Err(c),
            c if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

/// The command must parse into words, with `name` surviving as one whole word.
fn survives_as_one_word(command: &str, name: &str) -> Result<(), String> {
    let words = sh_words(command)
        .map_err(|c| format!("unquoted metacharacter {c:?} would start a new command"))?;
    match words.last() {
        Some(last) if last == name => Ok(()),
        Some(last) => Err(format!("last word is {last:?}, not the name {name:?}")),
        None => Err("no words at all".to_string()),
    }
}

/// The escape helper itself neutralises every hostile name.
#[test]
fn the_escape_helper_neutralises_hostile_names() {
    for name in HOSTILE {
        let escaped = shell_escape(name);
        assert!(
            escaped.starts_with('\'') && escaped.ends_with('\''),
            "{name:?} escaped to {escaped:?}, which is not a quoted span"
        );
        // The escaped form is exactly one word, and that word is the name.
        if let Err(why) = survives_as_one_word(&format!("echo {escaped}"), name) {
            panic!("{name:?} escaped to {escaped:?}: {why}");
        }
        // The dangerous characters survive as data — escaping must not silently
        // drop them, or the caller acts on a different name than it asked for.
        for ch in name.chars().filter(|c| !"'".contains(*c)) {
            assert!(
                escaped.contains(ch),
                "{name:?} lost the character {ch:?} while being escaped"
            );
        }
    }
}

/// `build_uninstall_command` must not let a name escape the quoting.
#[test]
fn uninstall_command_contains_hostile_names_safely() {
    for name in HOSTILE {
        for keep_data in [false, true] {
            let cmd = build_uninstall_command(name, keep_data);
            if let Err(why) = survives_as_one_word(&cmd, name) {
                panic!(
                    "{name:?} (keep_data={keep_data}) produced {cmd:?}: {why} — the \
                     shell would not receive the name as a single argument"
                );
            }
            assert!(
                cmd.starts_with("pm uninstall"),
                "{name:?} produced {cmd:?}, which is no longer a pm uninstall command"
            );
        }
    }
}

/// The same for the install command's path argument.
#[test]
fn install_command_contains_hostile_paths_safely() {
    for name in HOSTILE {
        let cmd = build_install_command(name, &["-r"]);
        if let Err(why) = survives_as_one_word(&cmd, name) {
            panic!("{name:?} produced {cmd:?}: {why}");
        }
        assert!(cmd.starts_with("pm install"), "{name:?} produced {cmd:?}");
    }
}

/// Ordinary package names still produce the command they always did.
///
/// The fix must be invisible for real input: `shell_escape` on a name with
/// nothing to escape yields the same single-quoted argument the builders wrote
/// by hand before.
#[test]
fn ordinary_names_are_unchanged() {
    assert_eq!(
        build_uninstall_command("com.example.app", false),
        "pm uninstall 'com.example.app'"
    );
    assert_eq!(
        build_uninstall_command("com.example.app", true),
        "pm uninstall -k 'com.example.app'"
    );
    assert_eq!(shell_escape("com.example.app"), "'com.example.app'");
}

/// Guards the tests above: the fixtures must really contain shell metacharacters.
///
/// If every fixture were an ordinary name, balanced quoting would hold without
/// the escaping ever being exercised.
#[test]
fn the_fixtures_are_actually_hostile() {
    let with_quote = HOSTILE.iter().filter(|n| n.contains('\'')).count();
    assert!(
        with_quote >= 3,
        "only {with_quote} fixtures contain a single quote — the escape is barely tested"
    );

    // A fixture only defeats naive single-quoting if it contains a quote: inside
    // a single-quoted POSIX span no other character has meaning. So the two sets
    // must coincide — that is the precise statement of why escaping the quote is
    // the whole job, and it also proves the fixtures reach the vulnerable path.
    let defeats_naive: Vec<&&str> = HOSTILE
        .iter()
        .filter(|n| survives_as_one_word(&format!("pm uninstall '{n}'"), n).is_err())
        .collect();
    let contains_quote: Vec<&&str> = HOSTILE.iter().filter(|n| n.contains('\'')).collect();
    assert_eq!(
        defeats_naive, contains_quote,
        "exactly the quote-bearing fixtures should defeat naive quoting"
    );
    assert!(
        defeats_naive.len() >= 4,
        "only {} fixtures defeat naive quoting; too few to prove the escape works",
        defeats_naive.len()
    );

    // The remaining fixtures are not wasted: they carry metacharacters that need
    // no quote to be dangerous, which is what the previously unquoted builders
    // in `shell_executor` exposed.
    let metachar_only = HOSTILE.len() - defeats_naive.len();
    assert!(
        metachar_only >= 4,
        "only {metachar_only} fixtures test the unquoted case"
    );
}
