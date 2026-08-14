//! Differential agreement between the crate's two fenced-code-block extractors.
//!
//! The crate parses markdown code fences twice, independently:
//!
//! * `response_parser::ResponseParser::parse_markdown_blocks` — backtick and
//!   tilde fences, returns `ContentSection`s
//! * `llm_response_parser::extract_code_blocks` — backtick fences only,
//!   returns `CodeBlock`s
//!
//! Tilde support is a documented, intentional difference, so this file only
//! feeds them BACKTICK-ONLY input — the domain where both claim to work. On
//! that shared domain two independent reconstructions of the same markdown
//! grammar cannot legitimately disagree: whichever one is right, they cannot
//! both be.
//!
//! The expected values are not copied from either implementation; each case
//! states the blocks a markdown reader should see, and both parsers are held
//! to it.

use rustre_agent_llm::llm_response_parser::extract_code_blocks;
use rustre_agent_llm::response_parser::{ContentSection, ResponseParser};

/// The (lang, code) pairs `ResponseParser` extracts, in order.
fn via_response_parser(text: &str) -> Vec<(String, String)> {
    ResponseParser::parse_markdown_blocks(text)
        .into_iter()
        .filter_map(|s| match s {
            ContentSection::CodeBlock { lang, code } => {
                Some((lang, code.trim_end().to_string()))
            }
            _ => None,
        })
        .collect()
}

/// The (lang, code) pairs `extract_code_blocks` extracts, in order.
fn via_llm_response_parser(text: &str) -> Vec<(String, String)> {
    extract_code_blocks(text)
        .into_iter()
        .map(|b| (b.language, b.content.trim_end().to_string()))
        .collect()
}

/// Backtick-only markdown cases, each with the blocks a correct reader sees.
fn shared_domain_cases() -> Vec<(&'static str, &'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        (
            "single block",
            "Here is code:\n```rust\nfn main() {}\n```\nDone.",
            vec![("rust", "fn main() {}")],
        ),
        (
            "two blocks",
            "One:\n```rs\nlet a = 1;\n```\nTwo:\n```py\nx = 2\n```\n",
            vec![("rs", "let a = 1;"), ("py", "x = 2")],
        ),
        (
            "no language tag",
            "```\nplain\n```\n",
            vec![("", "plain")],
        ),
        (
            "fence at very start of text",
            "```sh\nls -la\n```\ntrailing prose\n",
            vec![("sh", "ls -la")],
        ),
        (
            // A line of backticks INSIDE the block is not a closing fence when
            // it is longer than the opening fence: the block runs to the real
            // close. This is the case `find_fence_close` documents as "not more
            // backticks"; its twin has no such guard.
            "nested longer fence inside block",
            "```md\nexample:\n````\nnested\n````\ndone\n```\nafter\n",
            vec![("md", "example:\n````\nnested\n````\ndone")],
        ),
        (
            // The mirror image: a block OPENED with a longer fence, containing
            // an ordinary ``` line. The opening fence length must be preserved,
            // otherwise the leftover backtick is mistaken for a language tag.
            "block opened with a longer fence",
            "````md\ninner:\n```\nx\n```\ndone\n````\nafter\n",
            vec![("md", "inner:\n```\nx\n```\ndone")],
        ),
    ]
}

#[test]
fn both_parsers_agree_with_each_other_on_backtick_only_input() {
    let cases = shared_domain_cases();
    assert!(
        cases.len() >= 6,
        "anti-vacuity: expected the full shared-domain corpus"
    );

    let mut compared = 0usize;
    for (name, text, _) in &cases {
        let a = via_response_parser(text);
        let b = via_llm_response_parser(text);
        assert_eq!(
            a, b,
            "case `{name}`: the two extractors disagree.\n  \
             response_parser     -> {a:?}\n  \
             llm_response_parser -> {b:?}"
        );
        compared += 1;
    }
    assert_eq!(
        compared,
        cases.len(),
        "anti-vacuity: every case must have been compared"
    );
}

#[test]
fn response_parser_matches_the_expected_blocks() {
    let mut total_blocks = 0usize;
    for (name, text, expected) in shared_domain_cases() {
        let got = via_response_parser(text);
        let want: Vec<(String, String)> = expected
            .iter()
            .map(|(l, c)| ((*l).to_string(), (*c).to_string()))
            .collect();
        assert_eq!(got, want, "case `{name}` via response_parser");
        total_blocks += want.len();
    }
    assert!(
        total_blocks >= 6,
        "anti-vacuity: corpus must actually contain blocks, got {total_blocks}"
    );
}

#[test]
fn llm_response_parser_matches_the_expected_blocks() {
    let mut total_blocks = 0usize;
    for (name, text, expected) in shared_domain_cases() {
        let got = via_llm_response_parser(text);
        let want: Vec<(String, String)> = expected
            .iter()
            .map(|(l, c)| ((*l).to_string(), (*c).to_string()))
            .collect();
        assert_eq!(got, want, "case `{name}` via llm_response_parser");
        total_blocks += want.len();
    }
    assert!(
        total_blocks >= 6,
        "anti-vacuity: corpus must actually contain blocks, got {total_blocks}"
    );
}
