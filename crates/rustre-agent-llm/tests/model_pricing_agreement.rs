//! Cross-module agreement for per-model pricing.
//!
//! The crate reconstructs the price of the same model in three independent
//! places, in two different units:
//!
//! * `streaming::ModelCostRates`      — USD per 1 000 tokens
//! * `model_selector::ModelProfile`   — USD per 1 000 tokens
//! * `anthropic_client::ModelPricing` — USD per 1 000 000 tokens
//!
//! Two reconstructions of the same model id cannot both be right. These tests
//! do not copy expected prices: they normalise every source to USD/MTok and
//! require the sources to agree wherever they describe the same model.

use rustre_agent_llm::anthropic_client::ModelPricing;
use rustre_agent_llm::model_selector::ModelSelector;
use rustre_agent_llm::streaming::ModelCostRates;

/// USD per million tokens, from a per-1k rate.
fn per_mtok(per_1k: f64) -> f64 {
    per_1k * 1000.0
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// Every `ModelCostRates` constructor the crate exposes, with its model id
/// carried by the value itself rather than repeated here.
fn streaming_rates() -> Vec<ModelCostRates> {
    vec![
        ModelCostRates::gpt4o(),
        ModelCostRates::gpt4(),
        ModelCostRates::claude_opus(),
        ModelCostRates::claude_sonnet(),
        ModelCostRates::claude_haiku(),
    ]
}

#[test]
fn streaming_and_selector_agree_on_shared_model_ids() {
    let selector = ModelSelector::new();

    let mut compared: Vec<String> = Vec::new();
    for rates in streaming_rates() {
        let Some(profile) = selector.find_by_id(&rates.model) else {
            continue; // model only known to one source — nothing to cross-check
        };

        assert!(
            close(
                per_mtok(rates.prompt_cost_per_1k),
                per_mtok(profile.cost_per_1k_input_tokens)
            ),
            "input price disagrees for `{}`: streaming ${}/MTok vs selector ${}/MTok",
            rates.model,
            per_mtok(rates.prompt_cost_per_1k),
            per_mtok(profile.cost_per_1k_input_tokens),
        );
        assert!(
            close(
                per_mtok(rates.completion_cost_per_1k),
                per_mtok(profile.cost_per_1k_output_tokens)
            ),
            "output price disagrees for `{}`: streaming ${}/MTok vs selector ${}/MTok",
            rates.model,
            per_mtok(rates.completion_cost_per_1k),
            per_mtok(profile.cost_per_1k_output_tokens),
        );
        compared.push(rates.model.clone());
    }

    // Anti-vacuity: the loop must actually have cross-checked something. If the
    // id strings ever drift apart the overlap collapses to zero and every
    // assertion above is skipped — that must fail loudly, not pass silently.
    compared.sort();
    assert_eq!(
        compared,
        vec!["claude-haiku-3-5".to_string(), "gpt-4o".to_string()],
        "the set of models known to BOTH sources changed; re-check the overlap \
         instead of letting the cross-check quietly become vacuous"
    );
}

#[test]
fn anthropic_client_and_streaming_agree_on_haiku() {
    // `ModelPricing::claude_haiku_35` and `ModelCostRates::claude_haiku` both
    // describe claude-haiku-3-5, in different units.
    let client = ModelPricing::claude_haiku_35();
    let stream = ModelCostRates::claude_haiku();

    assert_eq!(
        stream.model, "claude-haiku-3-5",
        "premise: the streaming constructor still describes claude-haiku-3-5"
    );
    assert!(
        close(client.input_per_mtok, per_mtok(stream.prompt_cost_per_1k)),
        "haiku input price disagrees: anthropic_client ${}/MTok vs streaming ${}/MTok",
        client.input_per_mtok,
        per_mtok(stream.prompt_cost_per_1k),
    );
    assert!(
        close(client.output_per_mtok, per_mtok(stream.completion_cost_per_1k)),
        "haiku output price disagrees: anthropic_client ${}/MTok vs streaming ${}/MTok",
        client.output_per_mtok,
        per_mtok(stream.completion_cost_per_1k),
    );
}

#[test]
fn anthropic_client_and_selector_agree_on_haiku() {
    let selector = ModelSelector::new();
    let profile = selector
        .find_by_id("claude-haiku-3-5")
        .expect("premise: the selector catalogue still contains claude-haiku-3-5");
    let client = ModelPricing::claude_haiku_35();

    assert!(
        close(
            client.input_per_mtok,
            per_mtok(profile.cost_per_1k_input_tokens)
        ),
        "haiku input price disagrees: anthropic_client ${}/MTok vs selector ${}/MTok",
        client.input_per_mtok,
        per_mtok(profile.cost_per_1k_input_tokens),
    );
    assert!(
        close(
            client.output_per_mtok,
            per_mtok(profile.cost_per_1k_output_tokens)
        ),
        "haiku output price disagrees: anthropic_client ${}/MTok vs selector ${}/MTok",
        client.output_per_mtok,
        per_mtok(profile.cost_per_1k_output_tokens),
    );
}

#[test]
fn output_price_exceeds_input_price_for_every_known_rate() {
    // Derived property, not a copied table: every provider in this catalogue
    // charges more for generated tokens than for prompt tokens. A constructor
    // that silently swapped its two arguments would break this.
    let rates = streaming_rates();
    assert!(rates.len() >= 5, "anti-vacuity: expected the full rate catalogue");
    for r in rates {
        assert!(
            r.completion_cost_per_1k > r.prompt_cost_per_1k,
            "`{}` prices output (${}) at or below input (${}) per 1k — arguments swapped?",
            r.model,
            r.completion_cost_per_1k,
            r.prompt_cost_per_1k,
        );
    }
}
