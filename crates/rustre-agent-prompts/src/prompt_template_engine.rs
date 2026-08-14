//! Prompt template engine — **rendering layer** with conditionals, loops, and filters.
//!
//! Supports `{{var_name}}` placeholders, `{{#if var}}...{{/if}}` conditionals,
//! `{{#each list}}...{{/each}}` loops, and `{{escape_json var}}` / `upper` /
//! `lower` / `trim` filters.
//!
//! # Distinct from `prompt_templates`
//!
//! `prompt_template_engine` is the **generic rendering engine** — it owns the
//! `TemplateEngine` that parses and evaluates template syntax, a `TemplateLibrary`
//! that tracks per-template render statistics, and JSON-based template loading.
//! It carries no domain-specific prompts.
//!
//! `prompt_templates` is the **content** layer — it owns 10 builtin RE domain
//! templates (malware-analyze, vuln-analyze, binary-diff, …) and a `PromptChain`
//! execution model on top of a simpler `substitute()` function.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    MissingVariable(String),
    UnclosedBlock(String),
    CircularReference(String),
    InvalidJson(String),
    TemplateNotFound(String),
    ParseError(String),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingVariable(v) => write!(f, "missing required variable: {v}"),
            Self::UnclosedBlock(b) => write!(f, "unclosed block: {b}"),
            Self::CircularReference(r) => write!(f, "circular reference: {r}"),
            Self::InvalidJson(s) => write!(f, "invalid JSON: {s}"),
            Self::TemplateNotFound(n) => write!(f, "template not found: {n}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for TemplateError {}

// ─── VarType ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarType {
    Text,
    Number,
    Bool,
    List,
    Json,
}

impl std::fmt::Display for VarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Number => write!(f, "number"),
            Self::Bool => write!(f, "bool"),
            Self::List => write!(f, "list"),
            Self::Json => write!(f, "json"),
        }
    }
}

// ─── TemplateVar ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVar {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default: Option<String>,
    pub var_type: VarType,
}

impl TemplateVar {
    pub fn new(name: impl Into<String>, description: impl Into<String>, var_type: VarType) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            required: true,
            default: None,
            var_type,
        }
    }

    pub fn optional(mut self, default: impl Into<String>) -> Self {
        self.required = false;
        self.default = Some(default.into());
        self
    }
}

// ─── TemplateExample ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateExample {
    pub input_vars: HashMap<String, String>,
    pub expected_output: String,
}

// ─── Template ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub content: String,
    pub variables: Vec<TemplateVar>,
    pub examples: Vec<TemplateExample>,
    pub description: String,
    pub category: String,
}

impl Template {
    pub fn new(id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            content: content.into(),
            variables: Vec::new(),
            examples: Vec::new(),
            description: String::new(),
            category: String::from("general"),
        }
    }

    pub fn with_var(mut self, var: TemplateVar) -> Self {
        self.variables.push(var);
        self
    }

    pub fn with_example(mut self, example: TemplateExample) -> Self {
        self.examples.push(example);
        self
    }
}

// ─── TemplateStats ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateStats {
    pub variable_count: u32,
    pub example_count: u32,
    pub render_count: u32,
    pub avg_render_time_us: f64,
    total_render_time_us: u64,
}

impl TemplateStats {
    pub fn record_render(&mut self, duration_us: u64) {
        self.render_count += 1;
        self.total_render_time_us += duration_us;
        self.avg_render_time_us = self.total_render_time_us as f64 / self.render_count as f64;
    }
}

// ─── TemplateEngine ──────────────────────────────────────────────────────────

/// Core template rendering engine.
#[derive(Debug, Clone, Copy)]
pub struct TemplateEngine {
    strict_mode: bool,
    max_depth: usize,
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self { strict_mode: true, max_depth: 32 }
    }
}

impl TemplateEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lenient(mut self) -> Self {
        self.strict_mode = false;
        self
    }

    /// Render a template with the given variable bindings.
    pub fn render(
        &self,
        template: &Template,
        vars: &HashMap<String, String>,
    ) -> Result<String, TemplateError> {
        // Resolve all variables (apply defaults for missing optional ones)
        let mut resolved: HashMap<String, String> = HashMap::new();
        for var in &template.variables {
            if let Some(val) = vars.get(&var.name) {
                resolved.insert(var.name.clone(), val.clone());
            } else if let Some(def) = &var.default {
                resolved.insert(var.name.clone(), def.clone());
            } else if var.required && self.strict_mode {
                return Err(TemplateError::MissingVariable(var.name.clone()));
            } else {
                resolved.insert(var.name.clone(), String::new());
            }
        }
        // Also accept ad-hoc variables not declared in template.variables
        for (k, v) in vars {
            resolved.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self.render_str(&template.content, &resolved, 0)
    }

    /// Render a raw template string (used recursively for nested blocks).
    fn render_str(
        &self,
        content: &str,
        vars: &HashMap<String, String>,
        depth: usize,
    ) -> Result<String, TemplateError> {
        if depth > self.max_depth {
            return Err(TemplateError::ParseError("max recursion depth exceeded".into()));
        }
        // Process #each blocks first (they can contain #if)
        let content = self.process_each_blocks(content, vars, depth)?;
        // Process #if blocks
        let content = self.process_if_blocks(&content, vars, depth)?;
        // Substitute remaining {{var}} and {{filter var}} placeholders
        let content = self.substitute_vars(&content, vars)?;
        Ok(content)
    }

    fn process_each_blocks(
        &self,
        content: &str,
        vars: &HashMap<String, String>,
        depth: usize,
    ) -> Result<String, TemplateError> {
        let mut result = String::with_capacity(content.len());
        let mut rest = content;
        loop {
            if let Some(start) = rest.find("{{#each ") {
                result.push_str(&rest[..start]);
                let after_tag = &rest[start + 8..];
                // find end of opening tag
                let tag_end = after_tag
                    .find("}}")
                    .ok_or_else(|| TemplateError::UnclosedBlock("each".into()))?;
                let var_name = after_tag[..tag_end].trim();
                let body_start = tag_end + 2;
                let body_and_rest = &after_tag[body_start..];
                let close_tag = format!("{{{{/each}}}}");
                let body_end = body_and_rest
                    .find(close_tag.as_str())
                    .ok_or_else(|| TemplateError::UnclosedBlock(format!("each {var_name}")))?;
                let body = &body_and_rest[..body_end];
                rest = &body_and_rest[body_end + close_tag.len()..];

                // Look up the list variable (comma-separated values)
                let list_val = vars.get(var_name).map(String::as_str).unwrap_or("");
                if !list_val.is_empty() {
                    for item in list_val.split(',') {
                        let item = item.trim();
                        let mut item_vars = vars.clone();
                        item_vars.insert("this".to_string(), item.to_string());
                        let rendered = self.render_str(body, &item_vars, depth + 1)?;
                        result.push_str(&rendered);
                    }
                }
            } else {
                result.push_str(rest);
                break;
            }
        }
        Ok(result)
    }

    fn process_if_blocks(
        &self,
        content: &str,
        vars: &HashMap<String, String>,
        depth: usize,
    ) -> Result<String, TemplateError> {
        let mut result = String::with_capacity(content.len());
        let mut rest = content;
        loop {
            if let Some(start) = rest.find("{{#if ") {
                result.push_str(&rest[..start]);
                let after_tag = &rest[start + 6..];
                let tag_end = after_tag
                    .find("}}")
                    .ok_or_else(|| TemplateError::UnclosedBlock("if".into()))?;
                let var_name = after_tag[..tag_end].trim();
                let body_start = tag_end + 2;
                let body_and_rest = &after_tag[body_start..];
                let close_tag = "{{/if}}";
                let body_end = body_and_rest
                    .find(close_tag)
                    .ok_or_else(|| TemplateError::UnclosedBlock(format!("if {var_name}")))?;
                let body = &body_and_rest[..body_end];
                rest = &body_and_rest[body_end + close_tag.len()..];

                let condition = self.eval_condition(var_name, vars);
                // Check for {{else}} inside body
                if let Some(else_pos) = body.find("{{else}}") {
                    let true_branch = &body[..else_pos];
                    let false_branch = &body[else_pos + 8..];
                    if condition {
                        result.push_str(&self.render_str(true_branch, vars, depth + 1)?);
                    } else {
                        result.push_str(&self.render_str(false_branch, vars, depth + 1)?);
                    }
                } else if condition {
                    result.push_str(&self.render_str(body, vars, depth + 1)?);
                }
            } else {
                result.push_str(rest);
                break;
            }
        }
        Ok(result)
    }

    fn eval_condition(&self, var_name: &str, vars: &HashMap<String, String>) -> bool {
        match vars.get(var_name) {
            None => false,
            Some(v) => {
                let v = v.trim();
                !v.is_empty() && v != "false" && v != "0" && v != "no"
            }
        }
    }

    fn substitute_vars(
        &self,
        content: &str,
        vars: &HashMap<String, String>,
    ) -> Result<String, TemplateError> {
        let mut result = String::with_capacity(content.len());
        let mut rest = content;
        loop {
            if let Some(start) = rest.find("{{") {
                result.push_str(&rest[..start]);
                let after = &rest[start + 2..];
                let end = after
                    .find("}}")
                    .ok_or_else(|| TemplateError::ParseError("unclosed {{".into()))?;
                let expr = after[..end].trim();
                rest = &after[end + 2..];

                if let Some(filter_var) = expr.strip_prefix("escape_json ") {
                    let val = vars.get(filter_var).map(String::as_str).unwrap_or("");
                    result.push_str(&Self::escape_json(val));
                } else if let Some(filter_var) = expr.strip_prefix("upper ") {
                    let val = vars.get(filter_var).map(String::as_str).unwrap_or("");
                    result.push_str(&val.to_uppercase());
                } else if let Some(filter_var) = expr.strip_prefix("lower ") {
                    let val = vars.get(filter_var).map(String::as_str).unwrap_or("");
                    result.push_str(&val.to_lowercase());
                } else if let Some(filter_var) = expr.strip_prefix("trim ") {
                    let val = vars.get(filter_var).map(String::as_str).unwrap_or("");
                    result.push_str(val.trim());
                } else {
                    // Plain variable
                    match vars.get(expr) {
                        Some(val) => result.push_str(val),
                        None if self.strict_mode => {
                            return Err(TemplateError::MissingVariable(expr.to_string()))
                        }
                        None => {} // lenient: leave empty
                    }
                }
            } else {
                result.push_str(rest);
                break;
            }
        }
        Ok(result)
    }

    fn escape_json(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c => out.push(c),
            }
        }
        out
    }
}

// ─── TemplateLibrary ─────────────────────────────────────────────────────────

/// A registry of named templates organised by category.
#[derive(Debug, Default)]
pub struct TemplateLibrary {
    pub templates: HashMap<String, Template>,
    pub categories: HashMap<String, Vec<String>>,
    pub stats: HashMap<String, TemplateStats>,
    engine: TemplateEngine,
}

impl TemplateLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a template. Returns an error if an ID collision occurs.
    pub fn register(&mut self, template: Template) -> Result<(), TemplateError> {
        let id = template.id.clone();
        let cat = template.category.clone();
        let vars_count = template.variables.len() as u32;
        let examples_count = template.examples.len() as u32;
        self.templates.insert(id.clone(), template);
        self.categories.entry(cat).or_default().push(id.clone());
        let stats = self.stats.entry(id).or_default();
        stats.variable_count = vars_count;
        stats.example_count = examples_count;
        Ok(())
    }

    /// Render a template by ID with the given variables.
    pub fn render(
        &mut self,
        id: &str,
        vars: &HashMap<String, String>,
    ) -> Result<String, TemplateError> {
        let template = self
            .templates
            .get(id)
            .ok_or_else(|| TemplateError::TemplateNotFound(id.to_string()))?
            .clone();

        let start = Instant::now();
        let result = self.engine.render(&template, vars)?;
        let elapsed_us = start.elapsed().as_micros() as u64;

        let stats = self.stats.entry(id.to_string()).or_default();
        stats.record_render(elapsed_us);

        Ok(result)
    }

    /// Load templates from a JSON array string.
    pub fn load_from_json(&mut self, json: &str) -> Result<usize, TemplateError> {
        let templates: Vec<Template> = serde_json::from_str(json)
            .map_err(|e| TemplateError::InvalidJson(e.to_string()))?;
        let count = templates.len();
        for t in templates {
            self.register(t)?;
        }
        Ok(count)
    }

    /// Validate a template: check required vars present in content, detect
    /// unclosed blocks, and check for circular `{{include}}` references.
    pub fn validate_template(&self, template: &Template) -> Vec<TemplateError> {
        let mut errors = Vec::new();

        // Check unclosed #if blocks
        let if_opens = template.content.matches("{{#if ").count();
        let if_closes = template.content.matches("{{/if}}").count();
        if if_opens != if_closes {
            errors.push(TemplateError::UnclosedBlock(format!(
                "#if: {if_opens} open vs {if_closes} close"
            )));
        }

        // Check unclosed #each blocks
        let each_opens = template.content.matches("{{#each ").count();
        let each_closes = template.content.matches("{{/each}}").count();
        if each_opens != each_closes {
            errors.push(TemplateError::UnclosedBlock(format!(
                "#each: {each_opens} open vs {each_closes} close"
            )));
        }

        // Check that all required variables appear in content
        for var in &template.variables {
            if var.required {
                let placeholder = format!("{{{{{}}}}}", var.name);
                let in_if = format!("{{{{#if {}}}}}", var.name);
                let in_each = format!("{{{{#each {}}}}}", var.name);
                if !template.content.contains(&placeholder)
                    && !template.content.contains(&in_if)
                    && !template.content.contains(&in_each)
                {
                    errors.push(TemplateError::MissingVariable(format!(
                        "required var '{}' not referenced in template",
                        var.name
                    )));
                }
            }
        }

        // Check for circular {{include X}} references (simple self-reference check)
        let self_include = format!("{{{{include {}}}}}", template.id);
        if template.content.contains(&self_include) {
            errors.push(TemplateError::CircularReference(template.id.clone()));
        }

        errors
    }

    /// Return all template IDs in a given category.
    pub fn by_category(&self, category: &str) -> Vec<&str> {
        self.categories
            .get(category)
            .map(|ids| ids.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn get_stats(&self, id: &str) -> Option<&TemplateStats> {
        self.stats.get(id)
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    pub fn category_names(&self) -> Vec<&str> {
        self.categories.keys().map(String::as_str).collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn engine() -> TemplateEngine {
        TemplateEngine::new()
    }

    fn tmpl(id: &str, content: &str) -> Template {
        Template::new(id, content)
    }

    // 1. Simple substitution
    #[test]
    fn test_simple_substitution() {
        let t = tmpl("t1", "Hello {{name}}!");
        let vars = make_vars(&[("name", "world")]);
        let out = engine().render(&t, &vars).unwrap();
        assert_eq!(out, "Hello world!");
    }

    // 2. Multiple variables
    #[test]
    fn test_multiple_vars() {
        let t = tmpl("t2", "{{a}} + {{b}} = {{c}}");
        let vars = make_vars(&[("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "1 + 2 = 3");
    }

    // 3. Missing required var returns error in strict mode
    #[test]
    fn test_missing_required_var() {
        let t = tmpl("t3", "Hello {{name}}!");
        let vars = HashMap::new();
        let err = engine().render(&t, &vars).unwrap_err();
        assert!(matches!(err, TemplateError::MissingVariable(_)));
    }

    // 4. Lenient mode: missing var renders empty
    #[test]
    fn test_lenient_missing_var() {
        let t = tmpl("t4", "Hello {{name}}!");
        let vars = HashMap::new();
        let out = TemplateEngine::new().lenient().render(&t, &vars).unwrap();
        assert_eq!(out, "Hello !");
    }

    // 5. Default value applied for optional var
    #[test]
    fn test_default_value() {
        let mut t = tmpl("t5", "arch={{arch}}");
        t.variables.push(
            TemplateVar::new("arch", "architecture", VarType::Text).optional("x86_64"),
        );
        let vars = HashMap::new();
        let out = engine().render(&t, &vars).unwrap();
        assert_eq!(out, "arch=x86_64");
    }

    // 6. Conditional true branch
    #[test]
    fn test_if_true() {
        let t = tmpl("t6", "{{#if show}}visible{{/if}}");
        let vars = make_vars(&[("show", "true")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "visible");
    }

    // 7. Conditional false branch (omitted)
    #[test]
    fn test_if_false() {
        let t = tmpl("t7", "{{#if show}}visible{{/if}}");
        let vars = make_vars(&[("show", "false")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "");
    }

    // 8. If/else
    #[test]
    fn test_if_else() {
        let t = tmpl("t8", "{{#if flag}}yes{{else}}no{{/if}}");
        let yes = engine().render(&t, &make_vars(&[("flag", "1")])).unwrap();
        let no = engine().render(&t, &make_vars(&[("flag", "0")])).unwrap();
        assert_eq!(yes, "yes");
        assert_eq!(no, "no");
    }

    // 9. Each loop
    #[test]
    fn test_each_loop() {
        let t = tmpl("t9", "{{#each items}}[{{this}}]{{/each}}");
        let vars = make_vars(&[("items", "a,b,c")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "[a][b][c]");
    }

    // 10. Empty each loop produces nothing
    #[test]
    fn test_each_empty() {
        let t = tmpl("t10", "{{#each items}}x{{/each}}");
        let vars = make_vars(&[("items", "")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "");
    }

    // 11. escape_json filter
    #[test]
    fn test_escape_json_filter() {
        let t = tmpl("t11", r#"{"msg":"{{escape_json text}}"}"#);
        let vars = make_vars(&[("text", "line1\nline2")]);
        let out = engine().render(&t, &vars).unwrap();
        assert_eq!(out, r#"{"msg":"line1\nline2"}"#);
    }

    // 12. upper filter
    #[test]
    fn test_upper_filter() {
        let t = tmpl("t12", "{{upper word}}");
        let vars = make_vars(&[("word", "hello")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "HELLO");
    }

    // 13. lower filter
    #[test]
    fn test_lower_filter() {
        let t = tmpl("t13", "{{lower word}}");
        let vars = make_vars(&[("word", "WORLD")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "world");
    }

    // 14. Validate detects unclosed #if
    #[test]
    fn test_validate_unclosed_if() {
        let lib = TemplateLibrary::new();
        let t = tmpl("t14", "{{#if x}}oops");
        let errors = lib.validate_template(&t);
        assert!(errors.iter().any(|e| matches!(e, TemplateError::UnclosedBlock(_))));
    }

    // 15. Validate detects missing required variable reference
    #[test]
    fn test_validate_missing_required_var_ref() {
        let lib = TemplateLibrary::new();
        let mut t = tmpl("t15", "no vars here");
        t.variables.push(TemplateVar::new("critical", "must appear", VarType::Text));
        let errors = lib.validate_template(&t);
        assert!(errors.iter().any(|e| matches!(e, TemplateError::MissingVariable(_))));
    }

    // 16. Library load_from_json round-trip
    #[test]
    fn test_library_load_json() {
        let mut lib = TemplateLibrary::new();
        let json = r#"[{"id":"j1","content":"hi {{x}}","variables":[],"examples":[],"description":"","category":"test"}]"#;
        let count = lib.load_from_json(json).unwrap();
        assert_eq!(count, 1);
        assert!(lib.templates.contains_key("j1"));
    }

    // 17. Library render tracks stats
    #[test]
    fn test_library_stats_tracking() {
        let mut lib = TemplateLibrary::new();
        lib.register(tmpl("s1", "{{v}}")).unwrap();
        lib.render("s1", &make_vars(&[("v", "x")])).unwrap();
        lib.render("s1", &make_vars(&[("v", "y")])).unwrap();
        assert_eq!(lib.get_stats("s1").unwrap().render_count, 2);
    }

    // 18. by_category returns correct IDs
    #[test]
    fn test_by_category() {
        let mut lib = TemplateLibrary::new();
        let mut t = tmpl("cat_t", "x");
        t.category = "malware".into();
        lib.register(t).unwrap();
        let ids = lib.by_category("malware");
        assert!(ids.contains(&"cat_t"));
    }

    // 19. Validate circular self-include
    #[test]
    fn test_validate_circular() {
        let lib = TemplateLibrary::new();
        let t = tmpl("recursive", "{{include recursive}}");
        let errors = lib.validate_template(&t);
        assert!(errors.iter().any(|e| matches!(e, TemplateError::CircularReference(_))));
    }

    // 20. Nested if inside each
    #[test]
    fn test_nested_if_in_each() {
        let t = tmpl("t20", "{{#each items}}{{#if this}}[{{this}}]{{/if}}{{/each}}");
        let vars = make_vars(&[("items", "a,,b")]);
        assert_eq!(engine().render(&t, &vars).unwrap(), "[a][b]");
    }
}
