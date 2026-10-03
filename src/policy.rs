//! Policy loading, validation, precedence, and evaluation orchestration.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::model::{
    CanonicalRequest, Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION,
    PolicyLayer, Severity,
};
use crate::paths::{self, PathPattern};
use crate::{analyzers, shell};

pub(crate) const POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_RULES: usize = 1_024;
const MAX_PATTERNS_PER_RULE: usize = 256;

const BUILT_INS: &[BuiltInRule] = &[
    BuiltInRule::new(
        "drupal.secret.env",
        "secrets",
        "Reading environment secret files is prohibited.",
        Severity::Critical,
        RuleOperation::Read,
        &["**/.env", "**/.env.*"],
    ),
    BuiltInRule::new(
        "composer.secret.auth_json",
        "secrets",
        "Reading Composer authentication files is prohibited.",
        Severity::Critical,
        RuleOperation::Read,
        &["**/auth.json", "**/composer-auth.json"],
    ),
    BuiltInRule::new(
        "drupal.secret.settings_php",
        "secrets",
        "Reading Drupal settings.php is prohibited.",
        Severity::Critical,
        RuleOperation::Read,
        &["**/sites/*/settings.php", "**/sites/*/settings.local.php"],
    ),
    BuiltInRule::new(
        "filesystem.secret.private_key",
        "secrets",
        "Reading private key material is prohibited.",
        Severity::Critical,
        RuleOperation::Read,
        &["**/*.pem", "**/*.key"],
    ),
    BuiltInRule::new(
        "filesystem.write.core",
        "filesystem",
        "Writing Drupal core is prohibited; use managed dependency workflows.",
        Severity::High,
        RuleOperation::Write,
        &["**/web/core/**", "**/core/**"],
    ),
    BuiltInRule::new(
        "filesystem.write.vendor",
        "filesystem",
        "Writing Composer-managed vendor files is prohibited.",
        Severity::High,
        RuleOperation::Write,
        &["**/vendor/**"],
    ),
    BuiltInRule::new(
        "filesystem.write.contrib_module",
        "filesystem",
        "Writing contributed Drupal modules is prohibited.",
        Severity::High,
        RuleOperation::Write,
        &["**/web/modules/contrib/**"],
    ),
    BuiltInRule::new(
        "filesystem.write.contrib_theme",
        "filesystem",
        "Writing contributed Drupal themes is prohibited.",
        Severity::High,
        RuleOperation::Write,
        &["**/web/themes/contrib/**"],
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyKind {
    Organization,
    Project,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    schema: u16,
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    paths: PathPolicy,
    #[serde(default)]
    sql: SqlPolicy,
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlPolicy {
    #[serde(default)]
    sensitive_tables: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    #[serde(default)]
    unknown_tool: Option<UnknownToolDefault>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UnknownToolDefault {
    Deny,
    Ask,
    Allow,
    AllowUnlessSensitive,
    DenyIfSensitiveOtherwiseAllow,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathPolicy {
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
    #[serde(default)]
    writable: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    description: String,
    effect: DecisionEffect,
    severity: Severity,
    #[serde(default = "default_category")]
    category: String,
    #[serde(rename = "match")]
    matcher: RuleMatch,
}

fn default_category() -> String {
    "policy".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMatch {
    #[serde(default)]
    capabilities: Vec<Capability>,
    paths: Vec<String>,
}

impl Policy {
    pub(crate) fn load(path: &Path, kind: PolicyKind) -> Result<Self, PolicyError> {
        let metadata = fs::metadata(path).map_err(PolicyError::Read)?;
        if metadata.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::Invalid("policy exceeds 1 MiB"));
        }
        let bytes = fs::read(path).map_err(PolicyError::Read)?;
        Self::from_slice(&bytes, kind)
    }

    pub(crate) fn from_slice(input: &[u8], kind: PolicyKind) -> Result<Self, PolicyError> {
        if input.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyError::Invalid("policy exceeds 1 MiB"));
        }
        let policy: Self = serde_json::from_slice(input).map_err(PolicyError::Json)?;
        policy.validate(kind)?;
        Ok(policy)
    }

    fn validate(&self, kind: PolicyKind) -> Result<(), PolicyError> {
        if self.schema != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::Invalid("unsupported policy schema version"));
        }
        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::Invalid("policy contains too many rules"));
        }
        if matches!(kind, PolicyKind::Project) {
            if self.defaults.unknown_tool.is_some() {
                return Err(PolicyError::Weakening(
                    "project policy cannot change default decisions",
                ));
            }
            if !self.paths.writable.is_empty() {
                return Err(PolicyError::Weakening(
                    "project policy cannot add writable paths",
                ));
            }
        }
        validate_patterns(&self.paths.deny_read)?;
        validate_patterns(&self.paths.deny_write)?;
        validate_patterns(&self.paths.writable)?;
        if self.sql.sensitive_tables.len() > MAX_PATTERNS_PER_RULE
            || self.sql.sensitive_tables.iter().any(|table| {
                table.is_empty()
                    || table.len() > 128
                    || !table
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        {
            return Err(PolicyError::Invalid(
                "SQL sensitive table configuration is invalid",
            ));
        }
        let mut ids = HashSet::new();
        for rule in &self.rules {
            validate_rule_id(&rule.id)?;
            if !ids.insert(&rule.id) {
                return Err(PolicyError::Invalid("policy rule IDs must be unique"));
            }
            if rule.description.is_empty() || rule.description.len() > 512 {
                return Err(PolicyError::Invalid("rule description is invalid"));
            }
            if rule.category.is_empty() || rule.category.len() > 64 {
                return Err(PolicyError::Invalid("rule category is invalid"));
            }
            if rule.matcher.paths.is_empty() || rule.matcher.paths.len() > MAX_PATTERNS_PER_RULE {
                return Err(PolicyError::Invalid(
                    "rules require a bounded, non-empty path list",
                ));
            }
            validate_patterns(&rule.matcher.paths)?;
            if matches!(kind, PolicyKind::Project) && !matches!(rule.effect, DecisionEffect::Deny) {
                return Err(PolicyError::Weakening(
                    "project rules may only have deny effect",
                ));
            }
        }
        Ok(())
    }
}

fn validate_patterns(patterns: &[String]) -> Result<(), PolicyError> {
    if patterns.len() > MAX_PATTERNS_PER_RULE {
        return Err(PolicyError::Invalid("too many path patterns"));
    }
    for pattern in patterns {
        PathPattern::compile(pattern).map_err(PolicyError::Path)?;
    }
    Ok(())
}

fn validate_rule_id(id: &str) -> Result<(), PolicyError> {
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(PolicyError::Invalid("rule ID is invalid"));
    }
    Ok(())
}

pub(crate) fn evaluate(
    request: &CanonicalRequest,
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Decision, PolicyError> {
    let sensitive_tables = organization
        .into_iter()
        .chain(project)
        .flat_map(|policy| policy.sql.sensitive_tables.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if matches!(request.tool.capability, Capability::ShellExecute) {
        let command = request
            .facts
            .command
            .as_deref()
            .ok_or(PolicyError::Invalid(
                "shell request is missing its command fact",
            ))?;
        if let Some(decision) = evaluate_shell(command, &request.cwd, &sensitive_tables, 0)? {
            return Ok(decision);
        }
    }
    let normalized_paths = request
        .candidate_paths()
        .into_iter()
        .map(|path| paths::normalize(&request.cwd, path).map_err(PolicyError::Path))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(decision) = evaluate_built_ins(request, &normalized_paths)? {
        return Ok(decision);
    }
    let organization_decision = organization
        .map(|policy| {
            evaluate_policy(
                request,
                &normalized_paths,
                policy,
                PolicyLayer::Organization,
            )
        })
        .transpose()?
        .flatten();
    let project_decision = project
        .map(|policy| evaluate_policy(request, &normalized_paths, policy, PolicyLayer::Project))
        .transpose()?
        .flatten();
    match (organization_decision, project_decision) {
        (Some(organization), Some(project)) => {
            if effect_rank(project.effect) > effect_rank(organization.effect) {
                return Ok(project);
            }
            return Ok(organization);
        }
        (Some(decision), None) | (None, Some(decision)) => return Ok(decision),
        (None, None) => {}
    }
    let effect = if matches!(request.tool.capability, Capability::Unknown) {
        organization
            .and_then(|policy| policy.defaults.unknown_tool)
            .map_or(DecisionEffect::Allow, unknown_default_effect)
    } else {
        DecisionEffect::Allow
    };
    Ok(Decision {
        protocol: PROTOCOL_VERSION,
        effect,
        rule_id: "default.no_matching_rule".to_owned(),
        severity: Severity::Info,
        category: "default".to_owned(),
        reason: "No policy rule matched the normalized request.".to_owned(),
        policy_layer: PolicyLayer::Default,
        details: Evidence { matched_path: None },
    })
}

fn evaluate_shell(
    command: &str,
    cwd: &str,
    sensitive_tables: &[&str],
    depth: usize,
) -> Result<Option<Decision>, PolicyError> {
    if depth > 4 {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.nesting_limit",
            "Shell wrapper nesting exceeds safe analysis limits.",
            Severity::High,
        )));
    }
    let Ok(tokens) = shell::tokenize(command) else {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.ambiguous",
            "The shell command contains syntax that cannot be inspected safely.",
            Severity::High,
        )));
    };
    let mut decisions = Vec::new();
    for target in shell::redirect_targets(&tokens)
        .map_err(|_| PolicyError::Invalid("invalid shell redirection"))?
    {
        if let Some(decision) = evaluate_shell_path(cwd, target, RuleOperation::Write)? {
            decisions.push(decision);
        }
    }
    for segment in shell::segments(&tokens) {
        let words = shell::words(segment);
        if let Some(decision) = analyze_argv(&words, cwd, sensitive_tables, depth)? {
            decisions.push(decision);
        }
    }
    Ok(decisions
        .into_iter()
        .max_by_key(|decision| effect_rank(decision.effect)))
}

fn analyze_argv(
    words: &[&str],
    cwd: &str,
    sensitive_tables: &[&str],
    depth: usize,
) -> Result<Option<Decision>, PolicyError> {
    let mut words = words;
    while let Some((first, rest)) = words.split_first() {
        let name = command_name(first);
        if matches!(name, "env" | "command")
            || (words.len() != 1 && (first.starts_with('-') || is_assignment(first)))
        {
            words = rest;
        } else {
            break;
        }
    }
    let Some((program, args)) = words.split_first() else {
        return Ok(None);
    };
    let program = command_name(program);
    if program == "sudo" || program == "su" {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.privilege_escalation",
            "Privilege escalation commands are prohibited.",
            Severity::Critical,
        )));
    }
    if matches!(program, "sh" | "bash") && args.first().is_some_and(|arg| *arg == "-c") {
        return match args.get(1) {
            Some(inner) => evaluate_shell(inner, cwd, sensitive_tables, depth + 1),
            None => Ok(Some(command_decision(
                DecisionEffect::Deny,
                "shell.ambiguous",
                "A shell wrapper is missing its command text.",
                Severity::High,
            ))),
        };
    }
    if matches!(program, "python" | "python3" | "php" | "node")
        && args
            .first()
            .is_some_and(|arg| matches!(*arg, "-c" | "-r" | "-e"))
    {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.language_eval",
            "Arbitrary language evaluation cannot be inspected safely.",
            Severity::High,
        )));
    }
    if program == "ddev" {
        return match analyzers::ddev::unwrap(args) {
            analyzers::ddev::Target::Safe => Ok(None),
            analyzers::ddev::Target::Decision(decision) => Ok(Some(decision)),
            analyzers::ddev::Target::Drush(inner) => {
                Ok(analyzers::drush::analyze(inner, sensitive_tables))
            }
            analyzers::ddev::Target::Composer(inner) => Ok(analyzers::composer::analyze(inner)),
            analyzers::ddev::Target::Sql(sql) => Ok(analyzers::sql::analyze(sql, sensitive_tables)),
            analyzers::ddev::Target::Nested(inner) if inner.len() == 1 => {
                evaluate_shell(inner[0], cwd, sensitive_tables, depth + 1)
            }
            analyzers::ddev::Target::Nested(inner) => {
                analyze_argv(inner, cwd, sensitive_tables, depth + 1)
            }
        };
    }
    let semantic = match program {
        "drush" => analyzers::drush::analyze(args, sensitive_tables),
        "composer" => analyzers::composer::analyze(args),
        "git" => analyzers::git::analyze(args),
        "mysql" => args
            .windows(2)
            .find(|pair| pair[0] == "-e" || pair[0] == "--execute")
            .and_then(|pair| analyzers::sql::analyze(pair[1], sensitive_tables)),
        _ => None,
    };
    if semantic.is_some() {
        return Ok(semantic);
    }
    analyze_path_argv(program, args, cwd)
}

fn analyze_path_argv(
    program: &str,
    args: &[&str],
    cwd: &str,
) -> Result<Option<Decision>, PolicyError> {
    let path_operation = match program {
        "cat" | "head" | "tail" | "less" | "more" | "grep" | "sed" | "awk" | "wc" => {
            Some((RuleOperation::Read, args))
        }
        "rm" | "touch" | "mkdir" | "tee" => Some((RuleOperation::Write, args)),
        "cp" | "mv" | "install" => args
            .last()
            .map(|target| (RuleOperation::Write, std::slice::from_ref(target))),
        _ => None,
    };
    if let Some((operation, candidates)) = path_operation {
        for path in candidates
            .iter()
            .copied()
            .filter(|argument| !argument.starts_with('-'))
        {
            if let Some(decision) = evaluate_shell_path(cwd, path, operation)? {
                return Ok(Some(decision));
            }
        }
    }
    if matches!(program, "cp" | "mv") {
        for path in args[..args.len().saturating_sub(1)]
            .iter()
            .copied()
            .filter(|argument| !argument.starts_with('-'))
        {
            if let Some(decision) = evaluate_shell_path(cwd, path, RuleOperation::Read)? {
                return Ok(Some(decision));
            }
        }
    }
    Ok(None)
}

fn command_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn evaluate_shell_path(
    cwd: &str,
    path: &str,
    operation: RuleOperation,
) -> Result<Option<Decision>, PolicyError> {
    let normalized = paths::normalize(cwd, path).map_err(PolicyError::Path)?;
    for rule in BUILT_INS {
        if matches!(
            (operation, rule.operation),
            (RuleOperation::Read, RuleOperation::Read)
                | (RuleOperation::Write, RuleOperation::Write)
        ) && first_matching_path(std::slice::from_ref(&normalized), rule.patterns)?.is_some()
        {
            return Ok(Some(rule.decision(normalized)));
        }
    }
    Ok(None)
}

fn command_decision(
    effect: DecisionEffect,
    rule_id: &str,
    reason: &str,
    severity: Severity,
) -> Decision {
    Decision {
        protocol: PROTOCOL_VERSION,
        effect,
        rule_id: rule_id.to_owned(),
        severity,
        category: "shell".to_owned(),
        reason: reason.to_owned(),
        policy_layer: PolicyLayer::BuiltIn,
        details: Evidence { matched_path: None },
    }
}

const fn unknown_default_effect(default: UnknownToolDefault) -> DecisionEffect {
    match default {
        UnknownToolDefault::Deny => DecisionEffect::Deny,
        UnknownToolDefault::Ask => DecisionEffect::Ask,
        UnknownToolDefault::Allow
        | UnknownToolDefault::AllowUnlessSensitive
        | UnknownToolDefault::DenyIfSensitiveOtherwiseAllow => DecisionEffect::Allow,
    }
}

fn evaluate_built_ins(
    request: &CanonicalRequest,
    paths: &[String],
) -> Result<Option<Decision>, PolicyError> {
    for rule in BUILT_INS {
        if rule.operation.applies(request.tool.capability)
            && let Some(path) = first_matching_path(paths, rule.patterns)?
        {
            return Ok(Some(rule.decision(path)));
        }
    }
    Ok(None)
}

fn evaluate_policy(
    request: &CanonicalRequest,
    paths: &[String],
    policy: &Policy,
    layer: PolicyLayer,
) -> Result<Option<Decision>, PolicyError> {
    if (request.tool.capability.is_read()
        || matches!(
            request.tool.capability,
            Capability::McpCall | Capability::Unknown
        ))
        && let Some(path) = first_matching_owned_path(paths, &policy.paths.deny_read)?
    {
        return Ok(Some(policy_path_decision(
            "path.deny_read",
            "Reading a path denied by policy is prohibited.",
            layer,
            path,
        )));
    }
    if (request.tool.capability.is_write()
        || matches!(
            request.tool.capability,
            Capability::McpCall | Capability::Unknown
        ))
        && let Some(path) = first_matching_owned_path(paths, &policy.paths.deny_write)?
    {
        return Ok(Some(policy_path_decision(
            "path.deny_write",
            "Writing a path denied by policy is prohibited.",
            layer,
            path,
        )));
    }
    let mut strongest: Option<&Rule> = None;
    let mut matched_path = None;
    for rule in &policy.rules {
        if !rule.matcher.capabilities.is_empty()
            && !rule.matcher.capabilities.contains(&request.tool.capability)
        {
            continue;
        }
        if let Some(path) = first_matching_owned_path(paths, &rule.matcher.paths)?
            && strongest
                .is_none_or(|current| effect_rank(rule.effect) > effect_rank(current.effect))
        {
            strongest = Some(rule);
            matched_path = Some(path);
        }
    }
    Ok(strongest.map(|rule| Decision {
        protocol: PROTOCOL_VERSION,
        effect: rule.effect,
        rule_id: rule.id.clone(),
        severity: rule.severity,
        category: rule.category.clone(),
        reason: rule.description.clone(),
        policy_layer: layer,
        details: Evidence { matched_path },
    }))
}

const fn effect_rank(effect: DecisionEffect) -> u8 {
    match effect {
        DecisionEffect::Allow => 0,
        DecisionEffect::Ask => 1,
        DecisionEffect::Deny => 2,
    }
}

fn first_matching_path(paths: &[String], patterns: &[&str]) -> Result<Option<String>, PolicyError> {
    for pattern in patterns {
        let pattern = PathPattern::compile(pattern).map_err(PolicyError::Path)?;
        if let Some(path) = paths.iter().find(|path| pattern.matches(path)) {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

fn first_matching_owned_path(
    paths: &[String],
    patterns: &[String],
) -> Result<Option<String>, PolicyError> {
    let borrowed = patterns.iter().map(String::as_str).collect::<Vec<_>>();
    first_matching_path(paths, &borrowed)
}

fn policy_path_decision(suffix: &str, reason: &str, layer: PolicyLayer, path: String) -> Decision {
    let prefix = match layer {
        PolicyLayer::Organization => "organization",
        PolicyLayer::Project => "project",
        PolicyLayer::BuiltIn | PolicyLayer::Default => "policy",
    };
    Decision {
        protocol: PROTOCOL_VERSION,
        effect: DecisionEffect::Deny,
        rule_id: format!("{prefix}.{suffix}"),
        severity: Severity::High,
        category: "filesystem".to_owned(),
        reason: reason.to_owned(),
        policy_layer: layer,
        details: Evidence {
            matched_path: Some(path),
        },
    }
}

#[derive(Clone, Copy)]
enum RuleOperation {
    Read,
    Write,
}
impl RuleOperation {
    const fn applies(self, capability: Capability) -> bool {
        match self {
            Self::Read => {
                capability.is_read()
                    || matches!(capability, Capability::McpCall | Capability::Unknown)
            }
            Self::Write => {
                capability.is_write()
                    || matches!(capability, Capability::McpCall | Capability::Unknown)
            }
        }
    }
}

struct BuiltInRule {
    id: &'static str,
    category: &'static str,
    reason: &'static str,
    severity: Severity,
    operation: RuleOperation,
    patterns: &'static [&'static str],
}
impl BuiltInRule {
    const fn new(
        id: &'static str,
        category: &'static str,
        reason: &'static str,
        severity: Severity,
        operation: RuleOperation,
        patterns: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            category,
            reason,
            severity,
            operation,
            patterns,
        }
    }
    fn decision(&self, path: String) -> Decision {
        Decision {
            protocol: PROTOCOL_VERSION,
            effect: DecisionEffect::Deny,
            rule_id: self.id.to_owned(),
            severity: self.severity,
            category: self.category.to_owned(),
            reason: self.reason.to_owned(),
            policy_layer: PolicyLayer::BuiltIn,
            details: Evidence {
                matched_path: Some(path),
            },
        }
    }
}

pub(crate) fn explain(rule_id: &str) -> Option<String> {
    BUILT_INS
        .iter()
        .find(|rule| rule.id == rule_id)
        .map(|rule| {
            format!(
                "Rule: {}\nLayer: built_in\nSeverity: {:?}\nCategory: {}\nReason: {}\nPatterns: {}",
                rule.id,
                rule.severity,
                rule.category,
                rule.reason,
                rule.patterns.join(", ")
            )
        })
}

#[derive(Debug)]
pub(crate) enum PolicyError {
    Read(std::io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
    Weakening(&'static str),
    Path(paths::PathError),
}
impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "could not read mandatory policy: {error}"),
            Self::Json(error) => write!(
                formatter,
                "invalid policy JSON at line {} column {}",
                error.line(),
                error.column()
            ),
            Self::Invalid(message) | Self::Weakening(message) => formatter.write_str(message),
            Self::Path(error) => error.fmt(formatter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Policy, PolicyKind, evaluate};
    use crate::model::{CanonicalRequest, DecisionEffect, PolicyLayer};
    use serde_json::json;

    fn request(capability: &str, path: &str) -> CanonicalRequest {
        let value = json!({"protocol":1,"agent":"fixture","event":"pre_tool_use","cwd":"/workspace/project","tool":{"native_name":"fixture","capability":capability},"input":{},"facts":{"paths":[path]}});
        CanonicalRequest::from_slice(serde_json::to_string(&value).unwrap().as_bytes()).unwrap()
    }
    fn policy(input: &serde_json::Value, kind: PolicyKind) -> Policy {
        Policy::from_slice(serde_json::to_string(input).unwrap().as_bytes(), kind).unwrap()
    }
    fn shell_request(command: &str) -> CanonicalRequest {
        let value = json!({"protocol":1,"agent":"fixture","event":"pre_tool_use","cwd":"/workspace/project","tool":{"native_name":"Bash","capability":"shell_execute"},"input":{"command":command},"facts":{"command":command}});
        CanonicalRequest::from_slice(serde_json::to_string(&value).unwrap().as_bytes()).unwrap()
    }

    #[test]
    fn built_in_deny_cannot_be_weakened_by_organization_allow() {
        let organization = policy(
            &json!({"schema":1,"rules":[{"id":"organization.allow.settings","description":"Allow settings","effect":"allow","severity":"info","match":{"capabilities":["file_read"],"paths":["**/settings.php"]}}]}),
            PolicyKind::Organization,
        );
        let decision = evaluate(
            &request("file_read", "web/sites/default/settings.php"),
            Some(&organization),
            None,
        )
        .unwrap();
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.policy_layer, PolicyLayer::BuiltIn);
    }
    #[test]
    fn project_policy_rejects_allow_rules() {
        let input = json!({"schema":1,"rules":[{"id":"project.allow.anything","description":"Attempt weakening","effect":"allow","severity":"info","match":{"paths":["**/*"]}}]});
        assert!(
            Policy::from_slice(
                serde_json::to_string(&input).unwrap().as_bytes(),
                PolicyKind::Project
            )
            .is_err()
        );
    }
    #[test]
    fn deny_beats_ask_and_order_is_stable() {
        let organization = policy(
            &json!({"schema":1,"rules":[{"id":"organization.ask.private","description":"Ask first","effect":"ask","severity":"medium","match":{"paths":["**/private/**"]}},{"id":"organization.deny.private","description":"Deny","effect":"deny","severity":"high","match":{"paths":["**/private/**"]}}]}),
            PolicyKind::Organization,
        );
        let decision = evaluate(
            &request("file_read", "private/data.txt"),
            Some(&organization),
            None,
        )
        .unwrap();
        assert_eq!(decision.rule_id, "organization.deny.private");
    }
    #[test]
    fn unknown_sensitive_path_denies_but_safe_path_allows() {
        let denied = evaluate(&request("unknown", ".env.local"), None, None).unwrap();
        let allowed = evaluate(&request("unknown", "README.md"), None, None).unwrap();
        assert_eq!(denied.effect, DecisionEffect::Deny);
        assert_eq!(allowed.effect, DecisionEffect::Allow);
    }
    #[test]
    fn unknown_policy_schema_is_rejected() {
        assert!(Policy::from_slice(br#"{"schema":99}"#, PolicyKind::Organization).is_err());
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        assert!(
            Policy::from_slice(
                br#"{"schema":1,"future_optional":{"enabled":true}}"#,
                PolicyKind::Organization
            )
            .is_err()
        );
    }

    #[test]
    fn project_deny_strengthens_organization_allow() {
        let organization = policy(
            &json!({"schema":1,"rules":[{"id":"organization.allow.private","description":"Organization allow","effect":"allow","severity":"info","match":{"paths":["**/private/**"]}}]}),
            PolicyKind::Organization,
        );
        let project = policy(
            &json!({"schema":1,"rules":[{"id":"project.deny.private","description":"Project deny","effect":"deny","severity":"high","match":{"paths":["**/private/**"]}}]}),
            PolicyKind::Project,
        );
        let decision = evaluate(
            &request("file_read", "private/data.txt"),
            Some(&organization),
            Some(&project),
        )
        .unwrap();
        assert_eq!(decision.rule_id, "project.deny.private");
        assert_eq!(decision.effect, DecisionEffect::Deny);
    }

    #[test]
    fn first_rule_wins_when_effects_are_equal() {
        let organization = policy(
            &json!({"schema":1,"rules":[{"id":"organization.deny.first","description":"First","effect":"deny","severity":"high","match":{"paths":["**/private/**"]}},{"id":"organization.deny.second","description":"Second","effect":"deny","severity":"high","match":{"paths":["**/private/**"]}}]}),
            PolicyKind::Organization,
        );
        let decision = evaluate(
            &request("file_read", "private/data.txt"),
            Some(&organization),
            None,
        )
        .unwrap();
        assert_eq!(decision.rule_id, "organization.deny.first");
    }

    #[test]
    fn organization_and_project_can_add_sensitive_sql_tables() {
        let organization = policy(
            &json!({"schema":1,"sql":{"sensitive_tables":["customer_payments"]}}),
            PolicyKind::Organization,
        );
        let decision = evaluate(
            &shell_request("drush sql:query 'SELECT * FROM customer_payments'"),
            Some(&organization),
            None,
        )
        .unwrap();
        assert_eq!(decision.rule_id, "sql.read.sensitive_table");
    }
}
