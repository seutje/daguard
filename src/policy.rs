//! Policy loading, validation, precedence, and evaluation orchestration.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::model::{
    CanonicalRequest, Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION,
    PolicyLayer, SensitivityCategory, Severity,
};
use crate::paths::{self, PathPattern};
use crate::{analyzers, shell};

pub(crate) const POLICY_SCHEMA_VERSION: u16 = 3;
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
        &[
            "**/sites/*/settings.php",
            "**/sites/*/settings.local.php",
            "**/env/**/settings.php",
            "**/env/**/settings.local.php",
        ],
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
        "filesystem.secret.credential_store",
        "secrets",
        "Reading known credential stores is prohibited.",
        Severity::Critical,
        RuleOperation::Read,
        &[
            "**/.ssh/id_rsa",
            "**/.ssh/id_dsa",
            "**/.ssh/id_ecdsa",
            "**/.ssh/id_ecdsa_sk",
            "**/.ssh/id_ed25519",
            "**/.ssh/id_ed25519_sk",
            "**/.aws/credentials",
            "**/.azure/accessTokens.json",
            "**/.azure/msal_token_cache.json",
            "**/.config/gcloud/credentials.db*",
            "**/.config/gcloud/application_default_credentials.json",
            "**/.kube/config",
            "**/.docker/config.json",
            "**/.netrc",
            "**/_netrc",
            "**/.npmrc",
            "**/.pypirc",
        ],
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
    /// Only the organization can designate its own candidate rules as telemetry.
    /// Path protections, analyzer rules, defaults and project rules stay enforced.
    #[serde(default, deserialize_with = "deserialize_audit_only_rules")]
    audit_only_rules: Option<Vec<String>>,
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    paths: PathPolicy,
    #[serde(default)]
    sql: SqlPolicy,
    #[serde(default)]
    result: ResultPolicy,
    #[serde(default)]
    rules: Vec<Rule>,
}

// Absence means enforcement; a present null/type error is invalid configuration.
fn deserialize_audit_only_rules<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlPolicy {
    #[serde(default)]
    sensitive_tables: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultPolicy {
    #[serde(default)]
    secret_prefixes: Vec<String>,
    #[serde(default)]
    sensitive_fields: BTreeMap<String, SensitivityCategory>,
    #[serde(default)]
    ip_addresses_are_personal: bool,
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
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(PolicyError::Read)?
            .take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(PolicyError::Read)?;
        Self::from_slice(&bytes, kind)
    }

    pub(crate) fn from_slice(input: &[u8], kind: PolicyKind) -> Result<Self, PolicyError> {
        if input.len() as u64 > MAX_POLICY_BYTES {
            return Err(PolicyError::Invalid("policy exceeds 1 MiB"));
        }
        crate::json::preflight(input, 1024 * 1024).map_err(PolicyError::Json)?;
        let policy: Self = serde_json::from_slice(input).map_err(PolicyError::Json)?;
        policy.validate(kind)?;
        Ok(policy)
    }

    fn validate(&self, kind: PolicyKind) -> Result<(), PolicyError> {
        if !(1..=POLICY_SCHEMA_VERSION).contains(&self.schema) {
            return Err(PolicyError::Invalid("unsupported policy schema version"));
        }
        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::Invalid("policy contains too many rules"));
        }
        if let Some(observed) = &self.audit_only_rules {
            if self.schema < 2 {
                return Err(PolicyError::Invalid(
                    "audit-only rules require policy schema 2",
                ));
            }
            if matches!(kind, PolicyKind::Project) {
                return Err(PolicyError::Weakening(
                    "project policy cannot enable audit-only evaluation",
                ));
            }
            let mut unique = HashSet::new();
            if observed.len() > MAX_RULES
                || observed.iter().any(|id| {
                    !unique.insert(id)
                        || explain(id).is_some()
                        || !self
                            .rules
                            .iter()
                            .any(|rule| rule.id == *id && rule.effect != DecisionEffect::Allow)
                })
            {
                return Err(PolicyError::Invalid(
                    "audit-only IDs must name unique organization candidate deny/ask rules",
                ));
            }
        }
        if matches!(kind, PolicyKind::Project) && self.defaults.unknown_tool.is_some() {
            return Err(PolicyError::Weakening(
                "project policy cannot change default decisions",
            ));
        }
        validate_patterns(&self.paths.deny_read)?;
        validate_patterns(&self.paths.deny_write)?;
        if self.sql.sensitive_tables.len() > MAX_PATTERNS_PER_RULE
            || self.sql.sensitive_tables.iter().any(|table| {
                table.is_empty()
                    || table.len() > 128
                    || !table.bytes().any(|byte| byte.is_ascii_alphanumeric())
                    || !table
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'*')
            })
        {
            return Err(PolicyError::Invalid(
                "SQL sensitive table configuration is invalid",
            ));
        }
        validate_result_policy(self.schema, &self.result)?;
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

    pub(crate) fn audit_only(&self) -> bool {
        self.audit_only_rules
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
    }

    pub(crate) fn sensitive_tables(&self) -> impl Iterator<Item = &str> {
        self.sql.sensitive_tables.iter().map(String::as_str)
    }

    pub(crate) fn extend_scan_config(&self, config: &mut crate::scanner::ScanConfig) {
        config
            .secret_prefixes
            .extend(self.result.secret_prefixes.iter().cloned());
        for (field, category) in &self.result.sensitive_fields {
            config
                .sensitive_fields
                .entry(field.to_ascii_lowercase().replace('-', "_"))
                .or_insert(*category);
        }
        config.ip_addresses_are_personal |= self.result.ip_addresses_are_personal;
    }
}

fn validate_result_policy(schema: u16, result: &ResultPolicy) -> Result<(), PolicyError> {
    if schema < 3
        && (!result.secret_prefixes.is_empty()
            || !result.sensitive_fields.is_empty()
            || result.ip_addresses_are_personal)
    {
        return Err(PolicyError::Invalid(
            "result scanning policy requires policy schema 3",
        ));
    }
    if result.secret_prefixes.len() > MAX_PATTERNS_PER_RULE
        || result.secret_prefixes.iter().any(|prefix| {
            prefix.is_empty()
                || prefix.len() > 64
                || !prefix.is_ascii()
                || prefix.bytes().any(|byte| byte.is_ascii_whitespace())
        })
        || result.sensitive_fields.len() > MAX_PATTERNS_PER_RULE
        || result.sensitive_fields.keys().any(|field| {
            field.is_empty()
                || field.len() > 128
                || !field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    {
        return Err(PolicyError::Invalid(
            "result scanning configuration is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn scan_config(
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> crate::scanner::ScanConfig {
    let mut config = crate::scanner::ScanConfig::default();
    if let Some(policy) = organization {
        policy.extend_scan_config(&mut config);
    }
    if let Some(policy) = project {
        policy.extend_scan_config(&mut config);
    }
    config
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SensitivePathMatch {
    pub(crate) source_id: String,
    pub(crate) layer: PolicyLayer,
    pub(crate) normalized_path: String,
}

/// Reuses mandatory and configured read-path policy for metadata-only source
/// classification. Sink policy intentionally does not participate here.
pub(crate) fn classify_sensitive_path(
    cwd: &str,
    path: &str,
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Option<SensitivePathMatch>, PolicyError> {
    let normalized = paths::normalize(cwd, path).map_err(PolicyError::Path)?;
    for rule in BUILT_INS
        .iter()
        .filter(|rule| matches!(rule.operation, RuleOperation::Read))
    {
        if first_matching_path(std::slice::from_ref(&normalized), rule.patterns)?.is_some() {
            return Ok(Some(SensitivePathMatch {
                source_id: rule.id.to_owned(),
                layer: PolicyLayer::BuiltIn,
                normalized_path: normalized,
            }));
        }
    }
    for (policy, layer, source_id) in [
        (
            organization,
            PolicyLayer::Organization,
            "organization.path.deny_read",
        ),
        (project, PolicyLayer::Project, "project.path.deny_read"),
    ] {
        let Some(policy) = policy else {
            continue;
        };
        if first_matching_owned_path(std::slice::from_ref(&normalized), &policy.paths.deny_read)?
            .is_some()
        {
            return Ok(Some(SensitivePathMatch {
                source_id: source_id.to_owned(),
                layer,
                normalized_path: normalized,
            }));
        }
    }
    Ok(None)
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
    evaluate_inner(request, organization, project, false)
}

/// Re-evaluate while omitting only organization-designated candidate rules.
/// Never convert a winning deny directly to allow: other mandatory rules may match.
pub(crate) fn enforce(
    request: &CanonicalRequest,
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Decision, PolicyError> {
    evaluate_inner(request, organization, project, true)
}

fn evaluate_inner(
    request: &CanonicalRequest,
    organization: Option<&Policy>,
    project: Option<&Policy>,
    omit_candidates: bool,
) -> Result<Decision, PolicyError> {
    request
        .validate()
        .map_err(|_| PolicyError::Invalid("invalid canonical request"))?;
    let sensitive_tables = organization
        .into_iter()
        .chain(project)
        .flat_map(|policy| policy.sql.sensitive_tables.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let command_decision =
        request_command_decision(request, &sensitive_tables, organization, project)?;
    // A candidate file rule must never replace a mandatory command denial.
    if let Some(decision) = &command_decision
        && decision.effect == DecisionEffect::Deny
    {
        return Ok(decision.clone());
    }
    let normalized_paths = request
        .candidate_paths()
        .into_iter()
        .map(|path| paths::normalize(&request.cwd, path).map_err(PolicyError::Path))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(decision) = request_tree_decision(
        request,
        &normalized_paths,
        &sensitive_tables,
        organization,
        project,
    )? {
        return Ok(decision);
    }
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
                omit_candidates,
            )
        })
        .transpose()?
        .flatten();
    let project_decision = project
        .map(|policy| {
            evaluate_policy(
                request,
                &normalized_paths,
                policy,
                PolicyLayer::Project,
                false,
            )
        })
        .transpose()?
        .flatten();
    let organization_decision = match (organization_decision, command_decision.as_ref()) {
        (Some(policy), Some(command))
            if effect_rank(policy.effect) < effect_rank(command.effect) =>
        {
            Some(command.clone())
        }
        (policy, _) => policy,
    };
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
    if let Some(command) = command_decision
        && effect_rank(command.effect) >= effect_rank(effect)
    {
        return Ok(command);
    }
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

fn request_tree_decision(
    request: &CanonicalRequest,
    normalized_paths: &[String],
    sensitive_tables: &[&str],
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Option<Decision>, PolicyError> {
    if matches!(
        request.tool.capability,
        Capability::FileDelete | Capability::FileMove
    ) {
        let context = ShellContext {
            cwd: &request.cwd,
            container: false,
            sensitive_tables,
            organization,
            project,
        };
        for path in normalized_paths {
            if let Some(decision) = evaluate_tree_write(&context, path)? {
                return Ok(Some(decision));
            }
        }
    }
    Ok(None)
}

fn request_command_decision(
    request: &CanonicalRequest,
    sensitive_tables: &[&str],
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Option<Decision>, PolicyError> {
    if !request.tool.is_mcp()
        && !matches!(
            request.tool.capability,
            Capability::ShellExecute | Capability::Unknown
        )
    {
        return Ok(None);
    }
    let queries = request
        .candidate_queries()
        .map_err(|_| PolicyError::Invalid("invalid structured SQL input"))?;
    let name = request.tool.native_name.to_ascii_lowercase();
    if (request.tool.is_mcp() || request.tool.capability == Capability::Unknown)
        && queries.is_empty()
        && ["__db__", "database", "sql", "postgres", "mongo"]
            .iter()
            .any(|part| name.contains(part))
    {
        return Ok(Some(analyzers::sql::uninspectable()));
    }
    for query in queries {
        if let Some(decision) = analyzers::sql::analyze(query, sensitive_tables) {
            return Ok(Some(decision));
        }
    }
    let commands = request.candidate_commands();
    if request.tool.capability == Capability::ShellExecute && commands.is_empty() {
        return Err(PolicyError::Invalid(
            "shell request is missing its command fact",
        ));
    }
    let context = ShellContext {
        cwd: &request.cwd,
        container: false,
        sensitive_tables,
        organization,
        project,
    };
    let mut decisions = Vec::new();
    for command in commands {
        if let Some(decision) = evaluate_shell(command, &context, 0)? {
            decisions.push(decision);
        }
    }
    Ok(decisions
        .into_iter()
        .max_by_key(|decision| effect_rank(decision.effect)))
}

struct ShellContext<'a> {
    cwd: &'a str,
    container: bool,
    sensitive_tables: &'a [&'a str],
    organization: Option<&'a Policy>,
    project: Option<&'a Policy>,
}

fn evaluate_shell(
    command: &str,
    context: &ShellContext<'_>,
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
    let Ok(segments) = shell::contextual_segments(&tokens, context.cwd) else {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.ambiguous",
            "The shell execution directory cannot be established safely.",
            Severity::High,
        )));
    };
    for (cwd, segment) in segments {
        let context = ShellContext {
            cwd: &cwd,
            ..*context
        };
        for target in shell::redirect_targets(segment)
            .map_err(|_| PolicyError::Invalid("invalid shell redirection"))?
        {
            if let Some(decision) = evaluate_shell_path(&context, target, RuleOperation::Write)? {
                decisions.push(decision);
            }
        }
        let words = shell::words(segment);
        if let Some(decision) = analyze_argv(&words, &context, depth)? {
            decisions.push(decision);
        }
    }
    Ok(decisions
        .into_iter()
        .max_by_key(|decision| effect_rank(decision.effect)))
}

fn analyze_argv(
    words: &[&str],
    context: &ShellContext<'_>,
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
    let Ok(words) = shell::normalize_argv(words) else {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.ambiguous",
            "An execution wrapper cannot be inspected safely.",
            Severity::High,
        )));
    };
    let Some((program, args)) = words.split_first() else {
        return Ok(None);
    };
    let program = command_name(program);
    if unsupported_control(program) {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.ambiguous",
            "Unsupported directory-changing command.",
            Severity::High,
        )));
    }
    if program == "sudo" || program == "su" {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "shell.privilege_escalation",
            "Privilege escalation commands are prohibited.",
            Severity::Critical,
        )));
    }
    if matches!(program, "sh" | "bash") {
        let command_flag = args
            .iter()
            .take_while(|arg| arg.starts_with('-'))
            .position(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c'));
        let Some(position) = command_flag else {
            return Ok(Some(command_decision(
                DecisionEffect::Deny,
                "shell.ambiguous",
                "A shell invocation without inspectable command text is prohibited.",
                Severity::High,
            )));
        };
        return match args.get(position + 1) {
            Some(inner) => evaluate_shell(inner, context, depth + 1),
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
        return analyze_ddev(args, context, depth);
    }
    let semantic = match program {
        "drush" => analyzers::drush::analyze(args, context.sensitive_tables),
        "composer" => analyzers::composer::analyze(args),
        "git" => analyzers::git::analyze(args),
        "mysql" => match analyzers::sql::client_query(args, false) {
            Ok(query) => analyzers::sql::analyze(query, context.sensitive_tables),
            Err(()) => Some(analyzers::sql::uninspectable()),
        },
        _ => None,
    };
    if semantic.is_some() {
        return Ok(semantic);
    }
    analyze_path_argv(program, args, context)
}

fn unsupported_control(program: &str) -> bool {
    matches!(
        program,
        "cd" | "pushd"
            | "popd"
            | "if"
            | "then"
            | "else"
            | "for"
            | "while"
            | "until"
            | "do"
            | "case"
            | "!"
            | "function"
    )
}

fn analyze_ddev(
    args: &[&str],
    context: &ShellContext<'_>,
    depth: usize,
) -> Result<Option<Decision>, PolicyError> {
    match analyzers::ddev::unwrap(args) {
        analyzers::ddev::Target::Safe => Ok(None),
        analyzers::ddev::Target::Decision(decision) => Ok(Some(decision)),
        analyzers::ddev::Target::Drush(inner) => {
            Ok(analyzers::drush::analyze(inner, context.sensitive_tables))
        }
        analyzers::ddev::Target::Composer(inner) => Ok(analyzers::composer::analyze(inner)),
        analyzers::ddev::Target::Sql(sql) => {
            Ok(analyzers::sql::analyze(sql, context.sensitive_tables))
        }
        analyzers::ddev::Target::Nested(inner, cwd) => {
            let context = ShellContext {
                cwd,
                container: true,
                ..*context
            };
            if inner.len() == 1 {
                evaluate_shell(inner[0], &context, depth + 1)
            } else {
                analyze_argv(inner, &context, depth + 1)
            }
        }
    }
}

fn analyze_path_argv(
    program: &str,
    args: &[&str],
    context: &ShellContext<'_>,
) -> Result<Option<Decision>, PolicyError> {
    let Ok(effects) = analyzers::filesystem::effects(program, args) else {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "filesystem.ambiguous",
            "Filesystem operand effects cannot be established safely.",
            Severity::High,
        )));
    };
    for effect in effects {
        use analyzers::filesystem::Effect;
        let (path, operation) = match effect {
            Effect::Read(path) => (path, RuleOperation::Read),
            Effect::Write(path) | Effect::TreeWrite(path) => (path, RuleOperation::Write),
        };
        if let Some(decision) = evaluate_shell_path(context, path, operation)? {
            return Ok(Some(decision));
        }
        if matches!(effect, Effect::TreeWrite(_))
            && let Some(decision) = evaluate_tree_write(context, path)?
        {
            return Ok(Some(decision));
        }
    }
    if let Some(candidates) = analyzers::network::protected_file_candidates(program, args) {
        for candidate in candidates {
            if let Some(decision) = evaluate_shell_path(context, candidate, RuleOperation::Read)? {
                return Ok(Some(decision));
            }
        }
    }
    if program == "git" {
        return analyze_git_paths(args, context);
    }
    if matches!(program, "grep" | "rg") {
        return analyze_search(program, args, context);
    }
    let path_operation = match program {
        "sed"
            if args.iter().any(|arg| {
                *arg == "--in-place"
                    || arg.starts_with("--in-place=")
                    || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('i'))
            }) =>
        {
            Some((RuleOperation::Write, args))
        }
        "cat" | "head" | "tail" | "less" | "more" | "sed" | "awk" | "wc" => {
            Some((RuleOperation::Read, args))
        }
        "touch" | "mkdir" | "tee" => Some((RuleOperation::Write, args)),
        _ => None,
    };
    if let Some((operation, candidates)) = path_operation {
        for path in candidates
            .iter()
            .copied()
            .filter(|argument| !argument.starts_with('-'))
        {
            if let Some(decision) = evaluate_shell_path(context, path, operation)? {
                return Ok(Some(decision));
            }
        }
    }
    let read_candidates = match program {
        "cp" | "mv" => &args[..args.len().saturating_sub(1)],
        // In-place sed also reads its inputs and can print their contents.
        "sed" => args,
        _ => &[],
    };
    for path in read_candidates
        .iter()
        .copied()
        .filter(|argument| !argument.starts_with('-'))
    {
        if let Some(decision) = evaluate_shell_path(context, path, RuleOperation::Read)? {
            return Ok(Some(decision));
        }
    }
    Ok(None)
}

fn analyze_search(
    program: &str,
    args: &[&str],
    context: &ShellContext<'_>,
) -> Result<Option<Decision>, PolicyError> {
    let candidates = search_path_candidates(program, args);
    for candidate in &candidates {
        if let Some(decision) = evaluate_shell_path(context, candidate, RuleOperation::Read)? {
            return Ok(Some(decision));
        }
    }
    let bulk = candidates.is_empty()
        || candidates.iter().any(|path| {
            *path == "."
                || *path == ".."
                || path.ends_with('/')
                || !path.rsplit('/').next().unwrap_or(path).contains('.')
        })
        || args.iter().any(|arg| {
            matches!(*arg, "--files" | "--recursive" | "--dereference-recursive")
                || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains(['r', 'R']))
        });
    if bulk && !search_excludes_protected(program, args, context) {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "filesystem.read.bulk",
            "Bulk reads require explicit exclusions for every protected read pattern.",
            Severity::High,
        )));
    }
    Ok(None)
}

fn search_excludes_protected(program: &str, args: &[&str], context: &ShellContext<'_>) -> bool {
    if program != "rg"
        || args.iter().any(|arg| {
            matches!(*arg, "-L" | "--follow" | "--pre" | "--pre-glob") || arg.starts_with("--pre=")
        })
    {
        return false;
    }
    let mut exclusions = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let value = if matches!(*arg, "-g" | "--glob") {
            index += 1;
            args.get(index).copied()
        } else {
            arg.strip_prefix("--glob=")
                .or_else(|| arg.strip_prefix("-g").filter(|value| !value.is_empty()))
        };
        if let Some(value) = value {
            if let Some(exclusion) = value.strip_prefix('!') {
                exclusions.push(exclusion);
            } else {
                exclusions.clear();
            } // Later inclusion globs can override exclusions.
        }
        if *arg == "--iglob" || arg.starts_with("--iglob=") {
            return false;
        }
        index += 1;
    }
    BUILT_INS
        .iter()
        .filter(|rule| matches!(rule.operation, RuleOperation::Read))
        .flat_map(|rule| rule.patterns.iter().copied())
        .chain(
            context
                .organization
                .into_iter()
                .chain(context.project)
                .flat_map(|policy| policy.paths.deny_read.iter().map(String::as_str)),
        )
        .all(|pattern| exclusions.contains(&pattern))
}

fn analyze_git_paths(
    args: &[&str],
    context: &ShellContext<'_>,
) -> Result<Option<Decision>, PolicyError> {
    let mut cwd = context.cwd.to_owned();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if *arg == "-C" {
            cwd = paths::normalize(
                &cwd,
                args.get(index + 1)
                    .ok_or(PolicyError::Invalid("missing Git directory"))?,
            )
            .map_err(PolicyError::Path)?;
            index += 2;
        } else if arg.starts_with("--git-dir") || arg.starts_with("--work-tree") {
            return Ok(Some(command_decision(
                DecisionEffect::Deny,
                "git.context.unknown",
                "Git filesystem context cannot be established safely.",
                Severity::High,
            )));
        } else if *arg == "-c" {
            index += 2;
        } else if arg.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    let context = ShellContext {
        cwd: &cwd,
        ..*context
    };
    if args
        .get(index)
        .is_some_and(|arg| matches!(*arg, "show" | "cat-file"))
    {
        let mut inspectable = false;
        for arg in &args[index + 1..] {
            if let Some((_, path)) = arg.split_once(':') {
                let path = path
                    .strip_prefix("0:")
                    .or_else(|| path.strip_prefix("1:"))
                    .or_else(|| path.strip_prefix("2:"))
                    .or_else(|| path.strip_prefix("3:"))
                    .unwrap_or(path);
                inspectable = true;
                if let Some(decision) = evaluate_shell_path(&context, path, RuleOperation::Read)? {
                    return Ok(Some(decision));
                }
            }
        }
        if !inspectable {
            return Ok(Some(command_decision(
                DecisionEffect::Deny,
                "git.read.opaque_object",
                "Git object reads require inspectable path selectors.",
                Severity::High,
            )));
        }
    }
    Ok(None)
}

/// Extract explicit filesystem operands from grep-compatible command lines.
///
/// The first positional operand is the search expression unless `-e` or `-f`
/// supplied one. Treating that expression as a path creates false positives
/// for searches whose text happens to equal a protected directory name.
fn search_path_candidates<'a>(program: &str, args: &'a [&'a str]) -> Vec<&'a str> {
    let mut candidates = Vec::new();
    let mut pattern_supplied = false;
    let mut positional_pattern_seen = false;
    let mut positional_only = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if !positional_only && argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if !positional_only && argument.starts_with('-') && argument != "-" {
            if matches!(argument, "-e" | "--regexp" | "-f" | "--file")
                && let Some(value) = args.get(index + 1)
            {
                if matches!(argument, "-f" | "--file") {
                    candidates.push(*value);
                }
                pattern_supplied = true;
                index += 2;
                continue;
            }
            if let Some(value) = argument.strip_prefix("--file=").or_else(|| {
                argument
                    .strip_prefix("-f")
                    .filter(|value| !value.is_empty())
            }) {
                candidates.push(value);
                pattern_supplied = true;
                index += 1;
                continue;
            }
            if argument.starts_with("--regexp=")
                || argument
                    .strip_prefix("-e")
                    .is_some_and(|value| !value.is_empty())
            {
                pattern_supplied = true;
                index += 1;
                continue;
            }
            if search_option_takes_value(program, argument) {
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if pattern_supplied || positional_pattern_seen {
            candidates.push(argument);
        } else {
            positional_pattern_seen = true;
        }
        index += 1;
    }
    candidates
}

fn search_option_takes_value(program: &str, argument: &str) -> bool {
    if program == "rg" && matches!(argument, "-r" | "--replace") {
        return true;
    }
    matches!(
        argument,
        "-A" | "--after-context"
            | "-B"
            | "--before-context"
            | "-C"
            | "--context"
            | "-g"
            | "--glob"
            | "--iglob"
            | "-j"
            | "--threads"
            | "-m"
            | "--max-count"
            | "--max-columns"
            | "--max-depth"
            | "--path-separator"
            | "-t"
            | "--type"
            | "-T"
            | "--type-not"
            | "--type-add"
            | "--encoding"
            | "--engine"
            | "--sort"
            | "--sortr"
    )
}

fn command_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

fn evaluate_tree_write(
    context: &ShellContext<'_>,
    path: &str,
) -> Result<Option<Decision>, PolicyError> {
    let normalized = paths::normalize(context.cwd, path).map_err(PolicyError::Path)?;
    for rule in BUILT_INS
        .iter()
        .filter(|rule| matches!(rule.operation, RuleOperation::Write))
    {
        for pattern in rule.patterns {
            if paths::PathPattern::compile(pattern)
                .map_err(PolicyError::Path)?
                .covers_descendants(&normalized)
            {
                return Ok(Some(rule.decision(normalized)));
            }
        }
    }
    for (policy, layer) in [
        (context.organization, PolicyLayer::Organization),
        (context.project, PolicyLayer::Project),
    ] {
        if let Some(policy) = policy {
            for pattern in &policy.paths.deny_write {
                if paths::PathPattern::compile(pattern)
                    .map_err(PolicyError::Path)?
                    .covers_descendants(&normalized)
                {
                    return Ok(Some(policy_path_decision(
                        "path.deny_write",
                        "Deleting protected descendants is prohibited.",
                        layer,
                        normalized,
                    )));
                }
            }
        }
    }
    if path == "." || normalized == "/" {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "filesystem.write.ancestor",
            "Deleting an entire execution root cannot be inspected safely.",
            Severity::High,
        )));
    }
    Ok(None)
}

fn evaluate_shell_path(
    context: &ShellContext<'_>,
    path: &str,
    operation: RuleOperation,
) -> Result<Option<Decision>, PolicyError> {
    let normalized = paths::normalize(context.cwd, path).map_err(PolicyError::Path)?;
    if context.container
        && matches!(operation, RuleOperation::Write)
        && ["/modules/contrib", "/themes/contrib"]
            .iter()
            .any(|suffix| {
                normalized.ends_with(suffix) || normalized.contains(&format!("{suffix}/"))
            })
    {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "filesystem.write.contrib",
            "Writing container Composer-managed contrib code is prohibited.",
            Severity::High,
        )));
    }
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
    for (policy, layer) in [
        (context.organization, PolicyLayer::Organization),
        (context.project, PolicyLayer::Project),
    ] {
        let Some(policy) = policy else {
            continue;
        };
        let (patterns, suffix, reason) = match operation {
            RuleOperation::Read => (
                &policy.paths.deny_read,
                "path.deny_read",
                "Reading a path denied by policy is prohibited.",
            ),
            RuleOperation::Write => (
                &policy.paths.deny_write,
                "path.deny_write",
                "Writing a path denied by policy is prohibited.",
            ),
        };
        if first_matching_owned_path(std::slice::from_ref(&normalized), patterns)?.is_some() {
            return Ok(Some(policy_path_decision(
                suffix, reason, layer, normalized,
            )));
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
    if request.tool.capability == Capability::FileSearch
        && (paths.is_empty()
            || paths
                .iter()
                .any(|path| !path.rsplit('/').next().unwrap_or(path).contains('.')))
    {
        return Ok(Some(command_decision(
            DecisionEffect::Deny,
            "filesystem.read.bulk",
            "Unfiltered native subtree searches cannot protect sensitive descendants.",
            Severity::High,
        )));
    }
    for rule in BUILT_INS {
        if (rule.operation.applies(request.tool.capability) || request.tool.is_mcp())
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
    omit_candidates: bool,
) -> Result<Option<Decision>, PolicyError> {
    if (request.tool.is_mcp()
        || request.tool.capability.is_read()
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
    if (request.tool.is_mcp()
        || request.tool.capability.is_write()
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
        if omit_candidates
            && policy
                .audit_only_rules
                .as_ref()
                .is_some_and(|ids| ids.contains(&rule.id))
        {
            continue;
        }
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

struct RuleDocumentation {
    id: &'static str,
    effect: DecisionEffect,
    severity: Severity,
    category: &'static str,
    reason: &'static str,
    remediation: &'static str,
}

macro_rules! rule_doc {
    ($id:literal, $effect:ident, $severity:ident, $category:literal, $reason:literal, $remediation:literal) => {
        RuleDocumentation {
            id: $id,
            effect: DecisionEffect::$effect,
            severity: Severity::$severity,
            category: $category,
            reason: $reason,
            remediation: $remediation,
        }
    };
}

const RULE_DOCUMENTATION: &[RuleDocumentation] = &[
    rule_doc!(
        "guard.evaluation_error",
        Deny,
        Critical,
        "guard",
        "The guard could not safely evaluate or audit the request.",
        "Review the guard diagnostics and installation with `daguard doctor`; do not bypass the failed check."
    ),
    rule_doc!(
        "exfiltration.tainted_session",
        Deny,
        Critical,
        "exfiltration",
        "The session accessed protected data and then requested an outbound-capable operation.",
        "Start a new session that has not accessed sensitive sources, or have an authorized human transfer an approved sanitized value."
    ),
    rule_doc!(
        "exfiltration.tainted_session.review",
        Ask,
        High,
        "exfiltration",
        "The session accessed sensitive operational metadata and then requested an outbound-capable operation.",
        "Review the exact destination and send only an approved non-sensitive derived value."
    ),
    rule_doc!(
        "organization.path.deny_read",
        Deny,
        High,
        "filesystem",
        "Organization policy prohibits reading the matched path.",
        "Use an approved non-sensitive source or ask the policy owner for a safe derived value."
    ),
    rule_doc!(
        "organization.path.deny_write",
        Deny,
        High,
        "filesystem",
        "Organization policy prohibits writing the matched path.",
        "Write to an approved project-owned path or use the managed update workflow."
    ),
    rule_doc!(
        "project.path.deny_read",
        Deny,
        High,
        "filesystem",
        "Project policy prohibits reading the matched path.",
        "Use an approved non-sensitive source documented by the project."
    ),
    rule_doc!(
        "project.path.deny_write",
        Deny,
        High,
        "filesystem",
        "Project policy prohibits writing the matched path.",
        "Write to a project-approved path or use the documented managed workflow."
    ),
    rule_doc!(
        "drupal.secret.env",
        Deny,
        Critical,
        "secrets",
        "Environment files commonly contain credentials and tokens.",
        "Use documented non-secret configuration or ask a developer for the specific derived value needed."
    ),
    rule_doc!(
        "composer.secret.auth_json",
        Deny,
        Critical,
        "secrets",
        "Composer authentication files contain repository credentials.",
        "Use Composer commands that do not expose credentials, such as `composer validate`."
    ),
    rule_doc!(
        "drupal.secret.settings_php",
        Deny,
        Critical,
        "secrets",
        "Drupal settings.php files commonly contain credentials and salts.",
        "Use `ddev describe`, `drush status`, or request a specific non-secret derived value."
    ),
    rule_doc!(
        "filesystem.secret.private_key",
        Deny,
        Critical,
        "secrets",
        "Private key material must not be exposed to an agent.",
        "Use a credential-free development workflow or have a developer perform the authenticated operation."
    ),
    rule_doc!(
        "filesystem.secret.credential_store",
        Deny,
        Critical,
        "secrets",
        "Known SSH, cloud, container and package-manager credential stores are protected.",
        "Use public keys and derived non-secret configuration; keep authenticated access outside agent context."
    ),
    rule_doc!(
        "filesystem.write.core",
        Deny,
        High,
        "filesystem",
        "Drupal core is managed dependency source.",
        "Apply changes through Composer patches, configuration, or custom code."
    ),
    rule_doc!(
        "filesystem.write.vendor",
        Deny,
        High,
        "filesystem",
        "Vendor files are managed by Composer.",
        "Change the dependency declaration or use a reviewed Composer patch."
    ),
    rule_doc!(
        "filesystem.write.contrib_module",
        Deny,
        High,
        "filesystem",
        "Contributed modules are managed dependencies.",
        "Use a Composer patch or implement the behavior in a custom module."
    ),
    rule_doc!(
        "filesystem.write.contrib_theme",
        Deny,
        High,
        "filesystem",
        "Contributed themes are managed dependencies.",
        "Use a Composer patch or implement the behavior in a custom theme."
    ),
    rule_doc!(
        "shell.nesting_limit",
        Deny,
        High,
        "shell",
        "Nested shell wrappers exceeded the bounded analyzer depth.",
        "Run a simpler directly inspectable command."
    ),
    rule_doc!(
        "shell.ambiguous",
        Deny,
        High,
        "shell",
        "The shell syntax cannot be classified safely.",
        "Rewrite the operation as a simple command without expansion, heredocs, or unsupported redirection."
    ),
    rule_doc!(
        "shell.privilege_escalation",
        Deny,
        Critical,
        "shell",
        "Privilege escalation is outside the agent boundary.",
        "Have an authorized developer perform the privileged operation separately."
    ),
    rule_doc!(
        "shell.language_eval",
        Deny,
        High,
        "shell",
        "Arbitrary language evaluation cannot be inspected safely.",
        "Use a checked-in script or a purpose-specific, inspectable command."
    ),
    rule_doc!(
        "shell.drush.eval",
        Deny,
        Critical,
        "drush",
        "Arbitrary PHP evaluation through Drush bypasses bounded analysis.",
        "Use a specific read-only Drush command or checked-in custom code."
    ),
    rule_doc!(
        "shell.drush.sql_dump",
        Deny,
        High,
        "drush",
        "Database dumps may expose sensitive data.",
        "Use a sanitized fixture or have a developer export data through the approved process."
    ),
    rule_doc!(
        "shell.drush.sql_cli",
        Deny,
        High,
        "drush",
        "Interactive SQL cannot be inspected before execution.",
        "Use a single explicit read-only `drush sql:query` statement."
    ),
    rule_doc!(
        "drush.mutation.review",
        Ask,
        Medium,
        "drush",
        "State-changing Drush operations require review.",
        "Request approval with the intended configuration or schema change described."
    ),
    rule_doc!(
        "ddev.shell_escape",
        Deny,
        High,
        "ddev",
        "An unrestricted DDEV shell cannot be inspected safely.",
        "Run the required command directly through `ddev exec`."
    ),
    rule_doc!(
        "ddev.database_transfer",
        Deny,
        High,
        "ddev",
        "Database import/export may expose or overwrite sensitive data.",
        "Use the organization's reviewed and sanitized database transfer process."
    ),
    rule_doc!(
        "ddev.sql.interactive",
        Deny,
        High,
        "sql",
        "Interactive SQL cannot be inspected before execution.",
        "Use one explicit read-only SQL statement."
    ),
    rule_doc!(
        "sql.ambiguous",
        Deny,
        High,
        "sql",
        "SQL is malformed, unsupported, or exceeds analysis limits.",
        "Use a single explicit read-only SELECT, SHOW, EXPLAIN, or DESCRIBE statement."
    ),
    rule_doc!(
        "sql.read.sensitive_table",
        Deny,
        High,
        "sql",
        "The query reads a configured sensitive table.",
        "Query a non-sensitive aggregate or request sanitized data."
    ),
    rule_doc!(
        "sql.mutation.insert",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.update",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.delete",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.drop",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.alter",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.truncate",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.replace",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.create",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Use reviewed Drupal APIs, configuration workflows, or migrations."
    ),
    rule_doc!(
        "sql.mutation.grant",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Have an authorized administrator manage database privileges."
    ),
    rule_doc!(
        "sql.mutation.revoke",
        Deny,
        Critical,
        "sql",
        "Mutating SQL is prohibited.",
        "Have an authorized administrator manage database privileges."
    ),
    rule_doc!(
        "git.force_push",
        Deny,
        High,
        "git",
        "Force-pushing can rewrite shared history.",
        "Push normally or have a developer coordinate the history rewrite."
    ),
    rule_doc!(
        "git.credential_config",
        Deny,
        High,
        "git",
        "Agent-driven credential configuration is prohibited.",
        "Have a developer configure credentials outside the agent session."
    ),
    rule_doc!(
        "git.write.review",
        Ask,
        Medium,
        "git",
        "Repository writes and pushes require approval.",
        "Request approval after summarizing the exact commit or push."
    ),
    rule_doc!(
        "composer.dependencies.modify",
        Ask,
        Medium,
        "composer",
        "Dependency changes require review.",
        "Request approval with the intended package and constraint changes."
    ),
    rule_doc!(
        "composer.scripts.execute",
        Ask,
        High,
        "composer",
        "Composer scripts execute project or dependency code.",
        "Request approval or use a read-only Composer command."
    ),
];

pub(crate) fn explain(rule_id: &str) -> Option<String> {
    RULE_DOCUMENTATION
        .iter()
        .find(|documentation| documentation.id == rule_id)
        .map(|documentation| {
            format!(
                "Rule: {}\nEffect: {}\nSeverity: {}\nCategory: {}\nReason: {}\nRemediation: {}",
                documentation.id,
                effect_name(documentation.effect),
                severity_name(documentation.severity),
                documentation.category,
                documentation.reason,
                documentation.remediation,
            )
        })
}

const fn effect_name(effect: DecisionEffect) -> &'static str {
    match effect {
        DecisionEffect::Allow => "allow",
        DecisionEffect::Ask => "ask",
        DecisionEffect::Deny => "deny",
    }
}

const fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
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
    fn a10_structured_sql_is_inspected_before_execution() {
        for (input, expected) in [
            (
                serde_json::json!({"query":"DELETE FROM node"}),
                DecisionEffect::Deny,
            ),
            (
                serde_json::json!({"arguments":{"sql":"SELECT * FROM users_field_data"}}),
                DecisionEffect::Deny,
            ),
            (
                serde_json::json!({"statement":"SELECT nid FROM node"}),
                DecisionEffect::Allow,
            ),
            (serde_json::json!({}), DecisionEffect::Deny),
        ] {
            let mut request = request("mcp_call", "README.md");
            request.tool.native_name = "mcp__db__query".to_owned();
            request.input = input;
            assert_eq!(evaluate(&request, None, None).unwrap().effect, expected);
        }
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
    fn a20_inert_writable_setting_is_rejected() {
        for kind in [PolicyKind::Organization, PolicyKind::Project] {
            for writable in [json!([]), json!(["**/custom/**"])] {
                let input = json!({"schema":3,"paths":{"writable":writable}});
                assert!(Policy::from_slice(&serde_json::to_vec(&input).unwrap(), kind).is_err());
            }
        }
    }

    #[test]
    fn r07_known_credential_stores_are_protected_without_key_extensions() {
        for path in [
            "/home/synthetic/.ssh/id_ed25519",
            "/home/synthetic/.ssh/id_rsa",
            "/home/synthetic/.aws/credentials",
            "/home/synthetic/.kube/config",
            "/home/synthetic/.docker/config.json",
            "/home/synthetic/.netrc",
            "/home/synthetic/.config/gcloud/application_default_credentials.json",
        ] {
            let decision = evaluate(&request("file_read", path), None, None).unwrap();
            assert_eq!(decision.effect, DecisionEffect::Deny);
            assert_eq!(decision.rule_id, "filesystem.secret.credential_store");
        }
        for path in [
            "/home/synthetic/.ssh/id_ed25519.pub",
            "/home/synthetic/.ssh/known_hosts",
            "/home/synthetic/.aws/config",
            "web/modules/custom/example/config.json",
        ] {
            assert_eq!(
                evaluate(&request("file_read", path), None, None)
                    .unwrap()
                    .effect,
                DecisionEffect::Allow
            );
        }
    }

    #[test]
    fn a20_design_policy_example_is_loadable() {
        let design = include_str!("../DESIGN.md");
        let section = design.split("## 14. Policy file schema").nth(1).unwrap();
        let example = section
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("```")
            .next()
            .unwrap();
        assert!(Policy::from_slice(example.as_bytes(), PolicyKind::Organization).is_ok());
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
    fn organization_and_project_can_add_sensitive_sql_table_patterns() {
        let organization = policy(
            &json!({"schema":1,"sql":{"sensitive_tables":["customer_payments", "customer__*"]}}),
            PolicyKind::Organization,
        );
        for command in [
            "drush sql:query 'SELECT * FROM customer_payments'",
            "drush sql:query 'SELECT * FROM customer__billing_address'",
            "drush sql:query 'SELECT * FROM site_customer__billing_address'",
        ] {
            let decision = evaluate(&shell_request(command), Some(&organization), None).unwrap();
            assert_eq!(decision.rule_id, "sql.read.sensitive_table", "{command}");
        }

        let decision = evaluate(
            &shell_request("drush sql:query 'SELECT * FROM customer_profile'"),
            Some(&organization),
            None,
        )
        .unwrap();
        assert_eq!(decision.effect, DecisionEffect::Allow);
    }

    #[test]
    fn sensitive_sql_table_patterns_reject_unsupported_globs() {
        for pattern in ["*", "customer?", "customer-[0-9]"] {
            let value = json!({"schema":1,"sql":{"sensitive_tables":[pattern]}});
            assert!(
                Policy::from_slice(
                    &serde_json::to_vec(&value).unwrap(),
                    PolicyKind::Organization
                )
                .is_err(),
                "{pattern} must be rejected"
            );
        }
    }

    #[test]
    fn result_scanning_configuration_is_versioned_and_bounded() {
        let valid = json!({
            "schema": 3,
            "result": {
                "secret_prefixes": ["org_live_"],
                "sensitive_fields": {"case_reference": "private_content"},
                "ip_addresses_are_personal": true
            }
        });
        let organization = policy(&valid, PolicyKind::Organization);
        let config = super::scan_config(Some(&organization), None);
        assert_eq!(config.secret_prefixes, ["org_live_"]);
        assert!(config.ip_addresses_are_personal);
        let project = policy(
            &json!({
                "schema": 3,
                "result": {"sensitive_fields": {"case_reference": "personal_data"}}
            }),
            PolicyKind::Project,
        );
        let layered = super::scan_config(Some(&organization), Some(&project));
        assert_eq!(
            layered.sensitive_fields["case_reference"],
            crate::model::SensitivityCategory::PrivateContent
        );
        assert!(
            Policy::from_slice(
                &serde_json::to_vec(&json!({"schema":2,"result":{"secret_prefixes":["x_"]}}))
                    .unwrap(),
                PolicyKind::Organization,
            )
            .is_err()
        );
        assert!(
            Policy::from_slice(
                &serde_json::to_vec(
                    &json!({"schema":3,"result":{"secret_prefixes":["bad prefix"]}})
                )
                .unwrap(),
                PolicyKind::Organization,
            )
            .is_err()
        );
    }
}
