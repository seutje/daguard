//! Shared sensitivity taxonomy and metadata-only source classification.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::analyzers::{ddev, sql};
use crate::model::{CanonicalPostToolEvent, Capability, SensitivityCategory, merge_categories};
use crate::policy::{self, Policy, PolicyError};
use crate::shell;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SourceClassification {
    pub(crate) source_id: String,
    pub(crate) resource_kind: String,
    /// SHA-256 pseudonym only; never the resource path, query, or value.
    pub(crate) resource: String,
    pub(crate) categories: BTreeSet<SensitivityCategory>,
}

impl SourceClassification {
    /// Phase 15 detectors feed this constructor so they reuse the exact Phase
    /// 14 taxonomy. Sanitization or result blocking does not clear the record.
    #[allow(dead_code)]
    pub(crate) fn dynamic(
        detector_id: &str,
        categories: impl IntoIterator<Item = SensitivityCategory>,
    ) -> Self {
        Self {
            source_id: detector_id.to_owned(),
            resource_kind: "dynamic_detection".to_owned(),
            resource: "metadata-only".to_owned(),
            categories: categories.into_iter().collect(),
        }
    }
}

pub(crate) fn classify(
    event: &CanonicalPostToolEvent,
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Vec<SourceClassification>, PolicyError> {
    let request = event.as_request();
    classify_request(&request, organization, project)
}

pub(crate) fn classify_request(
    request: &crate::model::CanonicalRequest,
    organization: Option<&Policy>,
    project: Option<&Policy>,
) -> Result<Vec<SourceClassification>, PolicyError> {
    let mut paths = request
        .candidate_paths()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut sql_queries = Vec::new();
    for command in request.candidate_commands() {
        collect_shell_sources(command, &request.cwd, 0, &mut paths, &mut sql_queries);
    }
    if matches!(
        request.tool.capability,
        Capability::McpCall | Capability::Unknown
    ) {
        sql_queries.extend(
            request
                .candidate_queries()
                .map_err(|_| PolicyError::Invalid("invalid structured SQL input"))?
                .into_iter()
                .map(str::to_owned),
        );
    }

    let mut classifications = Vec::new();
    for path in paths {
        let Some(matched) =
            policy::classify_sensitive_path(&request.cwd, &path, organization, project)?
        else {
            continue;
        };
        let categories = categories_for_path_rule(&matched.source_id);
        merge_classification(
            &mut classifications,
            SourceClassification {
                source_id: matched.source_id,
                resource_kind: "file".to_owned(),
                resource: format!(
                    "sha256:{}",
                    crate::audit::sha256(matched.normalized_path.as_bytes())
                ),
                categories,
            },
        );
    }

    let configured = organization
        .into_iter()
        .chain(project)
        .flat_map(Policy::sensitive_tables)
        .collect::<Vec<_>>();
    for query in sql_queries {
        let Some(tables) = sql::referenced_sensitive_tables(&query, &configured) else {
            continue;
        };
        for table in tables {
            let categories = categories_for_table(&table);
            merge_classification(
                &mut classifications,
                SourceClassification {
                    source_id: "sql.read.sensitive_table".to_owned(),
                    resource_kind: "sql_table".to_owned(),
                    resource: format!("sha256:{}", crate::audit::sha256(table.as_bytes())),
                    categories,
                },
            );
        }
    }
    Ok(classifications)
}

fn categories_for_path_rule(source_id: &str) -> BTreeSet<SensitivityCategory> {
    use SensitivityCategory::{Authentication, Credential, OperationalSensitive, UnknownSensitive};
    match source_id {
        "drupal.secret.env" | "composer.secret.auth_json" => {
            BTreeSet::from([Credential, Authentication])
        }
        "drupal.secret.settings_php" => {
            BTreeSet::from([Credential, Authentication, OperationalSensitive])
        }
        "filesystem.secret.private_key" => BTreeSet::from([Credential, Authentication]),
        _ => BTreeSet::from([UnknownSensitive]),
    }
}

fn categories_for_table(table: &str) -> BTreeSet<SensitivityCategory> {
    use SensitivityCategory::{
        Authentication, Credential, CustomerData, FinancialData, OperationalSensitive,
        PersonalData, UnknownSensitive,
    };
    let unprefixed = known_suffix(table);
    if unprefixed == "sessions" {
        return BTreeSet::from([Credential, Authentication, PersonalData]);
    }
    if unprefixed == "flood" || unprefixed.starts_with("users") || unprefixed.starts_with("user__")
    {
        return BTreeSet::from([Credential, Authentication, PersonalData]);
    }
    if unprefixed.starts_with("commerce_payment") {
        return BTreeSet::from([FinancialData, CustomerData, PersonalData]);
    }
    if unprefixed.starts_with("commerce_order") || unprefixed.starts_with("commerce_shipment") {
        return BTreeSet::from([FinancialData, CustomerData, PersonalData]);
    }
    if unprefixed.starts_with("webform_submission")
        || unprefixed.starts_with("comment")
        || unprefixed.starts_with("profile")
    {
        return BTreeSet::from([CustomerData, PersonalData]);
    }
    if matches!(unprefixed, "watchdog" | "key_value" | "key_value_expire") {
        return BTreeSet::from([OperationalSensitive]);
    }
    BTreeSet::from([UnknownSensitive])
}

fn known_suffix(table: &str) -> &str {
    const PREFIXES: &[&str] = &[
        "sessions",
        "users",
        "user__",
        "flood",
        "commerce_payment",
        "commerce_order",
        "commerce_shipment",
        "webform_submission",
        "comment",
        "profile",
        "watchdog",
        "key_value",
    ];
    PREFIXES
        .iter()
        .filter_map(|prefix| table.find(prefix).map(|index| &table[index..]))
        .min_by_key(|suffix| suffix.len())
        .unwrap_or(table)
}

fn merge_classification(
    classifications: &mut Vec<SourceClassification>,
    classification: SourceClassification,
) {
    if let Some(existing) = classifications.iter_mut().find(|existing| {
        existing.source_id == classification.source_id
            && existing.resource_kind == classification.resource_kind
            && existing.resource == classification.resource
    }) {
        merge_categories(&mut existing.categories, classification.categories);
    } else {
        classifications.push(classification);
    }
}

fn collect_shell_sources(
    command: &str,
    cwd: &str,
    depth: usize,
    paths: &mut Vec<String>,
    queries: &mut Vec<String>,
) {
    if depth > 4 {
        return;
    }
    let Ok(tokens) = shell::tokenize(command) else {
        return;
    };
    let Ok(segments) = shell::contextual_segments(&tokens, cwd) else {
        return;
    };
    for (cwd, segment) in segments {
        let words = shell::words(segment);
        collect_argv_sources(&words, &cwd, depth, paths, queries);
    }
}

fn collect_argv_sources(
    words: &[&str],
    cwd: &str,
    depth: usize,
    paths: &mut Vec<String>,
    queries: &mut Vec<String>,
) {
    let Ok(words) = shell::normalize_argv(words) else {
        return;
    };
    let Some((program, args)) = words.split_first() else {
        return;
    };
    let program = program.rsplit('/').next().unwrap_or(program);
    if matches!(program, "sh" | "bash") {
        if let Some(position) = args
            .iter()
            .position(|arg| arg.starts_with('-') && arg.contains('c'))
            && let Some(inner) = args.get(position + 1)
        {
            collect_shell_sources(inner, cwd, depth + 1, paths, queries);
        }
        return;
    }
    if program == "ddev" {
        match ddev::unwrap(args) {
            ddev::Target::Nested(inner, cwd) if inner.len() == 1 => {
                collect_shell_sources(inner[0], cwd, depth + 1, paths, queries);
            }
            ddev::Target::Nested(inner, cwd) => {
                collect_argv_sources(inner, cwd, depth + 1, paths, queries);
            }
            ddev::Target::Drush(inner) => collect_drush_query(inner, queries),
            ddev::Target::Sql(query) => queries.push(query.to_owned()),
            ddev::Target::Safe | ddev::Target::Composer(_) | ddev::Target::Decision(_) => {}
        }
        return;
    }
    if program == "drush" {
        collect_drush_query(args, queries);
        return;
    }
    if program == "mysql" {
        if let Ok(query) = sql::client_query(args, false) {
            queries.push(query.to_owned());
        }
        return;
    }
    let candidates: &[&str] = match program {
        "cat" | "head" | "tail" | "less" | "more" | "sed" | "awk" | "wc" => args,
        "cp" | "mv" => &args[..args.len().saturating_sub(1)],
        _ => &[],
    };
    paths.extend(
        candidates
            .iter()
            .copied()
            .filter(|arg| !arg.starts_with('-'))
            .filter_map(|path| crate::paths::normalize(cwd, path).ok()),
    );
}

fn collect_drush_query(args: &[&str], queries: &mut Vec<String>) {
    let Ok(args) = crate::analyzers::drush::command_args(args) else {
        return;
    };
    if let [command, query] = args
        && matches!(*command, "sql:query" | "sql-query" | "sqlq")
    {
        queries.push((*query).to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::classify;
    use crate::model::{
        CanonicalPostToolEvent, Capability, Facts, PROTOCOL_VERSION, ResultMetadata, ResultStatus,
        SensitivityCategory, Tool,
    };

    fn event(command: &str) -> CanonicalPostToolEvent {
        CanonicalPostToolEvent {
            protocol: PROTOCOL_VERSION,
            agent: "codex".to_owned(),
            event: "post_tool_use".to_owned(),
            session_id: Some("synthetic".to_owned()),
            call_id: Some("synthetic-call".to_owned()),
            cwd: "/workspace/project".to_owned(),
            tool: Tool {
                native_name: "Bash".to_owned(),
                capability: Capability::ShellExecute,
            },
            input: serde_json::json!({}),
            facts: Facts {
                command: Some(command.to_owned()),
                ..Facts::default()
            },
            result: ResultMetadata {
                status: ResultStatus::Completed,
                content_type: Some("text/plain".to_owned()),
                byte_size: Some(10),
            },
        }
    }

    #[test]
    fn classifies_ddev_sql_and_settings_without_content() {
        let settings = classify(
            &event("ddev exec cat web/sites/default/settings.php"),
            None,
            None,
        )
        .unwrap();
        assert!(
            settings[0]
                .categories
                .contains(&SensitivityCategory::Credential)
        );
        let sql = classify(
            &event("ddev drush sql:query 'SELECT * FROM commerce_payment'"),
            None,
            None,
        )
        .unwrap();
        assert!(
            sql[0]
                .categories
                .contains(&SensitivityCategory::FinancialData)
        );
    }

    #[test]
    fn project_protected_paths_become_unknown_sensitive_sources() {
        let project = crate::policy::Policy::from_slice(
            br#"{"schema":1,"paths":{"deny_read":["**/private/**"]}}"#,
            crate::policy::PolicyKind::Project,
        )
        .unwrap();
        let mut event = event("git status");
        event.tool.capability = Capability::FileRead;
        event.facts.command = None;
        event.facts.paths = vec!["private/customer-export.txt".to_owned()];
        let classifications = classify(&event, None, Some(&project)).unwrap();
        assert_eq!(classifications[0].source_id, "project.path.deny_read");
        assert!(
            classifications[0]
                .categories
                .contains(&SensitivityCategory::UnknownSensitive)
        );
    }
}
