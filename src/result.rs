//! Canonical Phase 15 result decisions.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::model::{ResultEffect, SensitivityCategory};

pub(crate) const RESULT_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Finding {
    pub(crate) detector_id: &'static str,
    pub(crate) category: SensitivityCategory,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) confidence: Confidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Confidence {
    Medium,
    High,
}

/// Machine-readable result inspection output. `content` is the only result
/// body and is absent for `block`; raw and sanitized bodies cannot coexist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ResultDecision {
    pub(crate) protocol: u16,
    pub(crate) decision: ResultEffect,
    pub(crate) rule_id: &'static str,
    pub(crate) categories: BTreeSet<SensitivityCategory>,
    pub(crate) findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content: Option<String>,
    pub(crate) reason: &'static str,
}

impl ResultDecision {
    pub(crate) fn allow(content: String) -> Self {
        Self {
            protocol: RESULT_PROTOCOL_VERSION,
            decision: ResultEffect::Allow,
            rule_id: "result.clean",
            categories: BTreeSet::new(),
            findings: Vec::new(),
            content: Some(content),
            reason: "No configured sensitive result class was detected.",
        }
    }

    pub(crate) fn sanitize(content: String, findings: Vec<Finding>) -> Self {
        let categories = findings.iter().map(|finding| finding.category).collect();
        Self {
            protocol: RESULT_PROTOCOL_VERSION,
            decision: ResultEffect::Sanitize,
            rule_id: "result.sensitive_output",
            categories,
            findings,
            content: Some(content),
            reason: "Sensitive result values were replaced before release.",
        }
    }

    pub(crate) fn block(rule_id: &'static str, reason: &'static str) -> Self {
        Self {
            protocol: RESULT_PROTOCOL_VERSION,
            decision: ResultEffect::Block,
            rule_id,
            categories: BTreeSet::from([SensitivityCategory::UnknownSensitive]),
            findings: Vec::new(),
            content: None,
            reason,
        }
    }
}

pub(crate) const fn placeholder(category: SensitivityCategory) -> &'static str {
    match category {
        SensitivityCategory::Credential => "[REDACTED:CREDENTIAL]",
        SensitivityCategory::Authentication => "[REDACTED:AUTHENTICATION]",
        SensitivityCategory::PersonalData => "[REDACTED:PERSONAL_DATA]",
        SensitivityCategory::FinancialData => "[REDACTED:FINANCIAL_DATA]",
        SensitivityCategory::CustomerData => "[REDACTED:CUSTOMER_DATA]",
        SensitivityCategory::PrivateContent => "[REDACTED:PRIVATE_CONTENT]",
        SensitivityCategory::OperationalSensitive => "[REDACTED:OPERATIONAL_SENSITIVE]",
        SensitivityCategory::UnknownSensitive => "[REDACTED:UNKNOWN_SENSITIVE]",
    }
}
