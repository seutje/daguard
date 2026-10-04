//! Shared semantic analyzers.

pub(crate) mod composer;
pub(crate) mod ddev;
pub(crate) mod drush;
pub(crate) mod filesystem;
pub(crate) mod git;
pub(crate) mod network;
pub(crate) mod sql;

use crate::model::{Decision, DecisionEffect, Evidence, PROTOCOL_VERSION, PolicyLayer, Severity};

pub(crate) fn decision(
    effect: DecisionEffect,
    rule_id: &str,
    category: &str,
    reason: &str,
    severity: Severity,
) -> Decision {
    Decision {
        protocol: PROTOCOL_VERSION,
        effect,
        rule_id: rule_id.to_owned(),
        severity,
        category: category.to_owned(),
        reason: reason.to_owned(),
        policy_layer: PolicyLayer::BuiltIn,
        details: Evidence { matched_path: None },
    }
}
