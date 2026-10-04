//! Versioned agent/tool interception capability declarations.
//!
//! These records describe security mechanics, not policy decisions. Phase 14
//! post-tool integrations are intentionally `observe_only`: they can update
//! metadata-only taint state for a later pre-tool decision, but make no claim
//! that an already-produced result was kept out of model context.

use serde::Serialize;

use crate::model::{Capability, InterceptionCapability};

pub(crate) const CAPABILITY_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AdapterCapability {
    pub(crate) schema: u16,
    pub(crate) agent: &'static str,
    pub(crate) tool_category: Capability,
    pub(crate) interception: InterceptionCapability,
    pub(crate) pre_call_denial: bool,
    pub(crate) result_observation: bool,
    pub(crate) pre_context_containment: bool,
    pub(crate) minimum_tested_version: &'static str,
}

const fn observed(
    agent: &'static str,
    tool_category: Capability,
    version: &'static str,
) -> AdapterCapability {
    AdapterCapability {
        schema: CAPABILITY_SCHEMA_VERSION,
        agent,
        tool_category,
        interception: InterceptionCapability::ObserveOnly,
        pre_call_denial: true,
        result_observation: true,
        pre_context_containment: false,
        minimum_tested_version: version,
    }
}

pub(crate) const ADAPTER_CAPABILITIES: &[AdapterCapability] = &[
    observed("codex", Capability::ShellExecute, "0.160.0"),
    observed("codex", Capability::FileRead, "0.160.0"),
    observed("codex", Capability::FileWrite, "0.160.0"),
    observed("codex", Capability::McpCall, "0.160.0"),
    observed("codex", Capability::Unknown, "0.160.0"),
    observed("cursor", Capability::ShellExecute, "unverified"),
    observed("cursor", Capability::FileRead, "unverified"),
    observed("cursor", Capability::FileWrite, "unverified"),
    observed("cursor", Capability::McpCall, "unverified"),
    observed("cursor", Capability::Unknown, "unverified"),
    observed("opencode", Capability::ShellExecute, "2.0.22"),
    observed("opencode", Capability::FileRead, "2.0.22"),
    observed("opencode", Capability::FileWrite, "2.0.22"),
    observed("opencode", Capability::NetworkRead, "2.0.22"),
    observed("opencode", Capability::McpCall, "2.0.22"),
    observed("opencode", Capability::Unknown, "2.0.22"),
];

#[cfg(test)]
mod tests {
    use super::{ADAPTER_CAPABILITIES, CAPABILITY_SCHEMA_VERSION};

    #[test]
    fn capability_fixture_is_stable_and_never_claims_phase_15_containment() {
        let actual = serde_json::to_value(ADAPTER_CAPABILITIES).unwrap();
        let expected: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/adapter_capabilities.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
        assert!(ADAPTER_CAPABILITIES.iter().all(|record| {
            record.schema == CAPABILITY_SCHEMA_VERSION && !record.pre_context_containment
        }));
    }
}
