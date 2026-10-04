//! Versioned agent/tool interception capability declarations.
//!
//! These records describe security mechanics, not policy decisions. Phase 14
//! post-tool integrations are intentionally `observe_only`: they can update
//! metadata-only taint state for a later pre-tool decision, but make no claim
//! that an already-produced result was kept out of model context.

use serde::{Serialize, Serializer};

use crate::model::{Capability, InterceptionCapability};

pub(crate) const CAPABILITY_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Support {
    Yes,
    No,
}

impl Serialize for Support {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(matches!(self, Self::Yes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AdapterCapability {
    pub(crate) schema: u16,
    pub(crate) agent: &'static str,
    pub(crate) tool_category: Capability,
    pub(crate) interception: InterceptionCapability,
    pub(crate) pre_call_denial: Support,
    pub(crate) input_rewrite: Support,
    pub(crate) result_observation: Support,
    pub(crate) pre_context_output_replacement: Support,
    pub(crate) guarded_execution_support: Support,
    pub(crate) mcp_proxy_support: Support,
    pub(crate) pre_context_containment: Support,
    pub(crate) security_mode: &'static str,
    pub(crate) minimum_tested_version: &'static str,
}

const fn observed(
    agent: &'static str,
    tool_category: Capability,
    version: &'static str,
    guarded_execution_support: bool,
    mcp_proxy_support: bool,
) -> AdapterCapability {
    AdapterCapability {
        schema: CAPABILITY_SCHEMA_VERSION,
        agent,
        tool_category,
        interception: InterceptionCapability::ObserveOnly,
        pre_call_denial: Support::Yes,
        input_rewrite: Support::No,
        result_observation: Support::Yes,
        pre_context_output_replacement: Support::No,
        guarded_execution_support: if guarded_execution_support {
            Support::Yes
        } else {
            Support::No
        },
        mcp_proxy_support: if mcp_proxy_support {
            Support::Yes
        } else {
            Support::No
        },
        pre_context_containment: Support::No,
        security_mode: "pre_call_deny_and_post_observe",
        minimum_tested_version: version,
    }
}

pub(crate) const ADAPTER_CAPABILITIES: &[AdapterCapability] = &[
    observed("codex", Capability::ShellExecute, "0.160.0", true, false),
    observed("codex", Capability::FileRead, "0.160.0", false, false),
    observed("codex", Capability::FileWrite, "0.160.0", false, false),
    observed("codex", Capability::McpCall, "0.160.0", false, true),
    observed("codex", Capability::Unknown, "0.160.0", false, false),
    observed(
        "cursor",
        Capability::ShellExecute,
        "unverified",
        true,
        false,
    ),
    observed("cursor", Capability::FileRead, "unverified", false, false),
    observed("cursor", Capability::FileWrite, "unverified", false, false),
    observed("cursor", Capability::McpCall, "unverified", false, true),
    observed("cursor", Capability::Unknown, "unverified", false, false),
    observed("opencode", Capability::ShellExecute, "2.0.22", true, false),
    observed("opencode", Capability::FileRead, "2.0.22", false, false),
    observed("opencode", Capability::FileWrite, "2.0.22", false, false),
    observed("opencode", Capability::NetworkRead, "2.0.22", false, false),
    observed("opencode", Capability::McpCall, "2.0.22", false, true),
    observed("opencode", Capability::Unknown, "2.0.22", false, false),
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
            record.schema == CAPABILITY_SCHEMA_VERSION
                && record.pre_context_containment == super::Support::No
        }));
    }
}
