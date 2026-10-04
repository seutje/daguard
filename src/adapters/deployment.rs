//! Native deployment configuration translated into bounded guard bindings.
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

pub(crate) struct Binding {
    pub(crate) binary: PathBuf,
    pub(crate) policy: PathBuf,
    pub(crate) state: Option<PathBuf>,
    pub(crate) managed: bool,
    pub(crate) bridge: Option<PathBuf>,
}

pub(crate) fn bindings(bytes: &[u8], adapter: &str) -> Result<Vec<Binding>, &'static str> {
    crate::json::preflight(bytes, crate::json::MAX_REQUEST_BYTES)
        .map_err(|_| "invalid or unbounded integration configuration")?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "invalid configuration")?;
    let mut bindings = Vec::new();
    if adapter == "opencode" {
        for plugin in value
            .get("plugins")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(options) = plugin.get("options") else {
                continue;
            };
            let Some(guard) = options.get("guard").and_then(Value::as_str) else {
                continue;
            };
            let policy = options
                .get("policy")
                .and_then(Value::as_str)
                .ok_or("missing policy binding")?;
            let package = plugin
                .get("package")
                .and_then(Value::as_str)
                .ok_or("missing bridge binding")?;
            if !super::is_daguard_executable(guard)
                || !literal_path(guard)
                || !literal_path(policy)
                || !literal_path(package)
            {
                return Err("guard, policy and bridge must be literal absolute paths");
            }
            let managed = options.get("managed").map_or(Ok(false), |value| {
                value.as_bool().ok_or("invalid managed mode")
            })?;
            let state = options
                .get("stateDir")
                .map(|value| {
                    value
                        .as_str()
                        .filter(|path| literal_path(path))
                        .map(PathBuf::from)
                        .ok_or("invalid state directory")
                })
                .transpose()?;
            bindings.push(Binding {
                binary: guard.into(),
                policy: policy.into(),
                state,
                managed,
                bridge: Some(package.into()),
            });
        }
    } else {
        collect_commands(&value, adapter, &mut bindings)?;
    }
    if bindings.is_empty() {
        return Err("no guard deployment bindings");
    }
    Ok(bindings)
}

fn collect_commands(
    value: &Value,
    adapter: &str,
    bindings: &mut Vec<Binding>,
) -> Result<(), &'static str> {
    match value {
        Value::Object(fields) => {
            if let Some(command) = fields.get("command").and_then(Value::as_str) {
                let tokens = super::command_tokens(command).ok_or("invalid hook command")?;
                if tokens
                    .first()
                    .is_some_and(|path| super::is_daguard_executable(path))
                {
                    if fields
                        .get("async")
                        .is_some_and(|value| value.as_bool() != Some(false))
                    {
                        return Err("guard hooks must be synchronous");
                    }
                    bindings.push(command_binding(&tokens, adapter)?);
                }
            }
            for child in fields.values() {
                collect_commands(child, adapter, bindings)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_commands(child, adapter, bindings)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn literal_path(path: &str) -> bool {
    crate::paths::is_absolute(path)
        && !path.contains(['$', '{', '}', '%', ';', '|', '&', '`', '\n'])
}

fn command_binding(tokens: &[String], adapter: &str) -> Result<Binding, &'static str> {
    let binary = tokens
        .first()
        .filter(|path| literal_path(path))
        .ok_or("invalid guard path")?;
    let mut binding = Binding {
        binary: binary.into(),
        policy: PathBuf::new(),
        state: None,
        managed: false,
        bridge: None,
    };
    let mut seen = HashSet::new();
    let mut index = 1;
    while index < tokens.len() {
        let flag = tokens[index].as_str();
        if !seen.insert(flag) {
            return Err("duplicate hook option");
        }
        if flag == "--managed" {
            binding.managed = true;
            index += 1;
            continue;
        }
        let value = tokens.get(index + 1).ok_or("missing hook option value")?;
        match flag {
            "--adapter" if value == adapter => {}
            "--event" if matches!(value.as_str(), "pre-tool" | "post-tool") => {}
            "--policy" if literal_path(value) => binding.policy = value.into(),
            "--state-dir" if literal_path(value) => binding.state = Some(value.into()),
            "--project-policy" | "--audit-log" if literal_path(value) => {}
            _ => return Err("unsupported hook option, disabled session state or nonliteral path"),
        }
        index += 2;
    }
    if binding.policy.as_os_str().is_empty()
        || !seen.contains("--adapter")
        || !seen.contains("--event")
    {
        return Err("incomplete hook binding");
    }
    Ok(binding)
}
