//! Developer-only benchmarks using the production modules, without a public API.
#![allow(dead_code)]
#[path = "../src/adapters/mod.rs"]
mod adapters;
#[path = "../src/analyzers/mod.rs"]
mod analyzers;
#[path = "../src/json.rs"]
mod json;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/paths.rs"]
mod paths;
#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/shell.rs"]
mod shell;

use std::error::Error;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use model::DecisionEffect;
use serde::Serialize;

const DEFAULT_POLICY: &[u8] = include_bytes!("../policy/default-policy.json");
const WARMUP: usize = 20;

#[derive(Serialize)]
struct Measurement {
    name: String,
    samples: usize,
    iterations_per_sample: usize,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    min_ns: u128,
    max_ns: u128,
}

fn summarize(name: &str, mut times: Vec<u128>, iterations: usize) -> Measurement {
    times.sort_unstable();
    // Nearest-rank percentiles; sample collection always supplies a nonempty vector.
    let percentile = |percent: usize| times[(times.len() * percent).div_ceil(100) - 1];
    Measurement {
        name: name.to_owned(),
        samples: times.len(),
        iterations_per_sample: iterations,
        p50_ns: percentile(50),
        p95_ns: percentile(95),
        p99_ns: percentile(99),
        min_ns: times[0],
        max_ns: times[times.len() - 1],
    }
}

fn measure<T>(
    name: &str,
    samples: usize,
    iterations: usize,
    mut operation: impl FnMut() -> Result<T, Box<dyn Error>>,
) -> Result<Measurement, Box<dyn Error>> {
    for _ in 0..WARMUP {
        black_box(operation()?);
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(operation()?);
        }
        times.push(start.elapsed().as_nanos() / iterations as u128);
    }
    Ok(summarize(name, times, iterations))
}

struct Options {
    binary: PathBuf,
    samples: usize,
    iterations: usize,
}

impl Options {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut args = std::env::args_os().skip(1);
        let mut binary = None;
        let mut samples = 200;
        let mut iterations = 10;
        while let Some(arg) = args.next() {
            let value = args.next().ok_or("benchmark argument requires a value")?;
            match arg.to_str() {
                Some("--binary") => binary = Some(std::fs::canonicalize(value)?),
                Some("--samples") => samples = value.to_str().ok_or("invalid samples")?.parse()?,
                Some("--iterations") => {
                    iterations = value.to_str().ok_or("invalid iterations")?.parse()?;
                }
                _ => {
                    return Err(
                        "usage: performance --binary PATH [--samples N] [--iterations N]".into(),
                    );
                }
            }
        }
        if !(1..=10_000).contains(&samples) || !(1..=10_000).contains(&iterations) {
            return Err("samples and iterations must be between 1 and 10000".into());
        }
        Ok(Self {
            binary: binary.ok_or("--binary is required; benchmark an optimized release binary")?,
            samples,
            iterations,
        })
    }
}

fn payload(cwd: &str, tool: &str, input: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "session_id": "synthetic-benchmark-session",
        "tool_use_id": "synthetic-benchmark-call",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input
    }))
    .expect("synthetic JSON values serialize")
}

fn process(
    binary: &Path,
    args: &[&str],
    input: &[u8],
) -> Result<(u128, std::process::Output), Box<dyn Error>> {
    let start = Instant::now();
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing child stdin")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    let elapsed = start.elapsed().as_nanos();
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("benchmark guard invocation failed; inspect configuration separately".into());
    }
    Ok((elapsed, output))
}

fn process_measurement(
    options: &Options,
    name: &str,
    args: &[&str],
    input: &[u8],
    expected: Option<&serde_json::Value>,
) -> Result<Measurement, Box<dyn Error>> {
    let mut times = Vec::with_capacity(options.samples);
    for index in 0..(WARMUP + options.samples) {
        let (elapsed, output) = process(&options.binary, args, input)?;
        if let Some(expected) = expected {
            let response: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if &response != expected {
                return Err("benchmark response differs from the expected decision".into());
            }
        } else if output.stdout.is_empty() {
            return Err("version response is empty".into());
        }
        if index >= WARMUP {
            times.push(elapsed);
        }
    }
    Ok(summarize(name, times, 1))
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    architecture: &'static str,
    kernel: String,
    wsl2: bool,
    cpu_model: String,
    logical_cpus: usize,
    memory: String,
    project_location: &'static str,
    binary_version: String,
    harness_profile: &'static str,
    harness_target: &'static str,
}

fn environment(cwd: &Path, version: String) -> Environment {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let memory = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    Environment {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        wsl2: kernel.to_ascii_lowercase().contains("wsl2"),
        kernel: kernel.trim().to_owned(),
        cpu_model: cpu
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "model name").then(|| value.trim().to_owned())
            })
            .unwrap_or_default(),
        logical_cpus: std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        memory: memory
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .unwrap_or_default()
            .to_owned(),
        project_location: if cwd.starts_with("/mnt/c") {
            "mnt-c"
        } else {
            "other (verify filesystem manually)"
        },
        binary_version: version,
        harness_target: env!("DAGUARD_BUILD_TARGET"),
        harness_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

#[derive(Serialize)]
struct Report {
    schema: u16,
    environment: Environment,
    warmup_per_case: usize,
    policy_bytes: usize,
    measurements: Vec<Measurement>,
}

type Workload = (
    &'static str,
    &'static str,
    serde_json::Value,
    DecisionEffect,
    &'static str,
);

fn workloads() -> [Workload; 7] {
    [
        (
            "trivial_allow",
            "Bash",
            serde_json::json!({"command": "git status"}),
            DecisionEffect::Allow,
            "default.no_matching_rule",
        ),
        (
            "path_allow",
            "Read",
            serde_json::json!({"file_path": "web/modules/custom/example/example.module"}),
            DecisionEffect::Allow,
            "default.no_matching_rule",
        ),
        (
            "path_deny",
            "Read",
            serde_json::json!({"file_path": "web/sites/default/settings.php"}),
            DecisionEffect::Deny,
            "drupal.secret.settings_php",
        ),
        (
            "ddev_drush",
            "Bash",
            serde_json::json!({"command": "ddev drush cr"}),
            DecisionEffect::Allow,
            "default.no_matching_rule",
        ),
        (
            "sql_read",
            "Bash",
            serde_json::json!({"command": "ddev drush sql:query 'SELECT nid FROM node_field_data LIMIT 10'"}),
            DecisionEffect::Allow,
            "default.no_matching_rule",
        ),
        (
            "sql_mutation",
            "Bash",
            serde_json::json!({"command": "ddev drush sql:query 'DELETE FROM node_field_data WHERE nid = 0'"}),
            DecisionEffect::Deny,
            "sql.mutation.delete",
        ),
        (
            "complex_shell",
            "Bash",
            serde_json::json!({"command": "git status && ddev exec bash -c 'drush status && composer validate' && git diff"}),
            DecisionEffect::Allow,
            "default.no_matching_rule",
        ),
    ]
}

fn measure_components(
    options: &Options,
    policy_path: &Path,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    measurements.push(measure(
        "policy.parse_validate",
        options.samples,
        options.iterations,
        || {
            Ok(policy::Policy::from_slice(
                black_box(DEFAULT_POLICY),
                policy::PolicyKind::Organization,
            )
            .map_err(|error| error.to_string())?)
        },
    )?);
    measurements.push(measure(
        "policy.load_validate",
        options.samples,
        options.iterations,
        || {
            Ok(
                policy::Policy::load(black_box(policy_path), policy::PolicyKind::Organization)
                    .map_err(|error| error.to_string())?,
            )
        },
    )?);
    measurements.push(measure("sql.analyze", options.samples, options.iterations, || {
        Ok(analyzers::sql::analyze(black_box("/* synthetic */ SELECT nid FROM node_field_data; DELETE FROM node_field_data WHERE nid = 0"), &[]))
    })?);
    measurements.push(measure(
        "shell.tokenize",
        options.samples,
        options.iterations,
        || {
            Ok(shell::tokenize(black_box(
                "git status && ddev exec bash -c 'drush status && composer validate' && git diff",
            ))
            .map_err(|error| error.to_string())?)
        },
    )?);
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = Options::parse()?;
    if cfg!(debug_assertions) {
        return Err("run the benchmark in the optimized release profile".into());
    }
    let cwd = std::env::current_dir()?;
    let cwd_text = cwd.to_str().ok_or("benchmark cwd must be UTF-8")?;
    let policy_path = cwd.join("policy/default-policy.json");
    // Use the exact shipped policy, and reject accidental edits to this workload.
    if std::fs::read(&policy_path)? != DEFAULT_POLICY {
        return Err("run from repository root with the shipped policy".into());
    }
    let organization = policy::Policy::from_slice(DEFAULT_POLICY, policy::PolicyKind::Organization)
        .map_err(|error| error.to_string())?;
    let policy_text = policy_path.to_str().ok_or("policy path must be UTF-8")?;
    let args = [
        "--adapter",
        "codex",
        "--event",
        "pre-tool",
        "--policy",
        policy_text,
    ];
    let (_, version) = process(&options.binary, &["version"], &[])?;
    let version = String::from_utf8(version.stdout)?;
    if !version.contains("profile: release") {
        return Err("--binary must select a release binary".into());
    }
    let mut measurements = vec![process_measurement(
        &options,
        "process.version",
        &["version"],
        &[],
        None,
    )?];
    for (name, tool, input, effect, rule) in workloads() {
        let input = payload(cwd_text, tool, &input);
        let request = adapters::codex::normalize(&input).map_err(|error| error.to_string())?;
        let decision = policy::evaluate(&request, Some(&organization), None)
            .map_err(|error| error.to_string())?;
        if decision.effect != effect || decision.rule_id != rule {
            return Err(
                format!("benchmark case {name} does not match its expected rule/effect").into(),
            );
        }
        let expected = serde_json::to_value(adapters::codex::render(&decision))?;
        measurements.push(process_measurement(
            &options,
            &format!("process.{name}"),
            &args,
            &input,
            Some(&expected),
        )?);
        measurements.push(measure(
            &format!("evaluate.{name}"),
            options.samples,
            options.iterations,
            || {
                Ok(
                    policy::evaluate(black_box(&request), Some(black_box(&organization)), None)
                        .map_err(|error| error.to_string())?,
                )
            },
        )?);
    }
    measure_components(&options, &policy_path, &mut measurements)?;
    let report = Report {
        schema: 1,
        environment: environment(&cwd, version),
        warmup_per_case: WARMUP,
        policy_bytes: DEFAULT_POLICY.len(),
        measurements,
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
    println!();
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("performance: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::summarize;

    #[test]
    fn synthetic_workloads_keep_their_expected_security_decisions() {
        let organization = super::policy::Policy::from_slice(
            super::DEFAULT_POLICY,
            super::policy::PolicyKind::Organization,
        )
        .unwrap();
        for (name, tool, input, effect, rule) in super::workloads() {
            let bytes = super::payload("/workspace/synthetic-project", tool, &input);
            let request = super::adapters::codex::normalize(&bytes).unwrap();
            let decision = super::policy::evaluate(&request, Some(&organization), None).unwrap();
            assert_eq!(decision.effect, effect, "{name}");
            assert_eq!(decision.rule_id, rule, "{name}");
        }
    }

    #[test]
    fn nearest_rank_percentiles_handle_unsorted_and_single_samples() {
        let result = summarize("test", vec![50, 10, 40, 20, 30], 1);
        assert_eq!(
            (result.p50_ns, result.p95_ns, result.min_ns, result.max_ns),
            (30, 50, 10, 50)
        );
        let result = summarize("single", vec![42], 10);
        assert_eq!((result.p50_ns, result.p95_ns, result.p99_ns), (42, 42, 42));
    }
}
