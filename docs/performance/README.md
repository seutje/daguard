# Performance methodology

The developer-only Rust example measures the packaged guard and reuses the exact
production parser/analyzer modules for component measurements. It adds no crate
or workstation runtime dependency. Run from the repository root on the WSL
Linux filesystem with an optimized `x86_64-unknown-linux-musl` binary and harness:

```bash
cargo build --locked --release --target x86_64-unknown-linux-musl --bin daguard
cargo build --locked --release --target x86_64-unknown-linux-musl --example performance
target/x86_64-unknown-linux-musl/release/examples/performance \
  --binary target/x86_64-unknown-linux-musl/release/daguard \
  --samples 1000 --iterations 10 > /tmp/daguard-performance.json
```

These are contributor commands, not installation instructions. Prefer the CI
release binary for release acceptance. `--binary` can select an extracted release
binary; the harness rejects binaries whose version reports a non-release profile.
Use the same Rust target for the harness and guard. Set the build identity
variables documented in the release workflow when building a local reference;
otherwise `version` honestly reports unknown provenance fields.

## What is timed

- `process.version`: launch through completion of version output.
- `process.trivial_allow`: Codex hook parsing, loading/validating the shipped
  organization policy, analyzing `git status`, and rendering native allow.
- `process.path_allow` / `process.path_deny`: custom module read and multisite
  settings denial, including lexical normalization and policy checks.
- `process.ddev_drush`: safe `ddev drush cr` classification.
- `process.sql_read` / `process.sql_mutation`: safe SQL read and mutation denial
  through DDEV/Drush wrappers.
- `process.complex_shell`: chained commands with nested DDEV/Bash/Drush/Composer.
- `evaluate.*`: shared-core evaluation of the same already-normalized requests
  with already-parsed policy; this excludes startup, deserialization, and I/O.
- `policy.parse_validate`: policy deserialization, preflight, schema validation,
  and pattern validation. `policy.load_validate` adds bounded disk reading.
- `sql.analyze` / `shell.tokenize`: direct production analyzer/tokenizer calls.

The harness launches only the guard; it never executes proposed Git, DDEV,
Drush, shell, or SQL operations. All requests are synthetic and contain no file
contents or secrets. It checks each workload's expected effect and rule ID, then
compares every process response to the expected native response. Errors abort
rather than becoming fast successful samples. The benchmark does not change
policy, adapters, rules, or audit behavior.

`Instant` wall-clock timing surrounds launch, stdin delivery, stdout/stderr pipe
collection, and process completion. Response verification occurs after timing.
Each process case has 20 discarded warmups and one invocation per sample.
Component cases have 20 discarded operations and then timed batches of
`--iterations` operations; each sample is batch elapsed time divided by batch
size. Inputs/results use `black_box`, and result destruction is included.

Schema 1 reports integer **nanoseconds**: P50/P95/P99 use nearest-rank
percentiles of sorted samples; min/max show spread. Component percentiles are
percentiles of batch averages, not individual-operation tail latency. Nanosecond
units avoid rounding sub-microsecond work to zero; they do not imply that the
clock or hardware has nanosecond accuracy. Results include sample counts, policy
size, safe hardware metadata, and the binary's build identity. Reports omit
hostnames, usernames, raw payloads, and absolute local paths.

## Workload and acceptance limits

This is a warm-cache baseline for the 879-byte shipped policy, with organization
policy explicitly passed and no project policy, audit log, or `--managed` trust
checks. Larger team policies, audit I/O, managed path checks, host hook overhead,
cold disk caches, other adapters, and Windows security scanning can change
latency. Benchmark those deployment configurations before accepting them; do not
extrapolate these measurements to all input sizes or environments.

Keep the design targets unchanged until team review: startup/trivial allow
P50 <5 ms and P95 <15 ms; normal evaluation P50 <10 ms and P95 <25 ms; complex
shell P95 <50 ms. Compare these budgets to the **process** results, which include
loading policy on every invocation. Team budget and representative-hardware
approval are separate from collecting local evidence.

The optional `/mnt/c` comparison was not run. To compare, use an authorized
checkout and executable/policy on that filesystem, rerun from its repository
root, and record the filesystem with `df -T .`. Do not copy sensitive real
projects into benchmark fixtures.

## Regression monitoring

PR and release CI build the optimized musl guard and harness, run 200 samples
per case, verify decisions, and retain versioned JSON artifacts for review.
Invalid decisions or invocation failures fail CI; timing does not gate shared
runners. Download artifacts from the Actions run to compare the same workload,
policy size, Rust version, target, and hardware. Changing any of these requires
a new baseline. Do not compare component times to process times.

Treat a repeated >20% increase in P50 or P95 on matched, quiet hardware as a
signal to investigate, not an automatic security or release decision. Run at
least three sequential repetitions, avoid simultaneous builds/benchmarks, and
look at spread before attributing a change to code. Reproduce CI timing changes
on representative WSL hardware. Profile a reproduced hotspot before optimizing;
this phase adds no cache, persistent daemon, or startup integrity hashing.

## Local WSL baseline — 2026-10-03

[Raw report](wsl2-linux-2026-10-03.json) records 1,000 samples per case,
20 discarded warmups, and 10 operations per component batch. The guard and
harness both use the musl release target. Hardware is Intel Core Ultra 7 265H,
with 4 logical CPUs available to WSL and about 8 GB WSL memory; kernel is
`5.15.167.4-microsoft-standard-WSL2`. `df -T .` confirmed ext4 on `/dev/sdc`
for the repository, policy, harness, and binary. No simultaneous build or
benchmark ran during the retained measurement; warmups populate filesystem
caches. Host power/thermal state and Windows background activity were not
controlled.

The report's Git identity is the pre-change commit: this phase changes developer
benchmarking and documentation, not production guard sources or policy.

| Process workload | P50 (ms) | P95 (ms) | P99 (ms) |
| --- | ---: | ---: | ---: |
| process.version | 0.155 | 0.317 | 0.722 |
| process.trivial_allow | 1.324 | 1.710 | 3.057 |
| process.path_allow | 2.110 | 2.919 | 4.325 |
| process.path_deny | 1.574 | 1.914 | 3.580 |
| process.ddev_drush | 1.319 | 1.669 | 3.021 |
| process.sql_read | 1.330 | 1.653 | 3.253 |
| process.sql_mutation | 1.323 | 1.590 | 3.038 |
| process.complex_shell | 1.339 | 1.649 | 2.961 |

All measured process workloads meet the proposed design targets. Policy
load/validation costs about 0.57 ms P50 and 0.76 ms P95 in the component benchmark.
These component timings locate work for future profiling; they are not additive
estimates of full process latency. No performance optimization was warranted.
Team approval of the budgets and this machine's representativeness is pending;
local results alone do not complete Phase 9 acceptance.

## Invocation cost review

The normal hook path in `src/cli.rs` reads only explicit bounded request/policy
inputs and an optional configured audit destination. `policy::evaluate` and its
analyzers operate in process: no subprocess, network connection, directory
enumeration, project-content scan, or file-content hashing. Project marker
inspection and binary/policy integrity hashing belong to operator diagnostics,
not ordinary evaluation. Audit identifiers are bounded and hashed when logging
is enabled; this is distinct from hashing large files at every hook.

Policy parsing and pattern matching remain uncached. The local measurements do
not justify changing the security model or adding a daemon. Required formatting,
Clippy, unit/integration/golden tests, and static linkage checks remain the
correctness gates.
