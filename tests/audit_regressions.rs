//! Synthetic audit regressions. Proposed commands are classified, never executed.
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn check(command: &str) -> String {
    let input = json!({"protocol":1,"agent":"fixture","event":"pre_tool_use",
        "cwd":"/workspace/project","tool":{"native_name":"shell","capability":"shell_execute"},
        "input":{},"facts":{"command":command}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .arg("check")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["decision"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn cases(inputs: &[(&str, &str)]) {
    for (command, expected) in inputs {
        assert_eq!(check(command), *expected, "{command}");
    }
}
#[test]
fn a01_effective_directory() {
    cases(&[
        ("cd web/sites/default && cat settings.php", "deny"),
        ("cd web/core && touch index.php", "deny"),
        ("cd web/core && echo ok > index.php", "deny"),
        ("bash -c 'cd web/sites/default && cat settings.php'", "deny"),
        ("cd web/modules/custom && touch example.php", "allow"),
        ("cd web/core || touch index.php", "deny"),
    ]);
}

#[test]
fn a02_shell_uncertainty() {
    cases(&[
        ("cat web/sites/default/settings.p?p", "deny"),
        ("cat web/sites/default/settings.[p]hp", "deny"),
        ("SECRET_PATH=.env; cat $SECRET_PATH", "deny"),
        ("( cat .env )", "deny"),
        ("if true; then cat .env; fi", "deny"),
        ("cat 'web/modules/custom/example.php'", "allow"),
        ("echo 'literal $text * [x]'", "allow"),
    ]);
}
