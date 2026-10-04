//! Synthetic audit regressions. Proposed commands are classified, never executed.
use serde_json::{Value, json};
use std::fmt::Write as _;
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

#[test]
fn a03_transparent_wrappers() {
    cases(&[
        ("timeout 5 cat .env", "deny"),
        ("busybox cat .env", "deny"),
        ("env -C web/sites/default cat settings.php", "deny"),
        ("env --split-string='cat .env'", "deny"),
        ("nice -n 5 timeout --signal TERM 5 cat .env", "deny"),
        ("timeout 5 git status", "allow"),
        ("env -i NAME=value command git diff", "allow"),
        ("busybox cat web/modules/custom/example.php", "allow"),
    ]);
}

#[test]
fn a04_ddev_context() {
    cases(&[
        ("ddev . sudo true", "deny"),
        ("ddev exec --service web drush ev 1", "deny"),
        (
            "ddev exec --dir /var/www/html/web/core touch index.php",
            "deny",
        ),
        ("ddev exec touch modules/contrib/example/file.php", "deny"),
        ("ddev delete -Oy", "deny"),
        (
            "ddev exec --dir /var/www/html/docroot touch modules/contrib/example/file.php",
            "deny",
        ),
        ("ddev stop --remove-data -y", "deny"),
        ("ddev snapshot restore --latest", "deny"),
        ("ddev unknown-custom-command", "deny"),
        (
            "ddev exec --service web --dir /var/www/html/web/modules/custom touch example.php",
            "allow",
        ),
        ("ddev start", "allow"),
        ("ddev describe", "allow"),
        ("ddev stop", "allow"),
        ("ddev . drush cr", "allow"),
    ]);
}

#[test]
fn a05_filesystem_effects() {
    cases(&[
        ("cp -t web/core README.md", "deny"),
        ("cp -tweb/core README.md", "deny"),
        ("cp -r /tmp/core web", "deny"),
        ("cp --target-directory=web/core README.md", "deny"),
        ("mv web/core/index.php /tmp/file", "deny"),
        ("rm -rf web", "deny"),
        ("mv web /tmp/web", "deny"),
        ("curl -o web/core/index.php https://example.test", "deny"),
        ("wget -Oweb/core/index.php https://example.test", "deny"),
        ("cp -t web/modules/custom README.md", "allow"),
        (
            "mv web/modules/custom/example.php /tmp/example.php",
            "allow",
        ),
        ("rm -rf web/modules/custom/example", "allow"),
        (
            "curl -o web/modules/custom/example.php https://example.test",
            "allow",
        ),
    ]);
}

#[test]
fn a06_bulk_and_historical_reads() {
    cases(&[
        ("rg --hidden --no-ignore secret .", "deny"),
        ("rg secret", "deny"),
        ("grep -r secret web", "deny"),
        ("git show HEAD:web/sites/default/settings.php", "deny"),
        ("git -C web show HEAD:sites/default/settings.php", "deny"),
        ("git cat-file -p HEAD:.env", "deny"),
        ("git show HEAD:web/modules/custom/example.module", "allow"),
        ("rg secret web/modules/custom/example.module", "allow"),
        ("git status", "allow"),
        ("git diff", "allow"),
    ]);
}

#[test]
fn a06_filtered_search_preserves_protections() {
    let patterns = [
        "**/.env",
        "**/.env.*",
        "**/auth.json",
        "**/composer-auth.json",
        "**/sites/*/settings.php",
        "**/sites/*/settings.local.php",
        "**/env/**/settings.php",
        "**/env/**/settings.local.php",
        "**/*.pem",
        "**/*.key",
    ];
    let mut flags = String::new();
    for pattern in patterns {
        write!(flags, " -g '!{pattern}'").unwrap();
    }
    assert_eq!(check(&format!("rg secret .{flags}")), "allow");
    assert_eq!(check(&format!("rg secret .{flags} -g '*.php'")), "deny");
    assert_eq!(check(&format!("rg -L secret .{flags}")), "deny");
}

#[test]
fn a07_command_options() {
    cases(&[
        ("drush --root web sql:query 'DELETE FROM node'", "deny"),
        ("ddev drush --root web sql:query 'DELETE FROM node'", "deny"),
        ("composer --working-dir . install", "ask"),
        ("ddev composer -d . install", "ask"),
        ("mysql --execute='DELETE FROM node'", "deny"),
        ("mysql -e'DELETE FROM node'", "deny"),
        ("mysql -e 'SELECT 1' -e 'DELETE FROM node'", "deny"),
        ("mysql", "deny"),
        ("drush sql:query", "deny"),
        ("drush --root web sql:query 'SELECT nid FROM node'", "allow"),
        ("mysql --execute='SELECT 1'", "allow"),
        ("ddev mysql -e'SELECT 1'", "allow"),
        ("composer --working-dir . validate", "allow"),
    ]);
}
