//! Integration tests for the binary.

use assert_cmd::Command;
use predicates::prelude::*;

const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const HS256_SECRET: &str = "your-256-bit-secret";

fn cmd() -> Command {
    Command::cargo_bin("jwt-tui").unwrap()
}

#[test]
fn decode_pretty_outputs_header_and_payload() {
    cmd()
        .args(["decode", HS256_TOKEN])
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"))
        .stdout(predicate::str::contains("John Doe"));
}

#[test]
fn decode_json_emits_valid_json() {
    let out = cmd()
        .args(["decode", HS256_TOKEN, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["header"]["alg"], "HS256");
    assert_eq!(v["payload"]["sub"], "1234567890");
}

#[test]
fn sign_verify_round_trip_hs256() {
    let token = cmd()
        .args([
            "sign",
            "--alg",
            "HS256",
            "--secret",
            "the-secret",
            "--payload",
            r#"{"sub":"a","exp":99999999999}"#,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let token = String::from_utf8(token).unwrap().trim().to_owned();
    cmd()
        .args(["verify", &token, "--secret", "the-secret"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
    cmd()
        .args(["verify", &token, "--secret", "wrong"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("INVALID"));
}

#[test]
fn verify_rfc_example_works() {
    cmd()
        .args(["verify", HS256_TOKEN, "--secret", HS256_SECRET])
        .assert()
        .success();
}

#[test]
fn lab_attacks_require_lab_flag() {
    cmd()
        .args(["attack", "alg-none", HS256_TOKEN])
        .assert()
        .failure()
        .stderr(predicate::str::contains("lab"));
}

#[test]
fn alg_none_forge_strips_signature() {
    let out = cmd()
        .args(["--lab", "attack", "alg-none", HS256_TOKEN])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let token = String::from_utf8(out).unwrap();
    assert!(token.trim().ends_with('.'));
}

#[test]
fn kid_templates_print_all_classes() {
    let out = cmd()
        .args(["--lab", "attack", "kid"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("Path traversal"));
    assert!(s.contains("SQL injection"));
    assert!(s.contains("Command injection"));
}

#[test]
fn jar_add_list_show_remove_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    // Force the jar into a tmp data dir so we don't pollute real ~/.local/share.
    let env_key = "JWT_TUI_DATA_DIR";
    let _add = cmd()
        .env(env_key, dir.path())
        .args([
            "jar",
            "add",
            HS256_TOKEN,
            "--label",
            "rfc-sample",
            "--tag",
            "demo",
        ])
        .assert()
        .success();
    cmd()
        .env(env_key, dir.path())
        .args(["jar", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rfc-sample"));
    cmd()
        .env(env_key, dir.path())
        .args(["jar", "show", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains(HS256_TOKEN));
    cmd()
        .env(env_key, dir.path())
        .args(["jar", "remove", "1"])
        .assert()
        .success();
}

#[test]
fn manpage_generation_succeeds() {
    cmd()
        .args(["manpage"])
        .assert()
        .success()
        .stdout(predicate::str::contains("jwt").and(predicate::str::contains("SUBCOMMANDS")));
}

#[test]
fn completions_zsh_succeeds() {
    cmd()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef"));
}

#[test]
fn decode_via_stdin_works() {
    cmd()
        .arg("decode")
        .write_stdin(HS256_TOKEN)
        .assert()
        .success()
        .stdout(predicate::str::contains("HS256"));
}
