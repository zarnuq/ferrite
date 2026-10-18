use super::*;
use crate::{
    extensions::{self, Check, Package, Script},
    http::Upstream,
    scanner::Severity,
};

fn script(code: &str) -> Package {
    Package {
        checks: vec![],
        scripts: vec![Script {
            name: "fixture".into(),
            enabled: true,
            origin: "http://example.test".into(),
            phase: "request".into(),
            command: vec!["python3".into(), "-c".into(), code.into()],
        }],
    }
}
const RAW: &[u8] = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";

#[test]
fn package_validation_rejects_invalid_regexes_and_empty_matchers() {
    for check in [
        Check {
            url_regex: "[".into(),
            response_regex: "ok".into(),
            ..Default::default()
        },
        Check {
            response_regex: "[".into(),
            ..Default::default()
        },
        Check::default(),
    ] {
        assert!(
            Package {
                checks: vec![check],
                scripts: vec![]
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn package_validation_enforces_counts_and_script_phase() {
    let valid = Check {
        name: "fixture".into(),
        status: 200,
        ..Default::default()
    };
    assert!(
        Package {
            checks: vec![valid; 201],
            scripts: vec![]
        }
        .validate()
        .is_err()
    );
    let mut package = script("print('unused')");
    package.scripts[0].phase = "other".into();
    assert!(package.validate().is_err());
    package.scripts[0].phase = "request".into();
    package.scripts[0].command.clear();
    assert!(package.validate().is_err());
}

#[tokio::test]
async fn disabled_wrong_phase_and_other_origin_scripts_are_not_executed() {
    for case in 0..4 {
        let mut package = script("raise RuntimeError('must not execute')");
        match case {
            0 => package.scripts[0].enabled = false,
            1 => package.scripts[0].phase = "response".into(),
            2 => package.scripts[0].origin = "https://example.test".into(),
            _ => package.scripts[0].origin = "http://example.test:9000".into(),
        }
        assert_eq!(
            extensions::hooks(&package, "request", "http://example.test/", RAW.to_vec())
                .await
                .unwrap(),
            RAW
        );
    }
}

#[tokio::test]
async fn hook_round_trip_preserves_binary_bytes() {
    let package = script(
        "import sys,json;v=json.load(sys.stdin);assert v['version']==1;assert v['phase']=='request';print(json.dumps({'raw_base64':v['raw_base64']}))",
    );
    let raw = [RAW, b"\x00\xff\xfe\r\n"].concat();
    assert_eq!(
        extensions::hooks(&package, "request", "http://example.test/", raw.clone())
            .await
            .unwrap(),
        raw
    );
}

#[tokio::test]
async fn hook_rejects_nonzero_exit_malformed_json_missing_output_and_invalid_base64() {
    for code in [
        "import sys;sys.exit(3)",
        "print('not json')",
        "print('{}')",
        "print('{\"raw_base64\":\"!!!\"}')",
    ] {
        let error = extensions::hooks(
            &script(code),
            "request",
            "http://example.test/",
            RAW.to_vec(),
        )
        .await
        .err()
        .expect("invalid hook output was accepted");
        assert!(
            !error.contains("timed out"),
            "invalid-output test was masked by an unrelated timeout: {code}"
        );
    }
}

#[tokio::test]
async fn hook_timeout_is_bounded_and_does_not_block_the_runtime() {
    let package = script("import time;time.sleep(30)");
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        extensions::hooks(&package, "request", "http://example.test/", RAW.to_vec()),
    )
    .await
    .unwrap();
    assert!(result.err().unwrap().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn hook_output_size_is_bounded() {
    let package = script("import sys;sys.stdout.write('x'*3000000)");
    let result = tokio::time::timeout(
        DEADLINE,
        extensions::hooks(&package, "request", "http://example.test/", RAW.to_vec()),
    )
    .await
    .unwrap();
    assert!(result.err().unwrap().contains("2 MiB"));
}

#[test]
fn passive_check_requires_enable_scope_status_and_decoded_match() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"fixture-secret").unwrap();
    let body = encoder.finish().unwrap();
    let response = Reply::body(200, &[("Content-Encoding", "gzip")], &body).bytes;
    let mut package = Package {
        checks: vec![Check {
            name: "fixture".into(),
            enabled: true,
            url_regex: r"^https://example\.test/".into(),
            response_regex: "fixture-secret".into(),
            status: 200,
            severity: Some(Severity::High),
            ..Default::default()
        }],
        scripts: vec![],
    };
    assert_eq!(
        extensions::passive(&package, "https://example.test/", RAW, &response).len(),
        1
    );
    assert!(
        extensions::passive(&package, "https://example.test.attacker/", RAW, &response).is_empty()
    );
    package.checks[0].status = 403;
    assert!(extensions::passive(&package, "https://example.test/", RAW, &response).is_empty());
    package.checks[0].status = 200;
    package.checks[0].enabled = false;
    assert!(extensions::passive(&package, "https://example.test/", RAW, &response).is_empty());
}

#[tokio::test]
async fn differential_active_checks_suppress_matches_already_in_baseline() {
    for baseline_match in [true, false] {
        let server = fixture(move |raw| {
            let probe = Msg::parse(raw).first.contains("/probe ");
            Reply::body(
                200,
                &[],
                if probe || baseline_match {
                    b"fixture-secret"
                } else {
                    b"clean"
                },
            )
        })
        .await;
        let package = Package {
            checks: vec![Check {
                name: "differential".into(),
                enabled: true,
                url_regex: ".*".into(),
                request: "GET /probe HTTP/1.1\r\nHost: {{host}}\r\nConnection: close\r\n\r\n"
                    .into(),
                response_regex: "fixture-secret".into(),
                status: 200,
                differential: true,
                ..Default::default()
            }],
            scripts: vec![],
        };
        let (tx, rx) = std::sync::mpsc::channel();
        extensions::active(
            package,
            server.target.clone(),
            request(&server.target, "GET", "/baseline", b""),
            crate::session::Client::new(Arc::default(), false, false),
            Upstream::None,
            tx,
            eframe::egui::Context::default(),
        )
        .await;
        let issues = rx
            .try_iter()
            .filter(|e| matches!(e, crate::Event::Issue(..)))
            .count();
        assert_eq!(issues, usize::from(!baseline_match));
        assert_eq!(server.seen.lock().unwrap().len(), 2);
    }
}
