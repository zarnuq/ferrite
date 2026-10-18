use super::*;
use crate::{
    groups::{self, Mode},
    http::{self, Upstream},
    macros::{Extract, Macro, Step},
    session::Client,
};

fn client(macros: Vec<Macro>) -> Client {
    Client::new(Arc::default(), true, true).with_macros(macros)
}
fn rule(target: &Target, steps: Vec<Step>) -> Macro {
    Macro {
        validity: None,
        name: "fixture".into(),
        enabled: true,
        origin: target.url(),
        path_regex: "^/submit".into(),
        steps,
    }
}
fn step(target: &Target, path: &str, extract: Vec<Extract>) -> Step {
    Step {
        url: format!("{}{path}", target.url()),
        request: String::from_utf8(request(target, "GET", path, b"")).unwrap(),
        extract,
        expect_status: 200,
    }
}
fn extract(name: &str, pointer: &str) -> Extract {
    Extract {
        name: name.into(),
        regex: String::new(),
        json_pointer: pointer.into(),
        url_encode: false,
    }
}

#[tokio::test]
async fn macro_multi_step_extraction_and_cookie_rotation_are_sent_in_order() {
    let server = fixture(|raw| {
        let msg = Msg::parse(raw);
        let path = msg.first.split_whitespace().nth(1).unwrap();
        if path == "/token" {
            Reply::body(
                200,
                &[("Set-Cookie", "sid=one; Path=/")],
                br#"{"token":"a&b"}"#,
            )
        } else if path == "/next?token=a%26b" {
            assert_eq!(msg.header("cookie"), Some("sid=one"));
            Reply::body(
                200,
                &[("Set-Cookie", "sid=two; Path=/")],
                br#"{"nested":{"nonce":"final"}}"#,
            )
        } else {
            Reply::body(200, &[], b"done")
        }
    })
    .await;
    let mut first = extract("csrf", "/token");
    first.url_encode = true;
    let steps = vec![
        step(&server.target, "/token", vec![first]),
        step(
            &server.target,
            "/next?token={{csrf}}",
            vec![extract("nonce", "/nested/nonce")],
        ),
    ];
    let raw = request(
        &server.target,
        "POST",
        "/submit",
        b"csrf={{csrf}}&nonce={{nonce}}",
    );
    let (sent, result) = tokio::time::timeout(
        DEADLINE,
        client(vec![rule(&server.target, steps)]).send(&server.target, &raw, &Upstream::None),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap().status, 200);
    let msg = Msg::parse(&sent);
    assert_eq!(msg.body, b"csrf=a%26b&nonce=final");
    assert_eq!(msg.header("cookie"), Some("sid=two"));
    assert_eq!(
        msg.header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        msg.body.len()
    );
    assert_eq!(server.seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn macro_status_and_missing_extraction_fail_before_main_request() {
    for (status, pointer) in [(403, "/token"), (200, "/missing")] {
        let server = fixture(move |_| Reply::body(status, &[], br#"{"token":"x"}"#)).await;
        let rule = rule(
            &server.target,
            vec![step(
                &server.target,
                "/token",
                vec![extract("token", pointer)],
            )],
        );
        let raw = request(&server.target, "POST", "/submit", b"{{token}}");
        let (_, result) = client(vec![rule])
            .send(&server.target, &raw, &Upstream::None)
            .await;
        assert!(result.is_err());
        assert_eq!(
            server.seen.lock().unwrap().len(),
            1,
            "main request was sent after macro failure"
        );
    }
}

#[tokio::test]
async fn macros_do_not_run_for_disabled_rules_or_other_paths_or_origins() {
    let server = fixture(|_| Reply::body(200, &[], b"ok")).await;
    let mut active = rule(&server.target, vec![step(&server.target, "/token", vec![])]);
    for case in 0..3 {
        active.enabled = case != 0;
        active.origin = if case == 2 {
            "http://different.invalid".into()
        } else {
            server.target.url()
        };
        let path = if case == 1 { "/unrelated" } else { "/submit" };
        let (_, result) = client(vec![active.clone()])
            .send(
                &server.target,
                &request(&server.target, "GET", path, b""),
                &Upstream::None,
            )
            .await;
        assert_eq!(result.unwrap().status, 200);
    }
    assert_eq!(server.seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn regex_macro_extraction_reads_headers_and_decoded_body() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"token=body-token").unwrap();
    let compressed = encoder.finish().unwrap();
    let server = fixture(move |raw| {
        if Msg::parse(raw).first.contains("/token ") {
            Reply::body(
                200,
                &[("Content-Encoding", "gzip"), ("X-CSRF", "header-token")],
                &compressed,
            )
        } else {
            Reply::body(200, &[], b"ok")
        }
    })
    .await;
    let extracts = vec![
        Extract {
            name: "header".into(),
            regex: "(?i)x-csrf: ([^\\r\\n]+)".into(),
            json_pointer: String::new(),
            url_encode: false,
        },
        Extract {
            name: "body".into(),
            regex: "token=([a-z-]+)".into(),
            json_pointer: String::new(),
            url_encode: false,
        },
    ];
    let raw = request(&server.target, "POST", "/submit", b"{{header}}/{{body}}");
    let (sent, result) = client(vec![rule(
        &server.target,
        vec![step(&server.target, "/token", extracts)],
    )])
    .send(&server.target, &raw, &Upstream::None)
    .await;
    assert!(result.is_ok());
    assert_eq!(Msg::parse(&sent).body, b"header-token/body-token");
}

#[tokio::test]
async fn macro_step_cannot_contact_another_port_on_same_hostname() {
    let forbidden = fixture(|_| Reply::body(200, &[], b"should not run")).await;
    let server = fixture(|_| Reply::body(200, &[], b"ok")).await;
    let mut other = step(&forbidden.target, "/token", vec![]);
    other.expect_status = 0;
    let (_, result) = client(vec![rule(&server.target, vec![other])])
        .send(
            &server.target,
            &request(&server.target, "GET", "/submit", b""),
            &Upstream::None,
        )
        .await;
    assert!(result.is_err());
    assert!(forbidden.seen.lock().unwrap().is_empty());
    assert!(server.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn connection_modes_use_expected_number_of_tcp_connections() {
    for (mode, expected) in [
        (Mode::Sequence, 4),
        (Mode::Connection, 1),
        (Mode::Parallel, 4),
    ] {
        let server = fixture(|raw| Reply::body(200, &[], &Msg::parse(raw).body)).await;
        let requests: Vec<_> = (0..4)
            .map(|i| {
                request(
                    &server.target,
                    "POST",
                    &format!("/{i}"),
                    &[0, i, 255, b'\r', b'\n'],
                )
            })
            .collect();
        let results = tokio::time::timeout(
            DEADLINE,
            groups::send(server.target.clone(), requests, Upstream::None, mode),
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 4);
        for (i, result) in results {
            assert_eq!(
                Msg::parse(&result.unwrap().raw).body,
                [0, i as u8, 255, b'\r', b'\n']
            );
        }
        assert_eq!(server.connections.load(Ordering::SeqCst), expected);
    }
}

#[tokio::test]
async fn parallel_preparation_failure_does_not_complete_partial_requests() {
    let server = fixture(|_| Reply::body(200, &[], b"unexpected")).await;
    let requests = vec![request(&server.target, "GET", "/one", b""), Vec::new()];
    let results = tokio::time::timeout(
        DEADLINE,
        groups::send(
            server.target.clone(),
            requests,
            Upstream::None,
            Mode::Parallel,
        ),
    )
    .await
    .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|(_, r)| r.is_err()));
    assert!(server.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn closed_destination_returns_error_for_every_group_member() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let target = Target::from_url(&format!("http://{address}")).unwrap();
    for mode in [
        Mode::Sequence,
        Mode::Connection,
        Mode::Parallel,
        Mode::Http2,
    ] {
        let jobs = (0..3).map(|_| request(&target, "GET", "/", b"")).collect();
        let results = tokio::time::timeout(
            DEADLINE,
            groups::send(target.clone(), jobs, Upstream::None, mode),
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, r)| r.is_err()));
    }
}

#[tokio::test]
async fn raw_client_rejects_truncated_content_length_response() {
    let server = fixture(|_| Reply {
        bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort".to_vec(),
        close: true,
        split: None,
    })
    .await;
    let result = http::send(
        &server.target,
        &request(&server.target, "GET", "/", b""),
        &Upstream::None,
    )
    .await;
    assert!(
        result.is_err(),
        "truncated response was accepted as complete evidence"
    );
}

#[tokio::test]
async fn raw_client_rejects_incomplete_chunked_response() {
    let server = fixture(|_| Reply {
        bytes: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi".to_vec(),
        close: true,
        split: None,
    })
    .await;
    let result = http::send(
        &server.target,
        &request(&server.target, "GET", "/", b""),
        &Upstream::None,
    )
    .await;
    assert!(result.is_err(), "incomplete chunked body was accepted");
}

#[tokio::test]
async fn raw_client_handles_interim_response_and_binary_chunked_body() {
    let server=fixture(|_|Reply{bytes:b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n\x00\xffA\r\n0\r\n\r\n".to_vec(),close:true,split:None}).await;
    let response = http::send(
        &server.target,
        &request(&server.target, "GET", "/", b""),
        &Upstream::None,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(Msg::parse(&response.raw).decoded_body(), b"\x00\xffA");
}

#[tokio::test]
async fn head_response_completes_without_waiting_for_declared_body() {
    let server = fixture(|_| Reply {
        bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n".to_vec(),
        close: false,
        split: None,
    })
    .await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        http::send(
            &server.target,
            &request(&server.target, "HEAD", "/", b""),
            &Upstream::None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status, 200);
    assert!(Msg::parse(&response.raw).body.is_empty());
}

#[tokio::test]
async fn validity_checks_refresh_expired_session_once_then_reuse_login_and_extract_fresh_tokens() {
    let server = fixture(|raw| {
        let msg = Msg::parse(raw);
        let path = msg.first.split_whitespace().nth(1).unwrap();
        match path {
            "/session" if msg.header("cookie") == Some("sid=user") => {
                Reply::body(200, &[], br#"{"authenticated":true,"token":"fresh"}"#)
            }
            "/session" => Reply::body(200, &[], br#"{"authenticated":false}"#),
            "/login" => Reply::body(200, &[("Set-Cookie", "sid=user; Path=/")], b"logged in"),
            _ => {
                assert_eq!(msg.header("cookie"), Some("sid=user"));
                assert_eq!(msg.body, b"csrf=fresh");
                Reply::body(200, &[], b"done")
            }
        }
    })
    .await;
    let mut rule = rule(&server.target, vec![step(&server.target, "/login", vec![])]);
    rule.validity = Some(crate::macros::Validity {
        step: step(&server.target, "/session", vec![extract("csrf", "/token")]),
        expect_body_regex: r#""authenticated":true"#.into(),
    });
    let client = client(vec![rule]);
    let raw = request(&server.target, "POST", "/submit", b"csrf={{csrf}}");
    for _ in 0..2 {
        assert_eq!(
            client
                .send(&server.target, &raw, &Upstream::None)
                .await
                .1
                .unwrap()
                .status,
            200
        );
    }
    let seen = server.seen.lock().unwrap();
    let paths: Vec<_> = seen.iter().map(|r| Msg::parse(r).first).collect();
    assert_eq!(paths.iter().filter(|p| p.contains("/login ")).count(), 1);
    assert_eq!(paths.iter().filter(|p| p.contains("/session ")).count(), 3);
}

#[tokio::test]
async fn invalid_session_after_login_blocks_main_request_and_checks_cannot_cross_origin() {
    let server = fixture(|_| Reply::body(403, &[], b"logged out")).await;
    let mut rule = rule(&server.target, vec![]);
    let mut check = step(&server.target, "/session", vec![]);
    check.expect_status = 200;
    rule.validity = Some(crate::macros::Validity {
        step: check,
        expect_body_regex: String::new(),
    });
    let raw = request(&server.target, "GET", "/submit", b"");
    let error = client(vec![rule.clone()])
        .send(&server.target, &raw, &Upstream::None)
        .await
        .1
        .err()
        .unwrap();
    assert!(error.contains("still invalid"));
    assert_eq!(server.seen.lock().unwrap().len(), 2);
    rule.validity.as_mut().unwrap().step.url = "http://other.invalid/session".into();
    assert!(
        client(vec![rule])
            .send(&server.target, &raw, &Upstream::None)
            .await
            .1
            .err()
            .unwrap()
            .contains("origin")
    );
    assert_eq!(server.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn macro_login_and_token_substitution_preserve_binary_request_evidence() {
    let server = fixture(|raw| {
        if Msg::parse(raw).first.contains("/token ") {
            Reply::body(200, &[], br#"{"token":"fresh"}"#)
        } else {
            Reply::body(200, &[], b"done")
        }
    })
    .await;
    let rule = rule(
        &server.target,
        vec![step(
            &server.target,
            "/token",
            vec![extract("csrf", "/token")],
        )],
    );
    let client = client(vec![rule]);
    let raw = request(
        &server.target,
        "POST",
        "/submit",
        b"\0\xff{{csrf}}\xfe{{1337*1337}}",
    );
    let (sent, result) = client.send(&server.target, &raw, &Upstream::None).await;
    assert_eq!(result.unwrap().status, 200);
    let msg = Msg::parse(&sent);
    assert_eq!(msg.body, b"\0\xfffresh\xfe{{1337*1337}}");
    assert_eq!(
        msg.header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        msg.body.len()
    );
    let unmatched = request(
        &server.target,
        "POST",
        "/unmatched",
        b"\0\xff{{not_a_template}}\xfe",
    );
    assert_eq!(
        client
            .send(&server.target, &unmatched, &Upstream::None)
            .await
            .0,
        unmatched
    );
}
