use super::*;

fn message(body: &serde_json::Value) -> Msg {
    let body = serde_json::to_vec(body).unwrap();
    Msg {
        first: "POST /submit HTTP/1.1".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body,
    }
}

#[test]
fn nested_array_and_escaped_json_keys_generate_correct_insertion_points() {
    let msg = message(
        &serde_json::json!({"nested":{"users":[{"name":"alice","age":4}]},"a/b~c":"escaped","flag":true,"nothing":null}),
    );
    let names: Vec<_> = points(&msg).into_iter().map(|(_, name)| name).collect();
    assert!(names.contains(&"/nested/users/0/name".to_string()));
    assert!(names.contains(&"/nested/users/0/age".to_string()));
    assert!(names.contains(&"/a~1b~0c".to_string()));
    assert!(!names.contains(&"/flag".to_string()));
    assert!(!names.contains(&"/nothing".to_string()));
    let injected = Msg::parse(&inject(
        &msg,
        &Point::Json("/nested/users/0/name".into()),
        "<&",
        false,
    ));
    let body: serde_json::Value = serde_json::from_slice(&injected.body).unwrap();
    assert_eq!(body["nested"]["users"][0]["name"], "<&");
    assert_eq!(body["nested"]["users"][0]["age"], 4);
    assert_eq!(body["a/b~c"], "escaped");
    assert_eq!(
        injected
            .header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        injected.body.len()
    );
}

#[test]
fn json_insertion_point_budget_and_depth_are_bounded() {
    let values: Vec<_> = (0..1000).map(|i| serde_json::json!(i)).collect();
    assert_eq!(points(&message(&serde_json::json!(values))).len(), 200);
    let mut nested = serde_json::json!("leaf");
    for _ in 0..30 {
        nested = serde_json::json!({"child":nested});
    }
    assert!(points(&message(&nested)).is_empty());
}

#[test]
fn active_signatures_do_not_repeat_errors_already_present_in_baseline() {
    let raw=b"HTTP/1.1 500 Error\r\nContent-Type: text/html\r\n\r\nYou have an error in your SQL syntax";
    let response = Msg::parse(raw);
    assert!(analyse(Check::Sql, "canary", "clean baseline", &response, "id").is_some());
    assert!(
        analyse(
            Check::Sql,
            "canary",
            "You have an error in your SQL syntax",
            &response,
            "id"
        )
        .is_none()
    );
}

#[test]
fn multipart_and_header_injection_preserve_other_fields_and_binary_uploads() {
    let body=b"--bound\r\nContent-Disposition: form-data; name=\"first\"\r\n\r\nalice\r\n--bound\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.bin\"\r\n\r\n\x00\xffABC\r\n--bound\r\nContent-Disposition: form-data; name=\"second\"\r\n\r\nbob\r\n--bound--\r\n";
    let msg = Msg {
        first: "POST / HTTP/1.1".into(),
        headers: vec![
            (
                "Content-Type".into(),
                "multipart/form-data; boundary=bound".into(),
            ),
            ("User-Agent".into(), "fixture".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body: body.to_vec(),
    };
    let points = points(&msg);
    assert_eq!(points.len(), 3);
    let point = &points
        .iter()
        .find(|(_, n)| n == "multipart second")
        .unwrap()
        .0;
    let injected = Msg::parse(&inject(&msg, point, "payload<&", false));
    assert!(injected.body.windows(9).any(|w| w == b"payload<&"));
    assert!(injected.body.windows(5).any(|w| w == b"alice"));
    assert!(injected.body.windows(5).any(|w| w == b"\x00\xffABC"));
    assert_eq!(
        injected
            .header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        injected.body.len()
    );
    let header = &points
        .iter()
        .find(|(_, n)| n == "header User-Agent")
        .unwrap()
        .0;
    assert_eq!(
        Msg::parse(&inject(&msg, header, "marker", false)).header("user-agent"),
        Some("marker")
    );
    assert_eq!(
        Msg::parse(&inject(&msg, header, "evil\r\nInjected: yes", false)).header("user-agent"),
        Some("fixture")
    );
}

#[tokio::test]
async fn transient_signatures_and_neutral_control_errors_are_not_reported() {
    use crate::robust_tests::{Reply, fixture, request};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    for transient in [false, true] {
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let server = fixture(move |raw| {
            let first = Msg::parse(raw).first;
            let quote = first.contains("%27");
            let neutral = first.contains("ferritecontrol");
            let emit = if transient {
                quote && count.fetch_add(usize::from(quote), Ordering::SeqCst) == 0
            } else {
                quote || neutral
            };
            Reply::body(
                200,
                &[],
                if emit {
                    b"You have an error in your SQL syntax"
                } else {
                    b"normal"
                },
            )
        })
        .await;
        let (tx, rx) = mpsc::channel();
        active_controlled(
            server.target.clone(),
            request(&server.target, "GET", "/?id=1", b""),
            Upstream::None,
            tx,
            egui::Context::default(),
            crate::session::Client::new(Arc::default(), false, false),
            false,
            false,
        )
        .await;
        assert!(
            !rx.try_iter()
                .any(|e| matches!(e,Event::Issue(_,i) if i.title=="SQL injection"))
        );
    }
}

#[test]
fn duplicate_findings_remain_suppressed_after_project_restore_without_merging_parameters() {
    let issue = |param: &str| Issue {
        url: "https://example.test/item?id=one".into(),
        severity: Severity::High,
        title: "SQL injection",
        detail: format!("Parameter '{param}' produced an error"),
        req: b"GET /item?id=one HTTP/1.1\r\n\r\n".to_vec(),
        res: vec![],
    };
    let mut history = crate::history::History::default();
    history.add_issue("first".into(), issue("id"));
    let issues = std::mem::take(&mut history.issues);
    history.replace_all(vec![], vec![], issues);
    let mut duplicate = issue("id");
    duplicate.url = "https://example.test/item?id=two".into();
    history.add_issue("another runtime key".into(), duplicate);
    history.add_issue("different point".into(), issue("other"));
    assert_eq!(history.issues.len(), 2);
}

#[tokio::test]
async fn session_reuse_does_not_overwrite_cookie_insertion_points_or_record_wrong_evidence() {
    use crate::robust_tests::{Reply, fixture, request};
    use std::sync::{Arc, mpsc};
    let server = fixture(|raw| {
        let msg = Msg::parse(raw);
        let value = msg.header("cookie").unwrap_or("");
        Reply::body(
            200,
            &[],
            if value.contains("%27") {
                b"You have an error in your SQL syntax"
            } else {
                b"normal"
            },
        )
    })
    .await;
    let jar: crate::session::Shared = Arc::default();
    jar.lock()
        .unwrap()
        .set_cookie(&server.target.url(), "sid=legitimate; Path=/")
        .unwrap();
    let raw = request(&server.target, "GET", "/", b"");
    let mut msg = Msg::parse(&raw);
    msg.set_header("Cookie", "sid=old".into());
    let (tx, rx) = mpsc::channel();
    active_controlled(
        server.target.clone(),
        msg.render(),
        Upstream::None,
        tx,
        egui::Context::default(),
        crate::session::Client::new(jar.clone(), true, true),
        false,
        false,
    )
    .await;
    let issue = rx
        .try_iter()
        .find_map(|e| match e {
            Event::Issue(_, i) if i.title == "SQL injection" => Some(i),
            _ => None,
        })
        .expect("probe cookie was replaced by the jar");
    assert!(
        Msg::parse(&issue.req)
            .header("cookie")
            .unwrap()
            .contains("%27")
    );
    assert_eq!(
        Msg::parse(&jar.lock().unwrap().apply(&server.target, &raw)).header("cookie"),
        Some("sid=legitimate")
    );
}
