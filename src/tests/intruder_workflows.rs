use super::*;
use crate::robust_tests::{DEADLINE, Reply, fixture};
use std::sync::{RwLock, mpsc};

#[test]
fn processing_regex_then_transform_and_invalid_patterns() {
    let p = Processing {
        transform: "Base64".into(),
        find: "^user-".into(),
        replace: String::new(),
    };
    assert_eq!(p.apply("user-alice").unwrap(), "YWxpY2U=");
    let mut p = p;
    p.transform = "SHA-256".into();
    assert_eq!(p.apply("user-alice").unwrap().len(), 64);
    p.find = "[".into();
    assert!(p.apply("x").is_err());
}

#[tokio::test]
async fn restored_checkpoint_resumes_only_unsent_payloads_using_original_plan() {
    let server = fixture(|_| Reply::body(200, &[], b"ok")).await;
    let mut intruder = Intruder {
        target: server.target.clone(),
        template: format!(
            "GET /?id=§x§ HTTP/1.1\r\nHost: {}\r\n\r\n",
            server.target.host_header()
        ),
        sets: vec!["one\ntwo\nthree".into()],
        total: 3,
        result_target: Some(server.target.clone()),
        ..Default::default()
    };
    intruder.result_draft = Some(intruder.draft());
    // The first request was queued at save time. Its delivery is uncertain; never replay it automatically.
    intruder.on_queued(
        0,
        0,
        "one".into(),
        b"GET /?id=one HTTP/1.1\r\n\r\n".to_vec(),
    );
    let saved =
        serde_json::from_slice(&serde_json::to_vec(&intruder.save_state()).unwrap()).unwrap();
    intruder.restore(saved);
    intruder.load(
        Target::from_url("http://other.invalid/").unwrap(),
        b"GET /wrong HTTP/1.1\r\n\r\n".to_vec(),
    );
    intruder.sets = vec!["edited".into()];
    let shared = Arc::new(RwLock::new(Arc::new(crate::rules::Compiled::new(
        Default::default(),
    ))));
    let jar = Arc::default();
    let (tx, rx) = mpsc::channel();
    let ctx = egui::Context::default();
    let mut actions = vec![];
    intruder.start(
        &Env {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            rt: &tokio::runtime::Handle::current(),
            tx: &tx,
            egui: &ctx,
            shared: &shared,
            jar: &jar,
            actions: &mut actions,
        },
        true,
    );
    tokio::time::timeout(DEADLINE, async {
        loop {
            for event in rx.try_iter() {
                match event {
                    Event::IntruderQueued {
                        attack,
                        idx,
                        payloads,
                        request,
                    } => intruder.on_queued(attack, idx, payloads, request),
                    Event::Intruder {
                        attack,
                        idx,
                        request,
                        result,
                    } => intruder.on_result(attack, idx, request, result),
                    Event::IntruderDone { attack } => intruder.on_done(attack),
                    _ => {}
                }
            }
            if intruder.cancel.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    let paths: Vec<_> = seen.iter().map(|r| http::Msg::parse(r).first).collect();
    assert!(paths.iter().any(|p| p.contains("id=two")));
    assert!(paths.iter().any(|p| p.contains("id=three")));
    assert!(paths.iter().all(|p| !p.contains("id=one")));
    assert_eq!(intruder.done, 3);
    assert!(intruder.rows[0].error.contains("unfinished"));
    assert_eq!(intruder.target.host, "other.invalid");
}

#[tokio::test]
async fn checkpoint_at_retention_boundary_never_requeues_previous_batch() {
    let server = fixture(|_| Reply::body(200, &[], b"ok")).await;
    let mut tool = Intruder {
        target: server.target.clone(),
        template: format!(
            "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
            server.target.host_header()
        ),
        attack: Attack::Null,
        repeat: crate::retention::ROWS + 1,
        total: crate::retention::ROWS + 1,
        result_target: Some(server.target.clone()),
        ..Default::default()
    };
    tool.result_draft = Some(tool.draft());
    for i in 0..crate::retention::ROWS - 1 {
        tool.on_queued(0, i, i.to_string(), vec![]);
        tool.on_result(0, i, vec![], Err("fixture checkpoint".into()));
    }
    let shared = Arc::new(RwLock::new(Arc::new(crate::rules::Compiled::new(
        Default::default(),
    ))));
    let jar = Arc::default();
    let (tx, rx) = mpsc::channel();
    let ctx = egui::Context::default();
    let mut actions = vec![];
    for expected in [crate::retention::ROWS, crate::retention::ROWS + 1] {
        tool.start(
            &Env {
                listen_addr: "127.0.0.1:8080".parse().unwrap(),
                rt: &tokio::runtime::Handle::current(),
                tx: &tx,
                egui: &ctx,
                shared: &shared,
                jar: &jar,
                actions: &mut actions,
            },
            true,
        );
        tokio::time::timeout(DEADLINE, async {
            loop {
                for event in rx.try_iter() {
                    match event {
                        Event::IntruderQueued {
                            attack,
                            idx,
                            payloads,
                            request,
                        } => tool.on_queued(attack, idx, payloads, request),
                        Event::Intruder {
                            attack,
                            idx,
                            request,
                            result,
                        } => tool.on_result(attack, idx, request, result),
                        Event::IntruderDone { attack } => tool.on_done(attack),
                        _ => {}
                    }
                }
                if tool.cancel.is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tool.done, expected);
        assert_eq!(tool.row_base + tool.rows.len(), expected);
        let saved =
            serde_json::from_slice(&serde_json::to_vec(&tool.save_state()).unwrap()).unwrap();
        tool.restore(saved);
        assert_eq!(tool.row_base + tool.rows.len(), expected);
    }
    assert_eq!(server.seen.lock().unwrap().len(), 2);
}
