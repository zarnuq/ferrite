use crate::{
    history::History, http::Msg, intruder::Intruder, organizer::Organizer, project,
    repeater::Repeater,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferrite-regression-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> String {
        self.0
            .join("session.ferrite")
            .to_string_lossy()
            .into_owned()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn history() -> History {
    let mut history = History::default();
    history.on_request(
        7,
        "http://example.test/item".into(),
        b"GET /item HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
    );
    history.on_response(7,b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n\x00\xff\xfeA".to_vec(),12);
    history
}

#[test]
fn snapshot_is_independent_of_live_state_and_round_trips_binary_evidence() {
    let dir = Directory::new();
    let mut original = history();
    let snapshot = project::snapshot(
        &original,
        &Repeater::default(),
        &Organizer::default(),
        &Intruder::default(),
    );
    original.flows[0].note = "edited after snapshot".into();
    original.flows[0].req.clear();
    project::write_snapshot(snapshot, &dir.file()).unwrap();
    let mut restored = History::default();
    assert_eq!(
        project::load(
            &mut restored,
            &mut Repeater::default(),
            &mut Organizer::default(),
            &mut Intruder::default(),
            &dir.file()
        )
        .unwrap(),
        1
    );
    assert_eq!(restored.flows[0].note, "");
    assert!(!restored.flows[0].req.is_empty());
    assert_eq!(
        Msg::parse(restored.flows[0].res.as_ref().unwrap()).body,
        b"\x00\xff\xfeA"
    );
    assert_ne!(
        restored.flows[0].id, 7,
        "loaded traffic must receive fresh runtime IDs"
    );
}

#[test]
fn corrupt_and_wrong_format_projects_leave_live_state_unchanged() {
    use std::io::Write;
    let dir = Directory::new();
    for bytes in [
        b"not gzip".to_vec(),
        {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(br#"{"magic":"other","flows":[],"ws":[],"issues":[]}"#)
                .unwrap();
            gz.finish().unwrap()
        },
        {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(b"{bad json").unwrap();
            gz.finish().unwrap()
        },
    ] {
        std::fs::write(dir.file(), bytes).unwrap();
        let mut history = history();
        let original = history.flows[0].req.clone();
        let mut repeater = Repeater::default();
        repeater.add(
            crate::http::Target::from_url("http://example.test").unwrap(),
            original.clone(),
        );
        let before = serde_json::to_vec(&repeater.save_state()).unwrap();
        assert!(
            project::load(
                &mut history,
                &mut repeater,
                &mut Organizer::default(),
                &mut Intruder::default(),
                &dir.file()
            )
            .is_err()
        );
        assert_eq!(history.flows.len(), 1);
        assert_eq!(history.flows[0].req, original);
        assert_eq!(serde_json::to_vec(&repeater.save_state()).unwrap(), before);
    }
}

#[test]
fn failed_atomic_write_does_not_leave_partial_files_or_replace_existing_data() {
    let dir = Directory::new();
    let path = dir.0.join("occupied");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("keep"), b"original").unwrap();
    let result = project::write_snapshot(
        project::snapshot(
            &history(),
            &Repeater::default(),
            &Organizer::default(),
            &Intruder::default(),
        ),
        path.to_str().unwrap(),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(path.join("keep")).unwrap(), b"original");
    assert_eq!(
        std::fs::read_dir(&dir.0).unwrap().count(),
        1,
        "failed writes must remove their temporary files"
    );
}

#[test]
fn concurrent_atomic_saves_always_leave_a_loadable_complete_snapshot() {
    let dir = Directory::new();
    let path = dir.file();
    let workers: Vec<_> = (0..6)
        .map(|i| {
            let mut history = history();
            history.flows[0].note = format!("writer-{i}");
            let snapshot = project::snapshot(
                &history,
                &Repeater::default(),
                &Organizer::default(),
                &Intruder::default(),
            );
            let path = path.clone();
            std::thread::spawn(move || project::write_snapshot(snapshot, &path).unwrap())
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut history = History::default();
    project::load(
        &mut history,
        &mut Repeater::default(),
        &mut Organizer::default(),
        &mut Intruder::default(),
        &path,
    )
    .unwrap();
    assert_eq!(history.flows.len(), 1);
    assert!(history.flows[0].note.starts_with("writer-"));
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn atomic_project_files_are_private_to_the_current_user() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Directory::new();
    project::save(
        &history(),
        &Repeater::default(),
        &Organizer::default(),
        &Intruder::default(),
        &dir.file(),
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(dir.file()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn retention_enforces_byte_budget_and_keeps_newest_complete_request_metadata() {
    let mut history = History::default();
    let raw = [
        b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        &vec![b'x'; crate::retention::MESSAGE],
    ]
    .concat();
    for id in 0..70 {
        history.on_request(id, format!("http://example.test/{id}"), raw.clone());
    }
    history.enforce_limits();
    let bytes: usize = history
        .flows
        .iter()
        .map(|f| f.req.len() + f.res.as_ref().map_or(0, Vec::len))
        .sum();
    assert!(bytes <= crate::retention::BYTES);
    assert!(history.flows.len() < 70);
    assert_eq!(history.flows.last().unwrap().id, 69);
    assert!(history.flow(0).is_none());
    for f in &history.flows {
        assert_eq!(history.flow(f.id).unwrap().url, f.url);
    }
}

#[test]
fn retained_message_truncation_is_visible_and_small_messages_are_unchanged() {
    let raw = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(crate::retention::clip(raw.clone()), raw);
    let large = crate::retention::clip(vec![b'x'; crate::retention::MESSAGE + 1]);
    assert!(large.len() < crate::retention::MESSAGE + 200);
    assert!(String::from_utf8_lossy(&large).contains("truncated"));
}

#[test]
fn project_context_preserves_identities_workflows_and_scope_independently() {
    let dir = Directory::new();
    let mut context = project::Context::default();
    context.settings.include = vec!["^https://app.example/".into()];
    let mut identity = crate::authz::Identity {
        name: "User".into(),
        origin: "https://app.example".into(),
        headers: "Authorization: Bearer fixture".into(),
        ..Default::default()
    };
    identity
        .cookies
        .set_cookie("https://app.example/", "sid=user; Secure; Path=/")
        .unwrap();
    context.settings.identities.push(identity);
    context.settings.browser_steps = vec![crate::browser_lab::Step::Fill {
        selector: "#username".into(),
        value: "fixture".into(),
    }];
    let expected = context.settings.clone();
    let snapshot = project::snapshot(
        &History::default(),
        &Repeater::default(),
        &Organizer::default(),
        &Intruder::default(),
    )
    .with_context(context);
    project::write_snapshot(snapshot, &dir.file()).unwrap();
    let (_, loaded) = project::load_with_context(
        &mut History::default(),
        &mut Repeater::default(),
        &mut Organizer::default(),
        &mut Intruder::default(),
        &dir.file(),
    )
    .unwrap();
    assert!(loaded.unwrap().settings == expected);
    // A separate legacy/new project does not inherit this project's accounts or workflow.
    project::write_snapshot(
        project::snapshot(
            &History::default(),
            &Repeater::default(),
            &Organizer::default(),
            &Intruder::default(),
        ),
        &dir.file(),
    )
    .unwrap();
    let (_, loaded) = project::load_with_context(
        &mut History::default(),
        &mut Repeater::default(),
        &mut Organizer::default(),
        &mut Intruder::default(),
        &dir.file(),
    )
    .unwrap();
    assert!(loaded.is_none());
}
