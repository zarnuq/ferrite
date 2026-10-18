use super::*;
use crate::{
    http::{self, Target, Upstream},
    rules::{Compiled, Config},
};
use std::{
    sync::{Mutex, RwLock, mpsc},
    time::{Duration, Instant},
};

fn interaction(protocol: &str, payload: &str) -> Interaction {
    Interaction {
        time: 1,
        protocol: protocol.into(),
        peer: "127.0.0.1:1234".into(),
        payload: payload.into(),
    }
}
fn probe(token: &str) -> Probe {
    Probe {
        token: token.into(),
        url: "http://fixture.test/probe".into(),
        request: b"GET /probe HTTP/1.1\r\n\r\n".to_vec(),
        kind: "SSRF".into(),
    }
}

#[test]
fn callbacks_correlate_to_original_probe_and_ignore_unknown_or_poll_data() {
    let mut callbacks = Callbacks::default();
    callbacks.register(probe("aabbccddeeff00112233445566778899"));
    for (protocol, payload) in [
        ("HTTP", "GET /aabbccddeeff00112233445566778899 HTTP/1.1"),
        ("DNS", "aabbccddeeff00112233445566778899.fixture.test"),
    ] {
        let finding = callbacks.issue(&interaction(protocol, payload)).unwrap();
        assert_eq!(finding.url, "http://fixture.test/probe");
        assert!(finding.detail.contains(protocol));
        assert!(finding.req.starts_with(b"GET /probe"));
    }
    assert!(
        callbacks
            .issue(&interaction("HTTP", "GET /unknown HTTP/1.1"))
            .is_none()
    );
    assert!(
        callbacks
            .issue(&interaction("Poll", "aabbccddeeff00112233445566778899"))
            .is_none()
    );
}

#[test]
fn callback_state_rejects_stale_events_and_bounds_retention() {
    let mut callbacks = Callbacks::default();
    callbacks.run = 42;
    callbacks.on_note(41, Note::Interaction(interaction("HTTP", "stale")));
    assert!(callbacks.interactions.is_empty());
    for i in 0..2100 {
        callbacks.on_note(42, Note::Interaction(interaction("HTTP", &i.to_string())));
    }
    assert_eq!(callbacks.interactions.len(), 2000);
    assert_eq!(callbacks.interactions[0].payload, "100");
    for i in 0..1100 {
        callbacks.register(probe(&format!("token-{i}")));
    }
    assert_eq!(callbacks.probes.len(), 1000);
    assert_eq!(callbacks.tokens.len(), 1000);
    assert_eq!(callbacks.probes[0].token, "token-100");
}

#[test]
fn dns_parser_rejects_truncation_multiple_questions_and_compression_without_panics() {
    let mut packet = vec![0u8; 12];
    packet[5] = 1;
    packet.extend_from_slice(b"\x03abc\x07fixture\x04test\0\0\x01\0\x01");
    assert_eq!(dns_question(&packet).unwrap().0, "abc.fixture.test");
    for end in 0..packet.len() {
        assert!(
            dns_question(&packet[..end]).is_none(),
            "truncated packet accepted at {end}"
        );
    }
    packet[5] = 2;
    assert!(dns_question(&packet).is_none());
    packet[5] = 1;
    packet[12] = 0xc0;
    assert!(dns_question(&packet).is_none());
    for length in 0..300 {
        let data = vec![(length % 256) as u8; length];
        assert!(std::panic::catch_unwind(|| dns_question(&data)).is_ok());
    }
}

async fn next_note(rx: &mpsc::Receiver<crate::Event>, predicate: impl Fn(&Note) -> bool) -> Note {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        while let Ok(event) = rx.try_recv() {
            if let crate::Event::Callback { note, .. } = event {
                if predicate(&note) {
                    return note;
                }
            }
        }
        assert!(Instant::now() < deadline, "collector event timed out");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn collector_receives_http_and_dns_and_stops_cleanly() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = reserved.local_addr().unwrap();
    drop(reserved);
    let reserved = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_address = reserved.local_addr().unwrap();
    drop(reserved);
    let mut callbacks = Callbacks {
        http: http_address.to_string(),
        dns: dns_address.to_string(),
        ..Default::default()
    };
    let (tx, rx) = mpsc::channel();
    let rt = tokio::runtime::Handle::current();
    let egui = egui::Context::default();
    let shared = Arc::new(RwLock::new(Arc::new(Compiled::new(Config::default()))));
    let jar = Arc::new(Mutex::new(crate::session::Jar::default()));
    let mut actions = Vec::new();
    callbacks.start(&Env {
        listen_addr: http_address,
        rt: &rt,
        tx: &tx,
        egui: &egui,
        shared: &shared,
        jar: &jar,
        actions: &mut actions,
    });
    next_note(
        &rx,
        |n| matches!(n,Note::Status(s)if s.starts_with("Listening")),
    )
    .await;
    let target = Target::from_url(&format!("http://{http_address}")).unwrap();
    let raw = format!(
        "GET /unique-callback HTTP/1.1\r\nHost: {http_address}\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(
        http::send(&target, raw.as_bytes(), &Upstream::None)
            .await
            .unwrap()
            .status,
        200
    );
    match next_note(
        &rx,
        |n| matches!(n,Note::Interaction(i)if i.protocol=="HTTP"),
    )
    .await
    {
        Note::Interaction(i) => assert!(i.payload.contains("unique-callback")),
        _ => unreachable!(),
    }
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut query = vec![0u8; 12];
    query[0] = 0x12;
    query[1] = 0x34;
    query[2] = 1;
    query[5] = 1;
    query.extend_from_slice(b"\x03abc\x07fixture\x04test\0\0\x01\0\x01");
    socket.send_to(&query, dns_address).await.unwrap();
    let mut reply = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..2], &query[..2]);
    assert_eq!(reply[3] & 0x0f, 3);
    assert_eq!(n, query.len());
    match next_note(
        &rx,
        |n| matches!(n,Note::Interaction(i)if i.protocol=="DNS"),
    )
    .await
    {
        Note::Interaction(i) => assert_eq!(i.payload, "abc.fixture.test"),
        _ => unreachable!(),
    }
    callbacks
        .cancel
        .as_ref()
        .unwrap()
        .store(true, Ordering::Relaxed);
    next_note(&rx, |n| matches!(n, Note::Done)).await;
}

#[tokio::test]
async fn occupied_listener_port_reports_error_and_completion() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    let mut callbacks = Callbacks {
        http: address.to_string(),
        ..Default::default()
    };
    let (tx, rx) = mpsc::channel();
    let rt = tokio::runtime::Handle::current();
    let egui = egui::Context::default();
    let shared = Arc::new(RwLock::new(Arc::new(Compiled::new(Config::default()))));
    let jar = Arc::new(Mutex::new(crate::session::Jar::default()));
    let mut actions = Vec::new();
    callbacks.start(&Env {
        listen_addr: address,
        rt: &rt,
        tx: &tx,
        egui: &egui,
        shared: &shared,
        jar: &jar,
        actions: &mut actions,
    });
    match next_note(&rx, |n| matches!(n, Note::Status(_))).await {
        Note::Status(s) => assert!(s.contains("HTTP listener:")),
        _ => unreachable!(),
    }
    next_note(&rx, |n| matches!(n, Note::Done)).await;
}

#[tokio::test]
async fn collector_retains_callback_token_when_http_headers_arrive_in_fragments() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let mut callbacks = Callbacks {
        http: address.to_string(),
        ..Default::default()
    };
    let (tx, rx) = mpsc::channel();
    let rt = tokio::runtime::Handle::current();
    let egui = egui::Context::default();
    let shared = Arc::new(RwLock::new(Arc::new(Compiled::new(Config::default()))));
    let jar = Arc::new(Mutex::new(crate::session::Jar::default()));
    let mut actions = Vec::new();
    callbacks.start(&Env {
        listen_addr: address,
        rt: &rt,
        tx: &tx,
        egui: &egui,
        shared: &shared,
        jar: &jar,
        actions: &mut actions,
    });
    next_note(
        &rx,
        |n| matches!(n,Note::Status(s)if s.starts_with("Listening")),
    )
    .await;
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(b"GET /").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = socket
        .write_all(b"fragmented-unique-token HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
        .await;
    let note = next_note(
        &rx,
        |n| matches!(n,Note::Interaction(i)if i.protocol=="HTTP"),
    )
    .await;
    callbacks
        .cancel
        .as_ref()
        .unwrap()
        .store(true, Ordering::Relaxed);
    next_note(&rx, |n| matches!(n, Note::Done)).await;
    match note {
        Note::Interaction(i) => assert!(
            i.payload.contains("fragmented-unique-token"),
            "collector recorded only the first TCP fragment"
        ),
        _ => unreachable!(),
    }
}
