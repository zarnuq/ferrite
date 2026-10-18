//! Regression contracts for advanced features. Fixtures bind ephemeral loopback ports only.
use crate::http::{Msg, Target};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DEADLINE: Duration = Duration::from_secs(5);

pub struct Fixture {
    pub target: Target,
    pub seen: Arc<Mutex<Vec<Vec<u8>>>>,
    pub connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct Reply {
    pub bytes: Vec<u8>,
    pub close: bool,
    pub split: Option<(usize, Duration)>,
}
impl Reply {
    pub fn body(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Self {
        let mut raw = format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (key, value) in headers {
            raw.push_str(&format!("{key}: {value}\r\n"));
        }
        raw.push_str("\r\n");
        Self {
            bytes: [raw.as_bytes(), body].concat(),
            close: false,
            split: None,
        }
    }
}

pub async fn fixture<F>(respond: F) -> Fixture
where
    F: Fn(&[u8]) -> Reply + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture needs loopback sockets");
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (record, count, respond) = (seen.clone(), connections.clone(), Arc::new(respond));
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut io, _)) = accepted else { break };
                    count.fetch_add(1, Ordering::SeqCst);
                    let (record, respond) = (record.clone(), respond.clone());
                    children.spawn(async move {
                        loop {
                            let mut raw = Vec::new();
                            // Read exactly one request so keep-alive/pipelining tests cannot lose bytes.
                            let read = async {
                                while !raw.ends_with(b"\r\n\r\n") {
                                    raw.push(io.read_u8().await?);
                                    if raw.len() > 128 * 1024 { return Err(std::io::Error::other("fixture header limit")); }
                                }
                                let length = Msg::parse(&raw).header("content-length").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                                if length > 2 * 1024 * 1024 { return Err(std::io::Error::other("fixture body limit")); }
                                let start = raw.len(); raw.resize(start + length, 0);
                                io.read_exact(&mut raw[start..]).await?;
                                Ok::<_, std::io::Error>(())
                            };
                            if !matches!(tokio::time::timeout(DEADLINE, read).await, Ok(Ok(()))) { break; }
                            record.lock().unwrap().push(raw.clone());
                            let reply = respond(&raw);
                            if let Some((at, wait)) = reply.split {
                                if io.write_all(&reply.bytes[..at]).await.is_err() { break; }
                                tokio::time::sleep(wait).await;
                                if io.write_all(&reply.bytes[at..]).await.is_err() { break; }
                            } else if io.write_all(&reply.bytes).await.is_err() { break; }
                            if reply.close || Msg::parse(&raw).header("connection").is_some_and(|v| v.eq_ignore_ascii_case("close")) { break; }
                        }
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {},
            }
        }
    });
    Fixture {
        target: Target::from_url(&format!("http://{address}")).unwrap(),
        seen,
        connections,
        task,
    }
}

pub fn request(target: &Target, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        target.host_header(),
        body.len()
    );
    [head.as_bytes(), body].concat()
}

mod api;
mod persistence;
mod scripts;
mod transport;
mod workflows;
