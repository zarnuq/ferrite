//! Repeater groups: separate connections, connection reuse, last-byte release and HTTP/2.
use crate::http::{self, Msg, Reply, Target, Upstream};
use hudsucker::futures::{StreamExt, stream};
use std::{sync::Arc, time::{Duration, Instant}};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Copy, PartialEq, Default)]
pub enum Mode { #[default] Sequence, Connection, Parallel, Http2, Coalesced }
impl Mode {
    pub const ALL: [(Self, &'static str); 5] = [(Self::Sequence,"Sequence"), (Self::Connection,"Sequence / same connection"), (Self::Parallel,"Parallel / last-byte sync"), (Self::Http2,"Parallel / HTTP/2"),(Self::Coalesced,"HTTP/2 / coalesced release")];
    pub fn label(self) -> &'static str { Self::ALL.iter().find(|(m,_)| *m == self).unwrap().1 }
}

pub async fn send(target: Target, requests: Vec<Vec<u8>>, upstream: Upstream, mode: Mode) -> Vec<(usize, Result<Reply, String>)> {
    let count = requests.len();
    if count == 0 { return Vec::new(); }
    if count > 100 { return (0..count).map(|i| (i, Err("Groups support at most 100 requests".into()))).collect(); }
    let work = async {
        match mode {
            Mode::Sequence => {
                let mut out = Vec::new();
                for (i, req) in requests.iter().enumerate() { out.push((i, http::send(&target, req, &upstream).await)); }
                Ok(out)
            }
            Mode::Connection => {
                let mut io = http::connect(&target, &upstream).await.map_err(|e| e.to_string())?;
                let mut out = Vec::new();
                for (i, req) in requests.iter().enumerate() {
                    let at = Instant::now();
                    let mut msg = Msg::parse(req);
                    msg.set_header("Connection", "keep-alive".into());
                    io.write_all(&msg.render()).await.map_err(|e| e.to_string())?;
                    let raw = http::read_response(&mut io, req.starts_with(b"HEAD ")).await.map_err(|e| e.to_string())?;
                    out.push((i, Ok(Reply { status: Msg::parse(&raw).status(), raw, elapsed: at.elapsed() })));
                }
                Ok(out)
            }
            Mode::Parallel => {
                // Open all connections and write all prefixes before releasing any last byte.
                // A failed preparation causes the whole group to fail before release.
                let mut prepared = Vec::new();
                for (i, req) in requests.into_iter().enumerate() {
                    if req.is_empty() { return Err("Cannot synchronize an empty request".into()); }
                    let mut io = http::connect(&target, &upstream).await.map_err(|e| e.to_string())?;
                    io.write_all(&req[..req.len()-1]).await.map_err(|e| e.to_string())?;
                    prepared.push((i, req, io));
                }
                let gate = Arc::new(tokio::sync::Barrier::new(prepared.len()));
                let mut tasks = tokio::task::JoinSet::new();
                for (i, req, mut io) in prepared {
                    let gate = gate.clone();
                    tasks.spawn(async move {
                        gate.wait().await;
                        let at = Instant::now();
                        let result = async {
                            io.write_all(&req[req.len()-1..]).await.map_err(|e| e.to_string())?;
                            io.flush().await.map_err(|e| e.to_string())?;
                            let raw = http::read_response(&mut io, req.starts_with(b"HEAD ")).await.map_err(|e| e.to_string())?;
                            Ok(Reply {status: Msg::parse(&raw).status(), raw, elapsed: at.elapsed()})
                        }.await;
                        (i, result)
                    });
                }
                let mut out = Vec::new();
                while let Some(result) = tasks.join_next().await { out.push(result.map_err(|e| e.to_string())?); }
                Ok(out)
            }
            Mode::Coalesced => crate::coalesced::send(target,requests,upstream).await,
            Mode::Http2 => h2(target, requests, upstream).await,
        }
    };
    match tokio::time::timeout(Duration::from_secs(60), work).await {
        Ok(Ok(out)) => out,
        other => {
            let error = match other { Ok(Err(e)) => e, _ => "Group timed out after 60 seconds; some requests may have been sent".into() };
            (0..count).map(|i| (i, Err(error.clone()))).collect()
        }
    }
}

async fn h2(target: Target, requests: Vec<Vec<u8>>, upstream: Upstream) -> Result<Vec<(usize, Result<Reply, String>)>, String> {
    use http_body_util::{BodyExt, Full, Limited};
    use hudsucker::hyper::{Request, Version};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let io=h2_io(&target,&upstream).await?;
    let (sender, connection) = hudsucker::hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    let driver = tokio::spawn(connection);
    let gate = Arc::new(tokio::sync::Barrier::new(requests.len().max(1)));
    let result = stream::iter(requests.into_iter().enumerate()).map(|(i, raw)| {
        let mut sender = sender.clone(); let origin = target.url(); let gate = gate.clone();
        async move {
            let msg = Msg::parse(&raw);
            let mut words = msg.first.split_whitespace();
            let method = words.next().unwrap_or("GET"); let path = words.next().unwrap_or("/");
            let mut req = Request::builder().method(method).uri(format!("{origin}{path}")).version(Version::HTTP_2);
            for (k,v) in &msg.headers {
                if !["host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"].contains(&k.to_ascii_lowercase().as_str()) { req = req.header(k,v); }
            }
            let req = req.body(Full::new(bytes::Bytes::from(msg.body))).map_err(|e| e.to_string());
            gate.wait().await;
            let at = Instant::now();
            let result = async {
                let res = sender.send_request(req?).await.map_err(|e| e.to_string())?;
                let status = res.status().as_u16();
                let (parts, body) = res.into_parts();
                let headers = parts.headers.iter().map(|(k,v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
                let body = Limited::new(body, 16 * 1024 * 1024).collect().await.map_err(|e| e.to_string())?.to_bytes().to_vec();
                Ok(Reply { status, raw: Msg { first: format!("HTTP/2 {status}"), headers, body }.render(), elapsed: at.elapsed() })
            }.await;
            (i,result)
        }
    }).buffer_unordered(100).collect().await;
    driver.abort();
    Ok(result)
}

pub(crate) async fn h2_io(target:&Target,upstream:&Upstream)->Result<Box<dyn http::Stream>,String>{
    let tcp = http::dial(&target.host, target.port, &upstream).await.map_err(|e| e.to_string())?;
    let io: Box<dyn http::Stream> = if target.tls {
        let mut cfg = http::insecure_tls(); cfg.alpn_protocols = vec![b"h2".to_vec()];
        let name = hudsucker::rustls::pki_types::ServerName::try_from(target.host.clone()).map_err(|e| e.to_string())?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.map_err(|e| e.to_string())?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") { return Err("Target did not negotiate HTTP/2".into()); }
        Box::new(tls)
    } else { Box::new(tcp) };

    Ok(io)
}
