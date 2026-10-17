use crate::{
    Event, Kind, Pending,
    http::{self, Msg},
    rules::{Shared, current},
};
use eframe::egui;
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
    certificate_authority::RcgenAuthority,
    hyper::{
        HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderName, HeaderValue},
        http::request::Parts,
    },
    rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::{Connector, tungstenite::Message},
};
use hyper_util::rt::TokioIo;
use std::{
    error::Error,
    fs,
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        mpsc::Sender,
    },
    task::{Context, Poll},
    time::Instant,
};
use tokio::{net::TcpStream, sync::oneshot};

pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"))
        .join("ferrite")
}

/// Loads the CA from the config dir, generating it on first run.
fn load_or_create_ca() -> Result<Issuer<'static, KeyPair>, Box<dyn Error + Send + Sync>> {
    let dir = config_dir();
    let (cert_path, key_path) = (dir.join("ca.pem"), dir.join("ca.key"));
    if !cert_path.exists() || !key_path.exists() {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "ferrite CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        fs::create_dir_all(&dir)?;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)?
            .write_all(key.serialize_pem().as_bytes())?;
        fs::write(&cert_path, cert.pem())?;
    }
    let key = KeyPair::from_pem(&fs::read_to_string(&key_path)?)?;
    Ok(Issuer::from_ca_cert_pem(&fs::read_to_string(&cert_path)?, key)?)
}

/// Connector for the proxy's outbound client; honours the upstream proxy setting per connection.
#[derive(Clone)]
struct Dialer(Shared);

impl tower_service::Service<Uri> for Dialer {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TokioIo<TcpStream>>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let upstream = current(&self.0).cfg.upstream.clone();
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| io::Error::other("no host in URI"))?;
            let host = host.trim_matches(['[', ']']).to_string();
            let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
            let stream = http::dial(&host, port, &upstream).await?;
            let _ = stream.set_nodelay(true);
            Ok(TokioIo::new(stream))
        })
    }
}

pub async fn run(
    addr: SocketAddr,
    shared: Shared,
    tx: Sender<Event>,
    ui: egui::Context,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ca = RcgenAuthority::new(load_or_create_ca()?, 1_000, aws_lc_rs::default_provider());
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(http::insecure_tls())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(Dialer(shared.clone()));
    let handler = Handler { shared, tx, ui, id: 0, url: String::new(), start: Instant::now(), record: true };
    // ponytail: websocket upgrades connect directly, ignoring the upstream proxy; custom tungstenite connect if needed
    Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_http_connector(https)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_websocket_connector(Connector::Rustls(Arc::new(http::insecure_tls())))
        .build()?
        .start()
        .await?;
    Ok(())
}

/// hudsucker clones the handler per request, so `id`, `url` and `start` link a request to its response.
#[derive(Clone)]
struct Handler {
    shared: Shared,
    tx: Sender<Event>,
    ui: egui::Context,
    id: u64,
    url: String,
    start: Instant,
    record: bool,
}

impl Handler {
    fn send(&self, ev: Event) {
        let _ = self.tx.send(ev);
        self.ui.request_repaint();
    }

    /// Hands a message to the Intercept tab and waits. `None` means drop it.
    async fn intercept(&self, kind: Kind, url: &str, raw: Vec<u8>) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        self.send(Event::Intercept(Pending { kind, url: url.to_string(), raw: raw.clone(), reply }));
        rx.await.unwrap_or(Some(raw))
    }

    fn respond(&self, status: StatusCode, note: String) -> Response<Body> {
        let raw = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n\r\n{note}").into_bytes();
        self.send(Event::Response { id: self.id, raw, ms: self.start.elapsed().as_millis() });
        Response::builder().status(status).body(Body::from(note)).unwrap()
    }
}

fn version(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

fn render(first: String, headers: &HeaderMap, body: &[u8]) -> Vec<u8> {
    let headers = headers
        .iter()
        .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    Msg { first, headers, body: body.to_vec() }.render()
}

fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            map.append(k, v);
        }
    }
    map
}

/// Applies an edited raw request onto the original parts, keeping its scheme, host and extensions.
fn apply_request(parts: &mut Parts, raw: &[u8]) -> Vec<u8> {
    let m = Msg::parse(raw);
    let mut words = m.first.split_whitespace();
    if let Some(method) = words.next().and_then(|w| Method::from_bytes(w.as_bytes()).ok()) {
        parts.method = method;
    }
    if let Some(target) = words.next() {
        let uri = if target.starts_with("http://") || target.starts_with("https://") {
            target.parse()
        } else {
            let scheme = parts.uri.scheme_str().unwrap_or("http");
            let authority = parts.uri.authority().map_or("", |a| a.as_str());
            format!("{scheme}://{authority}{target}").parse()
        };
        if let Ok(uri) = uri {
            parts.uri = uri;
        }
    }
    parts.headers = header_map(&m.headers);
    m.body
}

fn apply_response(parts: &mut hudsucker::hyper::http::response::Parts, raw: &[u8]) -> Vec<u8> {
    let m = Msg::parse(raw);
    if let Ok(status) = StatusCode::from_u16(m.status()) {
        parts.status = status;
    }
    parts.headers = header_map(&m.headers);
    m.body
}

impl HttpHandler for Handler {
    async fn handle_request(&mut self, _ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        // CONNECT only opens the tunnel; the decrypted requests inside come through here again.
        if req.method() == Method::CONNECT {
            return req.into();
        }
        self.id = crate::history::next_id();
        self.start = Instant::now();
        self.url = req.uri().to_string();
        // ponytail: buffers whole bodies, so streaming bodies (SSE, long-poll) stall until done; stream-tee if it matters
        let (mut parts, body) = req.into_parts();
        let Ok(mut body) = body.collect().await.map(|c| c.to_bytes().to_vec()) else {
            return self.respond(StatusCode::BAD_GATEWAY, "ferrite: failed to read request body".into()).into();
        };
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        let mut raw = render(format!("{} {path} {}", parts.method, version(parts.version)), &parts.headers, &body);
        let cfg = current(&self.shared);
        self.record = !cfg.cfg.record_scope_only || cfg.in_scope(&self.url);
        let mut changed = false;
        if let Some(r) = cfg.apply(&raw, true) {
            raw = r;
            changed = true;
        }
        let stop = cfg.cfg.intercept.requests && !(cfg.cfg.intercept.skip_static && http::is_static(&self.url));
        let edited = if cfg.intercepts(stop, &self.url) {
            self.intercept(Kind::Request, &self.url, raw.clone()).await
        } else {
            Some(raw.clone())
        };
        let Some(edited) = edited else {
            self.send(Event::Request { id: self.id, url: self.url.clone(), raw });
            return self.respond(StatusCode::BAD_GATEWAY, "ferrite: request dropped".into()).into();
        };
        if changed || edited != raw {
            body = apply_request(&mut parts, &edited);
            raw = edited;
        }
        if self.record {
            self.send(Event::Request { id: self.id, url: self.url.clone(), raw });
        }
        Request::from_parts(parts, Body::from(body)).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (mut parts, body) = res.into_parts();
        let Ok(mut body) = body.collect().await.map(|c| c.to_bytes().to_vec()) else {
            return self.respond(StatusCode::BAD_GATEWAY, "ferrite: failed to read response body".into());
        };
        // Unpack compressed bodies so history, rules and intercept all see plaintext.
        if let Some(enc) = parts.headers.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()) {
            if let Some(decoded) = http::decode(enc, &body) {
                body = decoded;
                parts.headers.remove(CONTENT_ENCODING);
                if parts.headers.contains_key(CONTENT_LENGTH) {
                    parts.headers.insert(CONTENT_LENGTH, body.len().into());
                }
            }
        }
        let mut raw = render(format!("{} {}", version(parts.version), parts.status), &parts.headers, &body);
        let cfg = current(&self.shared);
        let mut changed = false;
        if let Some(r) = cfg.apply(&raw, false) {
            raw = r;
            changed = true;
        }
        let edited = if cfg.intercepts(cfg.cfg.intercept.responses, &self.url) {
            self.intercept(Kind::Response, &self.url, raw.clone()).await
        } else {
            Some(raw.clone())
        };
        let Some(edited) = edited else {
            return self.respond(StatusCode::BAD_GATEWAY, "ferrite: response dropped".into());
        };
        if changed || edited != raw {
            body = apply_response(&mut parts, &edited);
            raw = edited;
        }
        if self.record {
            self.send(Event::Response { id: self.id, raw, ms: self.start.elapsed().as_millis() });
        }
        Response::from_parts(parts, Body::from(body))
    }

    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = req.uri().host().unwrap_or("");
        !current(&self.shared).passthrough(host)
    }

    async fn handle_error(&mut self, _ctx: &HttpContext, err: hyper_util::client::legacy::Error) -> Response<Body> {
        let mut msg = err.to_string();
        let mut source = err.source();
        while let Some(s) = source {
            msg.push_str(&format!(": {s}"));
            source = s.source();
        }
        self.respond(StatusCode::BAD_GATEWAY, format!("ferrite: {msg}"))
    }
}

impl WebSocketHandler for Handler {
    async fn handle_message(&mut self, ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        let (url, outgoing) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => (dst.to_string(), true),
            WebSocketContext::ServerToClient { src, .. } => (src.to_string(), false),
        };
        let (mut data, text) = match &msg {
            Message::Text(t) => (t.as_bytes().to_vec(), true),
            Message::Binary(b) => (b.to_vec(), false),
            _ => return Some(msg),
        };
        let cfg = current(&self.shared);
        let mut msg = msg;
        if cfg.intercepts(cfg.cfg.intercept.websockets, &url) {
            let kind = if outgoing { Kind::WsOut } else { Kind::WsIn };
            let edited = self.intercept(kind, &url, data.clone()).await?;
            if edited != data {
                data = edited;
                msg = match String::from_utf8(data.clone()) {
                    Ok(s) if text => Message::Text(s.into()),
                    _ => Message::Binary(data.clone().into()),
                };
            }
        }
        self.send(Event::Ws { url, outgoing, text, data });
        Some(msg)
    }
}
