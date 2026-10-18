//! Raw HTTP helpers: parsing and rendering editable messages, body decoding,
//! display formatting, and a raw HTTP/1.1 client for Repeater and Intruder.

use hudsucker::rustls::{
    self, ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    collections::HashMap,
    io::{self, Read},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

// ---------- parsing / rendering ----------

/// Start line, headers and body of a raw message. Accepts `\n` or `\r\n` line endings,
/// since text edited in the UI ends up with bare `\n`.
pub struct Msg {
    pub first: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Msg {
    pub fn parse(raw: &[u8]) -> Msg {
        let mut pos = 0;
        let mut lines = Vec::new();
        while pos < raw.len() {
            let end = raw[pos..].iter().position(|&b| b == b'\n').map(|i| pos + i);
            let line = &raw[pos..end.unwrap_or(raw.len())];
            pos = end.map_or(raw.len(), |e| e + 1);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                break;
            }
            lines.push(String::from_utf8_lossy(line).into_owned());
        }
        let mut lines = lines.into_iter();
        let first = lines.next().unwrap_or_default();
        let headers = lines
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        Msg { first, headers, body: raw[pos..].to_vec() }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: String) {
        match self.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            Some(h) => h.1 = value,
            None => self.headers.push((name.to_string(), value)),
        }
    }

    /// Sets Content-Length to the body size when the header is present.
    pub fn fix_content_length(&mut self) {
        if self.header("content-length").is_some() {
            self.set_header("Content-Length", self.body.len().to_string());
        }
    }

    pub fn render(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 512);
        out.extend_from_slice(self.first.as_bytes());
        out.extend_from_slice(b"\r\n");
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn status(&self) -> u16 {
        self.first.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    /// Body with transfer and content encodings removed, for display and search.
    pub fn decoded_body(&self) -> Vec<u8> {
        let mut body = self.body.clone();
        if self.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            if let Some((b, _)) = dechunk(&body) {
                body = b;
            }
        }
        if let Some(enc) = self.header("content-encoding") {
            if let Some(b) = decode(enc, &body) {
                body = b;
            }
        }
        body
    }
}

/// Rewrites an HTTP/2 request from history as HTTP/1.1 so the raw client can send it.
pub fn to_http1(raw: &[u8], host: &str) -> Vec<u8> {
    let mut m = Msg::parse(raw);
    if let Some((rest, _)) = m.first.rsplit_once(' ') {
        m.first = format!("{rest} HTTP/1.1");
    }
    if m.header("host").is_none() {
        m.headers.insert(0, ("Host".into(), host.into()));
    }
    m.render()
}

/// Converts editor text to wire bytes: head lines get CRLF endings, the body is left exact.
/// With `update_length`, a present Content-Length is corrected to the body size.
pub fn to_wire(text: &str, update_length: bool) -> Vec<u8> {
    let b = text.as_bytes();
    let blank = (0..b.len()).find(|&i| b[i] == b'\n' && (b[i + 1..].starts_with(b"\n") || b[i + 1..].starts_with(b"\r\n")));
    let (head, body) = match blank {
        Some(i) => (&b[..i], &b[i + 1 + if b[i + 1] == b'\r' { 2 } else { 1 }..]),
        None => (b, &b[b.len()..]),
    };
    let mut out = Vec::with_capacity(b.len() + 64);
    for line in head.split(|&c| c == b'\n') {
        out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    if update_length {
        let mut m = Msg::parse(&out);
        let before = m.header("content-length").map(str::to_string);
        m.fix_content_length();
        if m.header("content-length").map(str::to_string) != before {
            return m.render();
        }
    }
    out
}

/// Builds a redirect request using browser-style method rewriting. Credentials stay
/// within the same origin, and unsupported schemes are rejected before a send.
pub fn follow_redirect(target: &Target, request: &str, location: &str, status: u16) -> Result<(Target, String), String> {
    let m = Msg::parse(request.as_bytes());
    let old_method = m.first.split_whitespace().next().unwrap_or("GET");
    let current = m.first.split_whitespace().nth(1).unwrap_or("/");
    let base = url::Url::parse(&target.url()).and_then(|base| base.join(current)).map_err(|e| e.to_string())?;
    let mut url = base.join(location).map_err(|e| format!("Invalid redirect URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return Err("Redirect must be an HTTP(S) URL without embedded credentials".into());
    }
    url.set_fragment(None);
    let new_target = Target::from_url(url.as_str()).ok_or("Invalid redirect target")?;
    let same_origin = base.origin() == url.origin();
    let path = &url[url::Position::BeforePath..];
    let get = (status == 303 && old_method != "HEAD") || (matches!(status, 301 | 302) && old_method == "POST");
    let method = if get { "GET" } else { old_method };
    let mut out = Msg { first: format!("{method} {path} HTTP/1.1"), headers: Vec::new(), body: Vec::new() };
    out.headers.push(("Host".into(), new_target.host_header()));
    for (k, v) in &m.headers {
        let lk = k.to_ascii_lowercase();
        let body_header = matches!(lk.as_str(), "content-length" | "content-type" | "transfer-encoding" | "content-encoding");
        let credential = matches!(lk.as_str(), "authorization" | "proxy-authorization" | "cookie" | "cookie2");
        if lk != "host" && (!get || !body_header) && (same_origin || !credential) {
            out.headers.push((k.clone(), v.clone()));
        }
    }
    if !get { out.body = m.body; }
    Ok((new_target, String::from_utf8_lossy(&out.render()).into_owned()))
}

/// A Python `requests` snippet that reproduces a captured request.
pub fn python(url: &str, raw: &[u8]) -> String {
    let lit = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let m = Msg::parse(raw);
    let method = m.first.split_whitespace().next().unwrap_or("GET");
    let mut out = String::from("import requests\n\nheaders = {\n");
    for (k, v) in &m.headers {
        if !matches!(k.to_ascii_lowercase().as_str(), "host" | "content-length") {
            out += &format!("    {}: {},\n", lit(k), lit(v));
        }
    }
    out += "}\n\n";
    let data = if m.body.is_empty() { String::new() } else { format!(", data={}", lit(&String::from_utf8_lossy(&m.body))) };
    out += &format!("r = requests.request({}, {}, headers=headers{data}, verify=False)\n", lit(method), lit(url));
    out + "print(r.status_code)\nprint(r.text)\n"
}

/// A curl command that reproduces a captured request.
pub fn curl(url: &str, raw: &[u8]) -> String {
    let q = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
    let m = Msg::parse(raw);
    let method = m.first.split_whitespace().next().unwrap_or("GET");
    let mut out = format!("curl -i -s -k -X {}", q(method));
    for (k, v) in &m.headers {
        if !matches!(k.to_ascii_lowercase().as_str(), "host" | "content-length") {
            out += &format!(" -H {}", q(&format!("{k}: {v}")));
        }
    }
    if !m.body.is_empty() {
        out += &format!(" --data-binary {}", q(&String::from_utf8_lossy(&m.body)));
    }
    out + " " + &q(url)
}

const STATIC_EXT: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm",
];

/// True for paths to images, stylesheets, fonts and media.
pub fn is_static(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or("").to_ascii_lowercase();
    STATIC_EXT.iter().any(|e| p.ends_with(e))
}

// ---------- body decoding ----------

const MAX_DECODED: u64 = 64 << 20;

/// Undoes a Content-Encoding value (possibly a comma list). `None` if unknown or corrupt.
pub fn decode(encoding: &str, body: &[u8]) -> Option<Vec<u8>> {
    if encoding.split(',').count()>8{return None;}
    let mut data = body.to_vec();
    for enc in encoding.split(',').take(8).collect::<Vec<_>>().into_iter().rev().map(|e| e.trim().to_ascii_lowercase()) {
        let mut out = Vec::new();
        let reader: Box<dyn Read> = match enc.as_str() {
            "identity" | "" => continue,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(&data[..])),
            "deflate" => {
                if flate2::read::ZlibDecoder::new(&data[..]).take(MAX_DECODED+1).read_to_end(&mut out).is_ok() {
                    if out.len() as u64>MAX_DECODED{return None;}
                    data = out;
                    continue;
                }
                out.clear();
                Box::new(flate2::read::DeflateDecoder::new(&data[..]))
            }
            "br" => Box::new(brotli::Decompressor::new(&data[..], 4096)),
            "zstd" => Box::new(zstd::stream::read::Decoder::new(&data[..]).ok()?),
            _ => return None,
        };
        reader.take(MAX_DECODED+1).read_to_end(&mut out).ok()?;
        if out.len() as u64>MAX_DECODED{return None;}
        data = out;
    }
    Some(data)
}

/// Decodes a complete chunked body. Returns the payload and the bytes consumed,
/// or `None` if incomplete or malformed.
pub fn dechunk(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = pos + buf[pos..].windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&buf[pos..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            // Skip trailers up to the final blank line.
            loop {
                let end = pos + buf[pos..].windows(2).position(|w| w == b"\r\n")?;
                let blank = end == pos;
                pos = end + 2;
                if blank {
                    return Some((out, pos));
                }
            }
        }
        let end=pos.checked_add(size)?;let next=end.checked_add(2)?;
        if next>buf.len()||buf.get(end..next)!=Some(b"\r\n"){return None;}
        out.extend_from_slice(&buf[pos..pos + size]);
        pos=next;
    }
}

// ---------- display ----------

#[derive(Clone, Copy, PartialEq, Default)]
pub enum View {
    #[default]
    Raw,
    Pretty,
    Hex,
    Params,
}

const MAX_SHOWN: usize = 256 * 1024;

/// Text for a message viewer. Large messages are cut so egui stays responsive.
pub fn render_view(raw: &[u8], view: View) -> String {
    let mut s = match view {
        View::Raw => String::from_utf8_lossy(&raw[..raw.len().min(MAX_SHOWN)]).into_owned(),
        View::Hex => hexdump(&raw[..raw.len().min(MAX_SHOWN / 4)]),
        View::Params => params_text(&Msg::parse(raw)),
        View::Pretty => {
            let m = Msg::parse(raw);
            let body = m.decoded_body();
            let pretty = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| String::from_utf8_lossy(&body[..body.len().min(MAX_SHOWN)]).into_owned());
            let mut head = String::from_utf8_lossy(&Msg { body: Vec::new(), ..m }.render()).into_owned();
            head.push_str(&pretty);
            head
        }
    };
    if raw.len() > MAX_SHOWN && matches!(view, View::Raw | View::Hex) {
        s.push_str(&format!("\n\n[ferrite: showing part of {} bytes]", raw.len()));
    }
    s
}

fn url_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

/// Splits `a=1&b=2` into decoded pairs.
pub fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (url_decode(k), url_decode(v))
        })
        .collect()
}

/// Inspector-style listing of query, body and cookie parameters.
fn params_text(m: &Msg) -> String {
    let mut out = String::new();
    let mut section = |title: &str, pairs: Vec<(String, String)>| {
        if !pairs.is_empty() {
            out += &format!("{title} ({})\n", pairs.len());
            for (k, v) in pairs {
                out += &format!("  {k} = {v}\n");
            }
            out.push('\n');
        }
    };
    let target = m.first.split_whitespace().nth(1).unwrap_or("");
    if let Some((_, q)) = target.split_once('?') {
        section("Query parameters", form_pairs(q));
    }
    let body = m.decoded_body();
    let ctype = m.header("content-type").unwrap_or("").to_ascii_lowercase();
    if ctype.contains("x-www-form-urlencoded") {
        section("Body parameters", form_pairs(&String::from_utf8_lossy(&body)));
    } else if let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice(&body) {
        section("JSON body", obj.into_iter().map(|(k, v)| (k, v.to_string())).collect());
    }
    let cookies = m
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|c| c.trim().split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    section("Request cookies", cookies);
    let set = m
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| {
            let (kv, attrs) = v.split_once(';').unwrap_or((v, ""));
            let (k, val) = kv.split_once('=').unwrap_or((kv, ""));
            (k.trim().to_string(), format!("{val}   [{}]", attrs.trim()))
        })
        .collect();
    section("Response cookies", set);
    section("Headers", m.headers.clone());
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A browser `fetch()` call reproducing a captured request, for pasting into a devtools console.
pub fn fetch_js(url: &str, raw: &[u8]) -> String {
    let lit = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    let m = Msg::parse(raw);
    let method = m.first.split_whitespace().next().unwrap_or("GET");
    let headers: Vec<String> = m
        .headers
        .iter()
        .filter(|(k, _)| !matches!(k.to_ascii_lowercase().as_str(), "host" | "content-length"))
        .map(|(k, v)| format!("    {}: {}", lit(k), lit(v)))
        .collect();
    let mut opts = vec![format!("  method: {}", lit(method)), format!("  headers: {{\n{}\n  }}", headers.join(",\n"))];
    if !m.body.is_empty() {
        opts.push(format!("  body: {}", lit(&String::from_utf8_lossy(&m.body))));
    }
    opts.push("  credentials: \"include\"".to_string());
    format!("fetch({}, {{\n{}\n}}).then(r => r.text()).then(console.log);", lit(url), opts.join(",\n"))
}

/// An auto-submitting HTML form that replays a request cross-site, like Burp's CSRF PoC.
pub fn csrf_poc(url: &str, raw: &[u8]) -> String {
    let m = Msg::parse(raw);
    let method = m.first.split_whitespace().next().unwrap_or("GET").to_ascii_uppercase();
    let ctype = m.header("content-type").unwrap_or("").to_ascii_lowercase();
    let body = String::from_utf8_lossy(&m.body).into_owned();
    let (action, form_method, enctype, fields) = if method == "GET" {
        let (base, q) = url.split_once('?').unwrap_or((url, ""));
        (base.to_string(), "GET", "", form_pairs(q))
    } else if ctype.contains("x-www-form-urlencoded") || (ctype.is_empty() && body.contains('=')) {
        (url.to_string(), "POST", "", form_pairs(&body))
    } else {
        // text/plain trick: name + "=" + value reproduces an arbitrary body such as JSON.
        let (k, v) = body.split_once('=').unwrap_or((&body, ""));
        let v = if body.contains('=') { v.to_string() } else { String::new() };
        let k = if body.contains('=') { k.to_string() } else { body.clone() };
        (url.to_string(), "POST", " enctype=\"text/plain\"", vec![(k, v)])
    };
    let inputs: String = fields
        .iter()
        .map(|(k, v)| format!("      <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n", html_escape(k), html_escape(v)))
        .collect();
    format!(
        "<html>\n  <body>\n    <form action=\"{}\" method=\"{form_method}\"{enctype}>\n{inputs}      <input type=\"submit\" value=\"Submit request\" />\n    </form>\n    <script>\n      history.pushState('', '', '/');\n      document.forms[0].submit();\n    </script>\n  </body>\n</html>\n",
        html_escape(&action)
    )
}

/// Current time as UTC HH:MM:SS. Avoids a datetime dependency.
pub fn now_hms() -> (u64, String) {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    (ms, hms(ms))
}

/// Formats unix milliseconds as UTC HH:MM:SS (empty for 0).
pub fn hms(ms: u64) -> String {
    if ms == 0 {
        return String::new();
    }
    let secs = ms / 1000;
    format!("{:02}:{:02}:{:02}", secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push(' ');
        out.extend(chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }));
        out.push('\n');
    }
    out
}

// ---------- client ----------

#[derive(Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    pub fn from_url(url: &str) -> Option<Target> {
        let uri: hudsucker::hyper::Uri = url.parse().ok()?;
        if !matches!(uri.scheme_str(), Some("http" | "https" | "ws" | "wss")) { return None; }
        let tls = uri.scheme_str() == Some("https") || uri.scheme_str() == Some("wss");
        Some(Target {
            host: uri.host()?.trim_matches(['[', ']']).to_string(),
            port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
            tls,
        })
    }

    /// Value for a Host header: port omitted when it is the scheme default.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn url(&self) -> String {
        format!("{}://{}", if self.tls { "https" } else { "http" }, self.host_header())
    }
}

/// Path-and-query of an absolute URL (defaults to "/").
pub fn url_path(url: &str) -> String {
    if let Ok(url) = url::Url::parse(url) {
        return url[url::Position::BeforePath..url::Position::AfterQuery].to_string();
    }
    if url.starts_with('/') { url.split('#').next().unwrap_or("/").to_string() } else { "/".to_string() }
}

#[derive(Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub enum Upstream {
    #[default]
    None,
    Http(String),
    Socks5(String),
}

// ponytail: fixed 60s TTL, ignores DNS record TTLs; use a real resolver if that matters
static DNS: Mutex<Option<HashMap<(String, u16), (Instant, Vec<SocketAddr>)>>> = Mutex::new(None);

/// Resolves with a short cache so Intruder does not pay a lookup per request.
async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let key = (host.to_string(), port);
    if let Some((at, addrs)) = DNS.lock().unwrap().get_or_insert_default().get(&key) {
        if at.elapsed() < Duration::from_secs(60) {
            return Ok(addrs.clone());
        }
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    DNS.lock().unwrap().get_or_insert_default().insert(key, (Instant::now(), addrs.clone()));
    Ok(addrs)
}

/// Opens a TCP connection to `host:port`, tunnelling through the upstream proxy if set.
pub async fn dial(host: &str, port: u16, upstream: &Upstream) -> io::Result<TcpStream> {
    match upstream {
        Upstream::None => TcpStream::connect(&resolve(host, port).await?[..]).await,
        Upstream::Socks5(proxy) => tokio_socks::tcp::Socks5Stream::connect(proxy.as_str(), (host, port))
            .await
            .map(|s| s.into_inner())
            .map_err(io::Error::other),
        Upstream::Http(proxy) => {
            let mut s = TcpStream::connect(proxy.as_str()).await?;
            let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await?;
            // Read byte by byte so nothing past the proxy's reply is consumed.
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() > 16 * 1024 {
                    return Err(io::Error::other("upstream proxy reply too large"));
                }
                head.push(s.read_u8().await?);
            }
            match Msg::parse(&head).status() {
                200 => Ok(s),
                code => Err(io::Error::other(format!("upstream proxy refused CONNECT: {code}"))),
            }
        }
    }
}

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS client config that accepts any server certificate, as a testing proxy must.
pub fn insecure_tls() -> ClientConfig {
    let provider = Arc::new(aws_lc_rs::default_provider());
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("default TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth()
}

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub struct Reply {
    pub raw: Vec<u8>,
    pub status: u16,
    pub elapsed: Duration,
}

/// Sends raw bytes exactly as given and reads one response.
pub async fn send(target: &Target, raw: &[u8], upstream: &Upstream) -> Result<Reply, String> {
    let start = Instant::now();
    let work = async {
        let mut stream = connect(target, upstream).await?;
        stream.write_all(raw).await?;
        let head_only = raw.starts_with(b"HEAD ");
        read_response(&mut stream, head_only).await
    };
    let raw = tokio::time::timeout(Duration::from_secs(30), work)
        .await
        .map_err(|_| "timed out after 30s".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(Reply { status: Msg::parse(&raw).status(), raw, elapsed: start.elapsed() })
}

pub(crate) async fn connect(target: &Target, upstream: &Upstream) -> io::Result<Box<dyn Stream>> {
        let tcp = dial(&target.host, target.port, upstream).await?;
        let stream: Box<dyn Stream> = if target.tls {
            let mut cfg = insecure_tls();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name = ServerName::try_from(target.host.clone()).map_err(io::Error::other)?;
            Box::new(tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?)
        } else {
            Box::new(tcp)
        };
        Ok(stream)
}

/// Reads one HTTP/1.x response, using Content-Length, chunked framing or EOF.
pub(crate) async fn read_response(stream: &mut Box<dyn Stream>, head_only: bool) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut read_more = async |buf: &mut Vec<u8>| -> io::Result<bool> {
        let n = stream.read(&mut chunk).await?;
        if buf.len() + n > 16 * 1024 * 1024 { return Err(io::Error::other("response exceeds 16 MiB tool limit")); }
        buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    };
    loop {
        let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
            if !read_more(&mut buf).await? {
                return if buf.is_empty() { Err(io::Error::other("connection closed with no response")) } else { Ok(buf) };
            }
            continue;
        };
        let msg = Msg::parse(&buf[..head_end]);
        let status = msg.status();
        if (100..200).contains(&status) && status != 101 {
            buf.drain(..head_end);
            continue;
        }
        if head_only || status == 204 || status == 304 || status == 101 {
            buf.truncate(head_end);
            return Ok(buf);
        }
        let chunked = msg.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = msg.header("content-length").and_then(|v| v.parse::<usize>().ok());
        loop {
            if chunked {
                if let Some((_, used)) = dechunk(&buf[head_end..]) {
                    buf.truncate(head_end + used);
                    return Ok(buf);
                }
            } else if let Some(len) = length {
                if buf.len() >= head_end + len {
                    buf.truncate(head_end + len);
                    return Ok(buf);
                }
            }
            if !read_more(&mut buf).await? {
                if chunked || length.is_some_and(|len| buf.len() < head_end + len) {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP response body"));
                }
                return Ok(buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_render_roundtrip() {
        let m = Msg::parse(b"POST /x HTTP/1.1\nHost: a\nContent-Length: 1\n\nhello");
        assert_eq!(m.first, "POST /x HTTP/1.1");
        assert_eq!(m.header("host"), Some("a"));
        let mut m = m;
        m.fix_content_length();
        assert_eq!(m.render(), b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello");
    }

    #[test]
    fn wire_format() {
        assert_eq!(to_wire("GET / HTTP/1.1\nHost: a", false), b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(
            to_wire("POST / HTTP/1.1\nContent-Length: 0\n\na\nb", true),
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\na\nb"
        );
        assert_eq!(to_wire("GET / HTTP/1.1\r\nX: 1\r\n\r\nz", false), b"GET / HTTP/1.1\r\nX: 1\r\n\r\nz");
        assert_eq!(curl("http://a/", b"GET / HTTP/1.1\r\nHost: a\r\nX: it's\r\n\r\n"), r"curl -i -s -k -X 'GET' -H 'X: it'\''s' 'http://a/'");
    }

    #[test]
    fn csrf_and_params() {
        let poc = csrf_poc("https://a/x", b"POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.c&n=\"1\"");
        assert!(poc.contains(r#"<form action="https://a/x" method="POST">"#));
        assert!(poc.contains(r#"name="email" value="a@b.c""#));
        assert!(poc.contains(r#"name="n" value="&quot;1&quot;""#));
        let json = csrf_poc("https://a/x", b"POST /x HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"a\":1}");
        assert!(json.contains(r#"enctype="text/plain""#));
        let f = fetch_js("https://a/x", b"POST /x HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"a\":1}");
        assert!(f.contains(r#"fetch("https://a/x""#) && f.contains(r#"method: "POST""#) && f.contains(r#"body: "{\"a\":1}""#));
        let p = params_text(&Msg::parse(b"GET /?q=a+b HTTP/1.1\r\nCookie: s=1; t=2\r\n\r\n"));
        assert!(p.contains("q = a b") && p.contains("t = 2"));
    }

    #[test]
    fn redirects() {
        let t = Target { host: "a.com".into(), port: 443, tls: true };
        let req = "POST /x/y HTTP/1.1\r\nHost: a.com\r\nCookie: s=1\r\nContent-Length: 1\r\n\r\nz";
        let (t2, r) = follow_redirect(&t, req, "http://b.com:81/p?q", 302).unwrap();
        assert_eq!((t2.host.as_str(), t2.port, t2.tls), ("b.com", 81, false));
        assert_eq!(r, "GET /p?q HTTP/1.1\r\nHost: b.com:81\r\n\r\n");
        assert!(follow_redirect(&t, req, "z", 307).unwrap().1.starts_with("POST /x/z HTTP/1.1"));
        assert!(follow_redirect(&t, req, "/top", 301).unwrap().1.starts_with("GET /top "));
    }

    #[test]
    fn redirects_resolve_urls_and_keep_credentials_within_origin() {
        let t = Target::from_url("https://a.com/").unwrap();
        let req = "POST /dir/page?old=1 HTTP/1.1\r\nHost: a.com\r\nAuthorization: Bearer secret\r\nCookie: sid=secret\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ndata";
        let (_, same) = follow_redirect(&t, req, "../done?x=2#top", 307).unwrap();
        let same = Msg::parse(same.as_bytes());
        assert_eq!(same.first, "POST /done?x=2 HTTP/1.1");
        assert_eq!(same.header("authorization"), Some("Bearer secret"));
        assert_eq!(same.body, b"data");
        let (other, request) = follow_redirect(&t, req, "//b.com:8443?x=1", 302).unwrap();
        let request = Msg::parse(request.as_bytes());
        assert_eq!(other.port, 8443);
        assert_eq!(request.first, "GET /?x=1 HTTP/1.1");
        assert!(request.header("cookie").is_none());
        assert!(request.header("authorization").is_none());
        assert!(request.header("content-length").is_none());
        assert!(request.body.is_empty());
        let (_, downgrade) = follow_redirect(&t, req, "http://a.com/", 308).unwrap();
        assert!(Msg::parse(downgrade.as_bytes()).header("authorization").is_none());
        let put = req.replacen("POST", "PUT", 1);
        assert!(follow_redirect(&t, &put, "?new=2", 302).unwrap().1.starts_with("PUT /dir/page?new=2 "));
        let head = req.replacen("POST", "HEAD", 1);
        assert!(follow_redirect(&t, &head, "/done", 303).unwrap().1.starts_with("HEAD /done "));
        for location in ["javascript:alert(1)", "ftp://a.com/", "https://user:pass@b.com/"] {
            assert!(follow_redirect(&t, req, location, 302).is_err());
        }
        assert_eq!(url_path("https://a.com?x=1#top"), "/?x=1");
        let ipv6 = Target::from_url("http://[::1]:8080/").unwrap();
        assert_eq!(ipv6.host_header(), "[::1]:8080");
        assert_eq!(ipv6.url(), "http://[::1]:8080");
    }

    #[test]
    fn dechunks() {
        let (body, used) = dechunk(b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\nNEXT").unwrap();
        assert_eq!(body, b"hello world");
        assert_eq!(used, 30);
        assert!(dechunk(b"5\r\nhel").is_none());
    }

    #[test]
    fn decodes_gzip() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"secret").unwrap();
        assert_eq!(decode("gzip", &e.finish().unwrap()).unwrap(), b"secret");
        assert!(decode("bogus", b"x").is_none());
    }

    #[test]
    fn target_from_url() {
        let t = Target::from_url("https://example.com:8443/a?b").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.tls), ("example.com", 8443, true));
        assert_eq!(Target::from_url("http://x/").unwrap().host_header(), "x");
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Network check for the raw client: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn sends_raw() {
        let t = Target { host: "example.com".into(), port: 443, tls: true };
        let r = send(&t, b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n", &Upstream::None).await.unwrap();
        eprintln!("example {:?}", r.elapsed);
        assert_eq!(r.status, 200);
        let body = Msg::parse(&r.raw).decoded_body();
        assert!(String::from_utf8_lossy(&body).contains("Example Domain"));
        let t = Target { host: "httpbin.org".into(), port: 80, tls: false };
        let r = send(&t, b"GET /stream/3 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n", &Upstream::None).await.unwrap();
        eprintln!("httpbin {:?}", r.elapsed);
        assert_eq!(Msg::parse(&r.raw).decoded_body().iter().filter(|&&b| b == b'\n').count(), 3);
        let t = Target { host: "self-signed.badssl.com".into(), port: 443, tls: true };
        let r = send(&t, b"GET / HTTP/1.1\r\nHost: self-signed.badssl.com\r\nConnection: close\r\n\r\n", &Upstream::None).await.unwrap();
        assert_eq!(r.status, 200);
    }
}

pub type WsStream = hudsucker::tokio_tungstenite::WebSocketStream<hudsucker::tokio_tungstenite::MaybeTlsStream<TcpStream>>;
pub async fn websocket(request: hudsucker::hyper::Request<()>, upstream: &Upstream) -> Result<(WsStream, hudsucker::tokio_tungstenite::tungstenite::handshake::client::Response), String> {
    let uri = request.uri();
    let host = uri.host().ok_or("WebSocket URL has no host")?.trim_matches(['[',']']);
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") {443}else{80});
    let tcp = dial(host,port,upstream).await.map_err(|e|e.to_string())?;
    hudsucker::tokio_tungstenite::client_async_tls_with_config(request,tcp,None,Some(hudsucker::tokio_tungstenite::Connector::Rustls(Arc::new(insecure_tls())))).await.map_err(|e|e.to_string())
}
