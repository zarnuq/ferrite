//! Explicit session-cookie reuse for manual tools. Cookies are conservatively bound to
//! the host that set them; Domain never expands delivery to additional hosts.
use crate::http::{self, Msg, Reply, Target, Upstream};
use eframe::egui;
use std::{sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};

pub type Shared = Arc<Mutex<Jar>>;

#[derive(Clone)]
struct Cookie {
    host: String,
    path: String,
    name: String,
    value: String,
    secure: bool,
    http_only: bool,
    expires: Option<u64>,
}

#[derive(Default)]
pub struct Jar { cookies: Vec<Cookie> }

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

impl Jar {
    fn prune(&mut self) { let t = now(); self.cookies.retain(|c| c.expires.is_none_or(|e| e > t)); }

    pub fn set_cookie(&mut self, url: &str, header: &str) -> Result<(), String> {
        let url = url::Url::parse(url).map_err(|e| e.to_string())?;
        if !matches!(url.scheme(), "http" | "https") { return Err("Use an HTTP(S) URL".into()); }
        let host = url.host_str().ok_or("URL has no host")?.trim_matches(['[', ']']).to_ascii_lowercase();
        let mut parts = header.split(';');
        let (name, value) = parts.next().unwrap_or("").trim().split_once('=').ok_or("Use name=value; Path=/; ...")?;
        if name.is_empty() || name.bytes().any(|b| !b.is_ascii_graphic() || b"()<>@,;:\\\"/[]?={}".contains(&b))
            || value.bytes().any(|b| b < 0x20 || b == 0x7f) { return Err("Invalid cookie name or value".into()); }
        let default_path = url.path().rfind('/').filter(|&i| i > 0).map(|i| &url.path()[..i]).unwrap_or("/");
        let mut cookie = Cookie { host: host.clone(), path: default_path.into(), name: name.into(), value: value.into(), secure: false, http_only: false, expires: None };
        let mut max_age = None;
        let mut domain = false;
        let mut explicit_path = false;
        for part in parts {
            let (key, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
            match key.to_ascii_lowercase().as_str() {
                "path" if value.starts_with('/') => { cookie.path = value.into(); explicit_path = true; },
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                "domain" => {
                    domain = true;
                    let value = value.trim_start_matches('.').to_ascii_lowercase();
                    if value.is_empty() || (host != value && !host.ends_with(&format!(".{value}"))) { return Err("Cookie Domain does not match its source host".into()); }
                }
                "max-age" => max_age = value.parse::<i64>().ok(),
                "expires" => cookie.expires = httpdate::parse_http_date(value).ok().and_then(|t| Some(t.duration_since(UNIX_EPOCH).unwrap_or_default())).map(|d| d.as_secs()),
                _ => {},
            }
        }
        if let Some(age) = max_age { cookie.expires = Some(if age <= 0 { 0 } else { now().saturating_add((age as u64).min(400 * 24 * 60 * 60)) }); }
        if cookie.secure && url.scheme() != "https" { return Err("A Secure cookie must be captured from HTTPS".into()); }
        if name.starts_with("__Secure-") && !cookie.secure { return Err("__Secure- cookies require Secure".into()); }
        if name.starts_with("__Host-") && (!cookie.secure || cookie.path != "/" || domain || !explicit_path) { return Err("__Host- cookies require Secure, Path=/ and no Domain".into()); }
        self.cookies.retain(|c| c.host != cookie.host || c.path != cookie.path || c.name != cookie.name);
        self.cookies.push(cookie);
        self.prune();
        // A long fuzzing run can emit a distinct cookie on every response.
        if self.cookies.len() > 2_000 { self.cookies.remove(0); }
        Ok(())
    }

    pub fn capture(&mut self, url: &str, response: &[u8]) {
        for (key, value) in Msg::parse(response).headers {
            if key.eq_ignore_ascii_case("set-cookie") { let _ = self.set_cookie(url, &value); }
        }
    }

    pub fn apply(&mut self, target: &Target, request: &[u8]) -> Vec<u8> {
        self.prune();
        let mut msg = Msg::parse(request);
        let request_path = msg.first.split_whitespace().nth(1).unwrap_or("/").split('?').next().unwrap_or("/");
        let mut matching: Vec<_> = self.cookies.iter().filter(|c| c.host == target.host.to_ascii_lowercase()
            && (!c.secure || target.tls) && path_matches(&c.path, request_path)).collect();
        if matching.is_empty() { return request.to_vec(); }
        matching.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        let mut values: Vec<String> = msg.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, value)| value.split(';')).map(str::trim).filter(|c| !c.is_empty())
            .filter(|c| !matching.iter().any(|m| c.split_once('=').is_some_and(|(name, _)| name == m.name))).map(str::to_string).collect();
        values.extend(matching.into_iter().map(|c| format!("{}={}", c.name, c.value)));
        msg.headers.retain(|(key, _)| !key.eq_ignore_ascii_case("cookie"));
        msg.set_header("Cookie", values.join("; "));
        msg.render()
    }
}

fn path_matches(cookie: &str, request: &str) -> bool {
    request == cookie || (request.starts_with(cookie) && (cookie.ends_with('/') || request.as_bytes().get(cookie.len()) == Some(&b'/')))
}

#[derive(Clone)]
pub struct Client { jar: Shared, reuse: bool, capture: bool }

impl Client {
    pub fn new(jar: Shared, reuse: bool, capture: bool) -> Self { Self { jar, reuse, capture } }
    pub fn prepare(&self, target: &Target, request: &[u8]) -> Vec<u8> {
        if self.reuse { self.jar.lock().unwrap().apply(target, request) } else { request.to_vec() }
    }
    pub fn capture(&self, target: &Target, request: &[u8], result: &Result<Reply, String>) {
        if !self.capture { return; }
        if let Ok(reply) = result {
            let path = Msg::parse(request).first.split_whitespace().nth(1).unwrap_or("/").to_string();
            self.jar.lock().unwrap().capture(&format!("{}{path}", target.url()), &reply.raw);
        }
    }
    pub async fn send(&self, target: &Target, request: &[u8], upstream: &Upstream) -> (Vec<u8>, Result<Reply, String>) {
        let sent = self.prepare(target, request);
        let result = http::send(target, &sent, upstream).await;
        self.capture(target, &sent, &result);
        (sent, result)
    }
}

pub struct Sessions {
    pub jar: Shared,
    url: String,
    header: String,
    message: String,
    search: String,
}
impl Default for Sessions {
    fn default() -> Self { Self { jar: Arc::default(), url: "https://example.com/".into(), header: String::new(), message: String::new(), search: String::new() } }
}
impl Sessions {
    pub fn ui(&mut self, ui: &mut egui::Ui, capture: &mut bool) {
        ui.heading("Session cookie jar");
        ui.checkbox(capture, "Capture Set-Cookie from proxy and tool responses");
        ui.label("Enable Use session cookies in Repeater, Crawler or Discovery to reuse captured cookies.");
        ui.weak("Cookies stay in memory and are bound to their source host. Path, Secure and expiration are respected; Domain does not expand delivery to subdomains.");
        ui.horizontal(|ui| {
            ui.label("URL"); ui.add(egui::TextEdit::singleline(&mut self.url).desired_width(300.0));
            ui.label("Set-Cookie"); ui.add(egui::TextEdit::singleline(&mut self.header).hint_text("sid=value; Path=/; Secure").desired_width(350.0));
            if ui.button("Add / update").clicked() { self.message = match self.jar.lock().unwrap().set_cookie(&self.url, &self.header) { Ok(()) => "Cookie updated".into(), Err(e) => e }; }
        });
        ui.label(&self.message);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Filter host or name"));
            if ui.button("Clear jar").clicked() { self.jar.lock().unwrap().cookies.clear(); }
        });
        let mut jar = self.jar.lock().unwrap(); jar.prune();
        ui.label(format!("{} cookies", jar.cookies.len()));
        let needle = self.search.to_ascii_lowercase();
        let mut remove = None;
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("cookie_jar").striped(true).show(ui, |ui| {
                for name in ["Host", "Path", "Name", "Value", "Secure", "HttpOnly", "Expires", ""] { ui.strong(name); } ui.end_row();
                for (i, cookie) in jar.cookies.iter_mut().enumerate().filter(|(_, c)| needle.is_empty() || c.host.contains(&needle) || c.name.to_ascii_lowercase().contains(&needle)) {
                    ui.label(&cookie.host); ui.label(&cookie.path); ui.label(&cookie.name);
                    let mut edited = cookie.value.clone();
                    if ui.add(egui::TextEdit::singleline(&mut edited).id_salt(i).min_size(egui::vec2(200.0, 20.0))).changed() {
                        if edited.bytes().any(|b| b < 0x20 || b == 0x7f || b == b';') {
                            self.message = "Cookie values cannot contain delimiters or control characters".into();
                        } else { cookie.value = edited; }
                    }
                    ui.label(if cookie.secure { "Yes" } else { "No" }); ui.label(if cookie.http_only { "Yes" } else { "No" });
                    ui.label(cookie.expires.map(|t| httpdate::fmt_http_date(UNIX_EPOCH + std::time::Duration::from_secs(t))).unwrap_or_else(|| "Session".into()));
                    if ui.button("Delete").clicked() { remove = Some(i); } ui.end_row();
                }
            });
        });
        if let Some(i) = remove { jar.cookies.remove(i); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookies_obey_host_path_secure_and_expiry_boundaries() {
        let mut jar = Jar::default();
        jar.set_cookie("https://app.example.com/admin/login", "sid=root; Path=/; Secure; HttpOnly").unwrap();
        jar.set_cookie("https://app.example.com/admin/login", "sid=admin; Secure").unwrap();
        let t = Target::from_url("https://app.example.com/").unwrap();
        let sent = jar.apply(&t, b"GET /admin/users HTTP/1.1\r\nCookie: sid=old; other=keep\r\n\r\n");
        assert_eq!(Msg::parse(&sent).header("cookie"), Some("other=keep; sid=admin; sid=root"));
        let sent = jar.apply(&t, b"GET /administrator HTTP/1.1\r\n\r\n");
        assert_eq!(Msg::parse(&sent).header("cookie"), Some("sid=root"));
        let plain = Target::from_url("http://app.example.com/").unwrap();
        assert!(Msg::parse(&jar.apply(&plain, b"GET / HTTP/1.1\r\n\r\n")).header("cookie").is_none());
        jar.set_cookie("https://app.example.com/", "sid=deleted; Path=/; Max-Age=0; Secure").unwrap();
        assert!(Msg::parse(&jar.apply(&t, b"GET / HTTP/1.1\r\n\r\n")).header("cookie").is_none());
        assert!(jar.set_cookie("https://app.example.com/", "x=1; Domain=other.com").is_err());
        jar.set_cookie("https://app.example.com/", "domain=1; Domain=example.com; Path=/").unwrap();
        let other = Target::from_url("https://other.example.com/").unwrap();
        assert!(Msg::parse(&jar.apply(&other, b"GET / HTTP/1.1\r\n\r\n")).header("cookie").is_none());
        jar.set_cookie("https://app.example.com/", "expired=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        assert!(!jar.cookies.iter().any(|c| c.name == "expired"));
    }
    #[tokio::test]
    async fn captures_and_reuses_a_rotating_session_on_the_wire() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port(), tls: false };
        let server = tokio::spawn(async move {
            for n in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 { panic!("missing request headers"); }
                    request.extend_from_slice(&buf[..n]);
                }
                if n == 1 { assert_eq!(Msg::parse(&request).header("cookie"), Some("other=keep; sid=new")); }
                socket.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=new; Path=/; HttpOnly\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            }
        });
        let jar: Shared = Arc::default();
        let client = Client::new(jar.clone(), true, true);
        let raw = b"GET /private HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: other=keep; sid=old\r\nConnection: close\r\n\r\n";
        let (_, first) = client.send(&target, raw, &Upstream::None).await;
        assert_eq!(first.unwrap().status, 200);
        let (sent, second) = client.send(&target, raw, &Upstream::None).await;
        assert_eq!(second.unwrap().status, 200);
        assert_eq!(Msg::parse(&sent).header("cookie"), Some("other=keep; sid=new"));
        server.await.unwrap();
        assert_eq!(jar.lock().unwrap().cookies.len(), 1);
    }

    #[test]
    fn disabled_reuse_preserves_wire_bytes_and_cookie_prefixes_are_checked() {
        let shared: Shared = Arc::default();
        shared.lock().unwrap().set_cookie("https://example.com/", "sid=new; Path=/").unwrap();
        let client = Client::new(shared.clone(), false, true);
        let raw = b"GET / HTTP/1.1\r\nCookie: sid=old\r\n\r\n";
        assert_eq!(client.prepare(&Target::from_url("https://example.com/").unwrap(), raw), raw);
        let mut jar = shared.lock().unwrap();
        assert!(jar.set_cookie("http://example.com/", "s=1; Secure").is_err());
        assert!(jar.set_cookie("https://example.com/", "__Host-s=1; Secure; Domain=example.com").is_err());
        assert!(jar.set_cookie("https://example.com/", "__Secure-s=1").is_err());
    }
}
