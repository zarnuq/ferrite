//! Crawler tab: spiders a site from a start URL, following in-scope links, and feeds every
//! fetched page into the proxy history (so the site map and passive scanner light up too).

use crate::{
    Env, Event,
    http::{self, Msg, Target},
    rules,
};
use eframe::egui;
use hudsucker::futures::{StreamExt, stream};
use regex::Regex;
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

/// History ids for crawled pages, kept well above the proxy's per-session counter to avoid clashes.
static CRAWL_ID: AtomicU64 = AtomicU64::new(1 << 50);

static LINK: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']([^"'#>\s]+)"#).unwrap()
});

/// Resolves a link found on `base` (an absolute URL) to an absolute URL, or `None` to skip it.
pub fn resolve(base: &str, link: &str) -> Option<String> {
    let link = link.trim();
    if link.is_empty() || link.starts_with('#') {
        return None;
    }
    let mut url = url::Url::parse(base).ok()?.join(link).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    url.set_fragment(None);
    Some(url.into())
}

/// Extracts and resolves all links from a page body.
fn links(base: &str, body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    LINK.captures_iter(&text).filter_map(|c| resolve(base, &c[1])).collect()
}

/// Redirects do not consume link depth; the shared visited set breaks redirect loops.
/// Every destination still passes through the crawl's host, scope and request limits.
fn destinations(url: &str, response: &Msg, depth: usize, max_depth: usize, follow: bool) -> Vec<(String, usize)> {
    if matches!(response.status(), 301 | 302 | 303 | 307 | 308) {
        return if follow {
            response.header("location").and_then(|l| resolve(url, l)).map(|u| vec![(u, depth)]).unwrap_or_default()
        } else { Vec::new() };
    }
    let ctype = response.header("content-type").unwrap_or("").to_ascii_lowercase();
    if depth >= max_depth || (!ctype.contains("html") && !ctype.is_empty()) { return Vec::new(); }
    links(url, &response.decoded_body()).into_iter().map(|u| (u, depth + 1)).collect()
}

pub struct Crawler {
    start: String,
    max_pages: usize,
    max_depth: usize,
    threads: usize,
    same_host: bool,
    scope_only: bool,
    follow_redirects: bool,
    use_cookies: bool,
    run: u64,
    crawled: Vec<(String, u16)>,
    errors: Vec<(String, String)>,
    cancel: Option<Arc<AtomicBool>>,
    message: String,
}

impl Default for Crawler {
    fn default() -> Self {
        Crawler {
            start: "https://example.com/".into(),
            max_pages: 100,
            max_depth: 3,
            threads: 8,
            same_host: true,
            scope_only: false,
            follow_redirects: true,
            use_cookies: false,
            run: 0,
            crawled: Vec::new(),
            errors: Vec::new(),
            cancel: None,
            message: String::new(),
        }
    }
}

pub enum Note {
    Page { url: String, status: u16 },
    Failed { url: String, error: String },
    Done,
}

impl Crawler {
    pub fn load(&mut self, url: String) {
        self.start = url;
    }

    pub fn on_note(&mut self, run: u64, note: Note) {
        if run != self.run {
            return;
        }
        match note {
            Note::Page { url, status } => self.crawled.push((url, status)),
            Note::Failed { url, error } => self.errors.push((url, error)),
            Note::Done => {
                self.cancel = None;
                self.message.clear();
            }
        }
    }

    fn start_crawl(&mut self, env: &Env) {
        let Some(start) = resolve(&self.start, &self.start) else {
            self.message = "Invalid start URL".into();
            return;
        };
        let Some(start_target) = Target::from_url(&start) else {
            self.message = "Invalid start URL".into();
            return;
        };
        let scope = rules::current(env.shared);
        if self.scope_only && !scope.in_scope(&start) {
            self.message = "Start URL is outside the configured scope".into();
            return;
        }
        self.message.clear();
        self.run += 1;
        self.crawled.clear();
        self.errors.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());

        let (tx, ui) = (env.tx.clone(), env.egui.clone());
        let upstream = env.upstream();
        let (run, max_pages, max_depth, threads, same_host, scope_only) =
            (self.run, self.max_pages, self.max_depth, self.threads.max(1), self.same_host, self.scope_only);
        let start_host = start_target.host.clone();
        let follow_redirects = self.follow_redirects;
        let session = env.session(self.use_cookies);

        env.rt.spawn(async move {
            let mut visited: HashSet<String> = HashSet::new();
            let mut queue: VecDeque<(String, usize)> = VecDeque::new();
            visited.insert(start.clone());
            queue.push_back((start, 0));
            let mut pages = 0usize;

            // Breadth-first, one wave of up to `threads` pages at a time.
            while !queue.is_empty() && pages < max_pages && !cancel.load(Ordering::Relaxed) {
                let wave: Vec<(String, usize)> = (0..threads.min(max_pages - pages)).filter_map(|_| queue.pop_front()).collect();
                pages += wave.len();
                let batch: Vec<_> = stream::iter(wave)
                    .map(|(url, depth)| {
                        let upstream = upstream.clone();
                        let tx = tx.clone();
                        let session = session.clone();
                        async move {
                            let Some(t) = Target::from_url(&url) else { return (url, depth, Err("Invalid URL".to_string())) };
                            let path = http::url_path(&url);
                            let req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", t.host_header()).into_bytes();
                            let start = Instant::now();
                            let (req, result) = session.send(&t, &req, &upstream).await;
                            let _ = tx.send(Event::Log(crate::logger::entry("Crawler", &t, &req, &result)));
                            match result {
                                Ok(r) => {
                                    let status = r.status;
                                    (url, depth, Ok((req, r.raw, start.elapsed().as_millis(), status)))
                                }
                                Err(e) => (url, depth, Err(e)),
                            }
                        }
                    })
                    .buffer_unordered(threads)
                    .collect()
                    .await;

                for (url, depth, result) in batch {
                    let (req, res, ms, status) = match result {
                        Ok(page) => page,
                        Err(error) => {
                            let _ = tx.send(Event::Crawler { run, note: Note::Failed { url, error } });
                            ui.request_repaint();
                            continue;
                        }
                    };
                    // Feed the page into history: site map + passive scan pick it up.
                    let id = CRAWL_ID.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(Event::Request { id, url: url.clone(), raw: req });
                    let _ = tx.send(Event::Response { id, raw: res.clone(), ms });
                    let _ = tx.send(Event::Crawler { run, note: Note::Page { url: url.clone(), status } });
                    ui.request_repaint();

                    let msg = Msg::parse(&res);
                    for (link, next_depth) in destinations(&url, &msg, depth, max_depth, follow_redirects) {
                        if visited.len() > max_pages * 20 {
                            break;
                        }
                        let Some(lt) = Target::from_url(&link) else { continue };
                        if same_host && lt.host != start_host {
                            continue;
                        }
                        if scope_only && !scope.in_scope(&link) {
                            continue;
                        }
                        if visited.insert(link.clone()) {
                            queue.push_back((link, next_depth));
                        }
                    }
                }
            }
            let _ = tx.send(Event::Crawler { run, note: Note::Done });
            ui.request_repaint();
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let running = self.cancel.is_some();
        ui.horizontal(|ui| {
            ui.label("Start URL");
            ui.add(egui::TextEdit::singleline(&mut self.start).desired_width(360.0).hint_text("https://host/path"));
            if running {
                if ui.button("Stop").clicked() {
                    if let Some(c) = &self.cancel {
                        c.store(true, Ordering::Relaxed);
                        self.message = "Stopping…".into();
                    }
                }
            } else if ui.button("Start crawl").clicked() {
                self.start_crawl(env);
            }
            ui.label(format!("{} pages", self.crawled.len()));
            if !self.errors.is_empty() { ui.label(format!("{} errors", self.errors.len())); }
            ui.colored_label(egui::Color32::LIGHT_RED, &self.message);
        });
        ui.horizontal(|ui| {
            ui.label("Max pages");
            ui.add(egui::DragValue::new(&mut self.max_pages).range(1..=10_000));
            ui.label("Max depth");
            ui.add(egui::DragValue::new(&mut self.max_depth).range(0..=20));
            ui.label("Threads");
            ui.add(egui::DragValue::new(&mut self.threads).range(1..=50));
            ui.checkbox(&mut self.same_host, "Same host only");
            ui.checkbox(&mut self.scope_only, "In-scope only");
            ui.checkbox(&mut self.follow_redirects, "Follow redirects");
            ui.checkbox(&mut self.use_cookies, "Use session cookies");
        });
        ui.separator();
        ui.weak("Crawled pages also appear in Proxy history, the Target site map, and are passively scanned.");
        egui::ScrollArea::vertical().auto_shrink(false).stick_to_bottom(true).show(ui, |ui| {
            for (url, status) in &self.crawled {
                ui.horizontal(|ui| {
                    let color = match status {
                        200..=299 => egui::Color32::from_rgb(120, 200, 120),
                        300..=399 => egui::Color32::from_rgb(120, 175, 255),
                        _ => egui::Color32::from_rgb(230, 150, 60),
                    };
                    ui.add(egui::Label::new(egui::RichText::new(status.to_string()).monospace().color(color)));
                    ui.add(egui::Label::new(egui::RichText::new(url).monospace()).truncate());
                });
            }
            for (url, error) in &self.errors {
                ui.colored_label(egui::Color32::LIGHT_RED, format!("{url}: {error}"));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_links() {
        let b = "https://a.com/dir/page?x=1";
        assert_eq!(resolve(b, "sub.html").unwrap(), "https://a.com/dir/sub.html");
        assert_eq!(resolve(b, "/root").unwrap(), "https://a.com/root");
        assert_eq!(resolve(b, "//cdn.com/x").unwrap(), "https://cdn.com/x");
        assert_eq!(resolve(b, "https://z.com/y?q").unwrap(), "https://z.com/y?q");
        assert_eq!(resolve(b, "page#frag").unwrap(), "https://a.com/dir/page");
        assert!(resolve(b, "mailto:x@y.com").is_none());
        assert!(resolve(b, "javascript:void(0)").is_none());
    }

    #[test]
    fn normalizes_urls_and_rejects_other_protocols() {
        let base = "https://A.com/dir/page?old=1";
        for (link, expected) in [
            ("../end", "https://a.com/end"),
            ("./page#top", "https://a.com/dir/page"),
            ("?new=2", "https://a.com/dir/page?new=2"),
            ("HTTPS://A.COM:443/dir/../end#x", "https://a.com/end"),
        ] {
            assert_eq!(resolve(base, link).as_deref(), Some(expected));
        }
        assert_eq!(resolve("https://a.com?x=1", "?y=2").as_deref(), Some("https://a.com/?y=2"));
        for link in ["ftp://a.com/file", "ws://a.com/", "data:text/html,hi", "tel:123", "#top"] {
            assert!(resolve(base, link).is_none(), "{link}");
        }
    }

    /// Exercise the real sender and UI event channel, including compressed HTML,
    /// relative links, deduplication, host/scope boundaries and exact request budgets.
    #[tokio::test]
    async fn crawls_local_site_with_limits() {
        use std::sync::{Mutex, RwLock, mpsc};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requested = Arc::new(Mutex::new(Vec::new()));
        let seen = requested.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut buf = [0; 1024];
                    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                        let n = socket.read(&mut buf).await.unwrap();
                        if n == 0 { return; }
                        raw.extend_from_slice(&buf[..n]);
                    }
                    let request = String::from_utf8_lossy(&raw);
                    let path = request.split_whitespace().nth(1).unwrap();
                    seen.lock().unwrap().push(path.to_string());
                    if path == "/drop" { return; }
                    let (status, extra) = match path {
                        "/redirect" => ("302 Found", "Location: /end\r\n".to_string()),
                        "/loop-a" => ("301 Moved", "Location: /loop-b\r\n".to_string()),
                        "/loop-b" => ("308 Redirect", "Location: /loop-a\r\n".to_string()),
                        "/external" => ("302 Found", format!("Location: http://localhost:{port}/foreign\r\n")),
                        "/scoped" => ("307 Redirect", "Location: /blocked\r\n".to_string()),
                        _ => ("200 OK", String::new()),
                    };
                    let body = match path {
                        "/" => format!(r#"<a href="/dir/page">page</a><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a><a href="/blocked">scope</a><a href="http://localhost:{port}/foreign">other host</a>"#),
                        "/dir/page" => r#"<a href="../end">end</a><a href="/dir/./page#top">duplicate</a>"#.into(),
                        _ => String::new(),
                    };
                    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    std::io::Write::write_all(&mut encoder, body.as_bytes()).unwrap();
                    let body = encoder.finish().unwrap();
                    let head = format!("HTTP/1.1 {status}\r\n{extra}Content-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    socket.write_all(head.as_bytes()).await.unwrap();
                    socket.write_all(&body).await.unwrap();
                });
            }
        });

        for (start_path, max_pages, max_depth, scope_only, follow_redirects, expected) in [
            ("/", 1, 3, false, true, 1),
            ("/", 2, 3, false, true, 2),
            ("/", 100, 0, false, true, 1),
            ("/", 100, 1, false, true, 6),
            ("/", 100, 3, false, true, 7),
            ("/", 100, 3, true, true, 6),
            ("/redirect", 100, 0, false, true, 2),
            ("/redirect", 100, 0, false, false, 1),
            ("/redirect", 1, 0, false, true, 1),
            ("/loop-a", 100, 0, false, true, 2),
            ("/external", 100, 0, false, true, 1),
            ("/scoped", 100, 0, true, true, 1),
            ("/drop", 1, 0, false, true, 0),
        ] {
            requested.lock().unwrap().clear();
            let cfg = rules::Config { exclude: vec!["/blocked$".into()], ..Default::default() };
            let shared = Arc::new(RwLock::new(Arc::new(rules::Compiled::new(cfg))));
            let (tx, rx) = mpsc::channel();
            let mut actions = Vec::new();
            let mut crawler = Crawler {
                start: format!("http://127.0.0.1:{port}{start_path}#fragment"),
                max_pages, max_depth, scope_only, follow_redirects, ..Default::default()
            };
            crawler.start_crawl(&Env {
                rt: &tokio::runtime::Handle::current(), tx: &tx,
                egui: &egui::Context::default(), shared: &shared, jar: &Arc::default(), actions: &mut actions,
            });
            let mut requests = HashSet::new();
            let mut responses = HashSet::new();
            let mut log_count = 0;
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    while let Ok(event) = rx.try_recv() {
                        match event {
                            Event::Request { id, url, .. } => { requests.insert(id); assert!(!url.contains('#')); }
                            Event::Response { id, .. } => { responses.insert(id); }
                            Event::Crawler { run, note } => crawler.on_note(run, note),
                            Event::Log(_) => log_count += 1,
                            _ => {},
                        }
                    }
                    if crawler.cancel.is_none() { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }).await.expect("crawl timed out");
            assert_eq!(crawler.crawled.len(), expected, "pages={max_pages}, depth={max_depth}, scope={scope_only}");
            assert_eq!(requests, responses, "every history request needs its response");
            assert_eq!(requests.len(), expected);
            let paths = requested.lock().unwrap();
            assert_eq!(paths.len(), expected.max(1), "request budget must hold on the wire");
            assert_eq!(log_count, paths.len(), "all attempts appear in Logger");
            assert_eq!(crawler.errors.len(), usize::from(start_path == "/drop"));
            assert!(!paths.iter().any(|p| p == "/foreign"));
            if start_path == "/" && max_pages == 100 && max_depth > 1 { assert!(paths.iter().any(|p| p == "/end")); }
            if scope_only { assert!(!paths.iter().any(|p| p == "/blocked")); }
        }
        server.abort();
    }

    #[tokio::test]
    async fn rejects_invalid_or_out_of_scope_start() {
        use std::sync::{RwLock, mpsc};
        let cfg = rules::Config { exclude: vec![".*".into()], ..Default::default() };
        let shared = Arc::new(RwLock::new(Arc::new(rules::Compiled::new(cfg))));
        let (tx, rx) = mpsc::channel();
        let mut actions = Vec::new();
        let env = Env {
            rt: &tokio::runtime::Handle::current(), tx: &tx,
            egui: &egui::Context::default(), shared: &shared, jar: &Arc::default(), actions: &mut actions,
        };
        for (start, scope_only, message) in [
            ("ftp://example.com/", false, "Invalid start URL"),
            ("http://example.com/", true, "Start URL is outside the configured scope"),
        ] {
            let mut crawler = Crawler { start: start.into(), scope_only, ..Default::default() };
            crawler.start_crawl(&env);
            assert_eq!(crawler.message, message);
            assert!(crawler.cancel.is_none());
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn extracts_links() {
        let body = "<a href=\"/a\">x</a> <img src='b.png'> <form action=\"https://z.com/f\"> <a href=\"#top\">".as_bytes();
        let found = links("https://h.com/p", body);
        assert!(found.contains(&"https://h.com/a".to_string()));
        assert!(found.contains(&"https://h.com/b.png".to_string()));
        assert!(found.contains(&"https://z.com/f".to_string()));
        assert!(!found.iter().any(|l| l.contains("top")));
    }
}
