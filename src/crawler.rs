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
    let lower = link.to_ascii_lowercase();
    if link.is_empty() || ["mailto:", "javascript:", "tel:", "data:", "#", "ftp:"].iter().any(|p| lower.starts_with(p)) {
        return None;
    }
    let (scheme, rest) = base.split_once("://")?;
    let (authority, base_path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let abs = if link.starts_with("http://") || link.starts_with("https://") {
        link.to_string()
    } else if let Some(pr) = link.strip_prefix("//") {
        format!("{scheme}://{pr}")
    } else if link.starts_with('/') {
        format!("{scheme}://{authority}{link}")
    } else {
        let dir = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        format!("{scheme}://{authority}{dir}{link}")
    };
    // Drop the fragment; keep the query.
    Some(abs.split('#').next().unwrap_or(&abs).to_string())
}

/// Extracts and resolves all links from a page body.
fn links(base: &str, body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    LINK.captures_iter(&text).filter_map(|c| resolve(base, &c[1])).collect()
}

pub struct Crawler {
    start: String,
    max_pages: usize,
    max_depth: usize,
    threads: usize,
    same_host: bool,
    scope_only: bool,
    run: u64,
    crawled: Vec<(String, u16)>,
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
            run: 0,
            crawled: Vec::new(),
            cancel: None,
            message: String::new(),
        }
    }
}

pub enum Note {
    Page { url: String, status: u16 },
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
            Note::Done => self.cancel = None,
        }
    }

    fn start_crawl(&mut self, env: &Env) {
        let Some(start_target) = Target::from_url(&self.start) else {
            self.message = "Invalid start URL".into();
            return;
        };
        self.message.clear();
        self.run += 1;
        self.crawled.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());

        let (tx, ui) = (env.tx.clone(), env.egui.clone());
        let upstream = env.upstream();
        let scope = rules::current(env.shared);
        let (run, max_pages, max_depth, threads, same_host, scope_only) =
            (self.run, self.max_pages, self.max_depth, self.threads.max(1), self.same_host, self.scope_only);
        let start = self.start.clone();
        let start_host = start_target.host.clone();

        env.rt.spawn(async move {
            let mut visited: HashSet<String> = HashSet::new();
            let mut queue: VecDeque<(String, usize)> = VecDeque::new();
            visited.insert(start.clone());
            queue.push_back((start, 0));
            let mut pages = 0usize;

            // Breadth-first, one wave of up to `threads` pages at a time.
            while !queue.is_empty() && pages < max_pages && !cancel.load(Ordering::Relaxed) {
                let wave: Vec<(String, usize)> = (0..threads).filter_map(|_| queue.pop_front()).collect();
                let batch: Vec<(String, usize, Option<(Vec<u8>, Vec<u8>, u128, u16)>)> = stream::iter(wave)
                    .map(|(url, depth)| {
                        let upstream = upstream.clone();
                        async move {
                            let Some(t) = Target::from_url(&url) else { return (url, depth, None) };
                            let path = http::url_path(&url);
                            let req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", t.host_header()).into_bytes();
                            let start = Instant::now();
                            match http::send(&t, &req, &upstream).await {
                                Ok(r) => {
                                    let status = r.status;
                                    (url, depth, Some((req, r.raw, start.elapsed().as_millis(), status)))
                                }
                                Err(_) => (url, depth, None),
                            }
                        }
                    })
                    .buffer_unordered(threads)
                    .collect()
                    .await;

                for (url, depth, result) in batch {
                    let Some((req, res, ms, status)) = result else { continue };
                    pages += 1;
                    // Feed the page into history: site map + passive scan pick it up.
                    let id = CRAWL_ID.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(Event::Request { id, url: url.clone(), raw: req });
                    let _ = tx.send(Event::Response { id, raw: res.clone(), ms });
                    let _ = tx.send(Event::Crawler { run, note: Note::Page { url: url.clone(), status } });
                    ui.request_repaint();

                    if depth >= max_depth {
                        continue;
                    }
                    let ctype = Msg::parse(&res).header("content-type").unwrap_or("").to_ascii_lowercase();
                    if !ctype.contains("html") && !ctype.is_empty() {
                        continue;
                    }
                    for link in links(&url, &res) {
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
                            queue.push_back((link, depth + 1));
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
                    if let Some(c) = self.cancel.take() {
                        c.store(true, Ordering::Relaxed);
                    }
                }
            } else if ui.button("Start crawl").clicked() {
                self.start_crawl(env);
            }
            ui.label(format!("{} pages", self.crawled.len()));
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
    fn extracts_links() {
        let body = "<a href=\"/a\">x</a> <img src='b.png'> <form action=\"https://z.com/f\"> <a href=\"#top\">".as_bytes();
        let found = links("https://h.com/p", body);
        assert!(found.contains(&"https://h.com/a".to_string()));
        assert!(found.contains(&"https://h.com/b.png".to_string()));
        assert!(found.contains(&"https://z.com/f".to_string()));
        assert!(!found.iter().any(|l| l.contains("top")));
    }
}
