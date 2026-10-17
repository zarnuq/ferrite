//! Content discovery tab: requests a wordlist of paths and files against a target
//! and lists what exists, so hidden endpoints surface. Like Burp's content discovery / dirb.

use crate::{
    Env, Event,
    Viewer,
    http::{self, Msg, Target},
    message_view, send_menu,
};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Common directory and file names to probe when no wordlist is supplied.
const DEFAULT_WORDS: &str = "\
admin
administrator
login
logout
dashboard
api
api/v1
api/v2
app
assets
backup
backups
config
config.php
config.json
.env
.git/HEAD
.git/config
.gitignore
.htaccess
.svn
db
database
debug
dev
docs
download
downloads
files
images
img
js
css
include
includes
internal
js
log
logs
old
private
public
robots.txt
sitemap.xml
secret
server-status
setup
static
status
temp
test
tests
tmp
upload
uploads
user
users
wp-admin
wp-login.php
phpinfo.php
info.php
.well-known/security.txt";

struct Row {
    path: String,
    status: u16,
    length: usize,
    raw: Vec<u8>,
    redirect: String,
    error: String,
    depth: usize,
}

pub struct Discovery {
    target: Target,
    base: String,
    words: String,
    extensions: String,
    threads: usize,
    hide_404: bool,
    use_cookies: bool,
    recursive: bool,
    max_depth: usize,
    queue: VecDeque<(String, usize)>,
    seen_bases: HashSet<String>,
    run: u64,
    rows: Vec<Row>,
    sent: usize,
    done: usize,
    cancel: Option<Arc<AtomicBool>>,
    load_path: String,
    message: String,
    selected: Option<usize>,
    view: Viewer,
    split: f32,
}

impl Default for Discovery {
    fn default() -> Self {
        Discovery {
            target: Target { host: "example.com".into(), port: 443, tls: true },
            base: "/".into(),
            words: DEFAULT_WORDS.into(),
            extensions: String::new(),
            threads: 20,
            hide_404: true,
            use_cookies: false,
            recursive: false,
            max_depth: 2,
            queue: VecDeque::new(),
            seen_bases: HashSet::new(),
            run: 0,
            rows: Vec::new(),
            sent: 0,
            done: 0,
            cancel: None,
            load_path: String::new(),
            message: String::new(),
            selected: None,
            view: Viewer::new(http::View::Raw),
            split: 0.5,
        }
    }
}

impl Discovery {
    /// Seeds the target and base directory from a request sent here.
    pub fn load(&mut self, target: Target, raw: Vec<u8>) {
        let m = Msg::parse(&raw);
        let path = m.first.split_whitespace().nth(1).unwrap_or("/");
        let path = path.split('?').next().unwrap_or("/");
        // Use the containing directory as the base.
        self.base = path[..path.rfind('/').map_or(0, |i| i + 1)].to_string();
        self.target = target;
    }

    pub fn on_result(&mut self, run: u64, idx: usize, result: Result<http::Reply, String>) {
        if run != self.run {
            return;
        }
        self.done += 1;
        let mut child = None;
        if let Some(row) = self.rows.get_mut(idx) {
            match result {
                Ok(r) => {
                    row.status = r.status;
                    row.length = r.raw.len();
                    row.redirect = Msg::parse(&r.raw).header("location").unwrap_or("").to_string();
                    row.raw = r.raw;
                    // A hit on an extension-less path is likely a directory worth recursing into.
                    let last = row.path.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
                    let is_dir = matches!(row.status, 200 | 301 | 302 | 307 | 308 | 403) && !last.contains('.');
                    if self.recursive && is_dir && row.depth < self.max_depth {
                        child = Some((format!("{}/", row.path.trim_end_matches('/')), row.depth + 1));
                    }
                }
                Err(e) => row.error = e,
            }
        }
        if let Some((base, depth)) = child {
            if self.seen_bases.insert(base.trim_end_matches('/').to_string()) {
                self.queue.push_back((base, depth));
            }
        }
        // Batch finished: mark idle so the UI pumps the next queued base (recursion).
        if self.done == self.sent && self.cancel.is_some() {
            self.cancel = None;
        }
    }

    /// Expands the wordlist with extensions and joins each onto the base path.
    fn paths_for(&self, base: &str) -> Vec<String> {
        let exts: Vec<&str> = self.extensions.split(|c| c == ',' || c == ' ' || c == '\n').map(str::trim).filter(|e| !e.is_empty()).collect();
        let base = if base.starts_with('/') { base.to_string() } else { format!("/{base}") };
        let base = if base.ends_with('/') { base } else { format!("{base}/") };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for word in self.words.lines().map(str::trim).filter(|w| !w.is_empty() && !w.starts_with('#')) {
            let word = word.trim_start_matches('/');
            let mut variants = vec![word.to_string()];
            for e in &exts {
                let dot = if e.starts_with('.') { "" } else { "." };
                variants.push(format!("{word}{dot}{e}"));
            }
            for v in variants {
                let path = format!("{base}{v}");
                if seen.insert(path.clone()) {
                    out.push(path);
                }
            }
        }
        out
    }

    fn start(&mut self, env: &Env) {
        if self.words.lines().all(|w| w.trim().is_empty() || w.starts_with('#')) {
            self.message = "Wordlist is empty.".into();
            return;
        }
        self.message.clear();
        self.run += 1;
        self.done = 0;
        self.sent = 0;
        self.rows.clear();
        self.selected = None;
        self.queue.clear();
        self.seen_bases.clear();
        let base = self.base.clone();
        self.seen_bases.insert(base.trim_end_matches('/').to_string());
        self.queue.push_back((base, 0));
        self.cancel = Some(Arc::new(AtomicBool::new(false)));
        self.pump(env);
    }

    /// Scans the next queued base directory, appending its probes to the current run.
    fn pump(&mut self, env: &Env) {
        let Some((base, depth)) = self.queue.pop_front() else {
            self.cancel = None;
            return;
        };
        let paths = self.paths_for(&base);
        let base_idx = self.rows.len();
        self.sent += paths.len();
        for p in &paths {
            self.rows.push(Row { path: p.clone(), status: 0, length: 0, raw: Vec::new(), redirect: String::new(), error: String::new(), depth });
        }
        let cancel = self.cancel.clone().unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let host_header = self.target.host_header();
        let requests: Vec<(usize, Vec<u8>)> = paths
            .into_iter()
            .enumerate()
            .map(|(i, p)| (base_idx + i, format!("GET {p} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n").into_bytes()))
            .collect();
        let (tx, ui, target, upstream) = (env.tx.clone(), env.egui.clone(), self.target.clone(), env.upstream());
        let (run, threads) = (self.run, self.threads.max(1));
        let session = env.session(self.use_cookies);
        env.rt.spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(threads));
            for (idx, raw) in requests {
                let permit = limit.clone().acquire_owned().await.unwrap();
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let (tx, ui, target, upstream) = (tx.clone(), ui.clone(), target.clone(), upstream.clone());
                let session = session.clone();
                tokio::spawn(async move {
                    let (raw, result) = session.send(&target, &raw, &upstream).await;
                    let _ = tx.send(Event::Log(crate::logger::entry("Discovery", &target, &raw, &result)));
                    let _ = tx.send(Event::Discovery { run, idx, result });
                    ui.request_repaint();
                    drop(permit);
                });
            }
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        // Start the next queued directory once the current batch drains (recursion step).
        if self.cancel.is_none() && !self.queue.is_empty() {
            self.cancel = Some(Arc::new(std::sync::atomic::AtomicBool::new(false)));
            self.pump(env);
        }
        // Still running while a batch is in flight or recursion has queued dirs.
        let running = self.cancel.is_some() || !self.queue.is_empty();
        ui.horizontal(|ui| {
            ui.label("Target");
            ui.add(egui::TextEdit::singleline(&mut self.target.host).desired_width(200.0));
            ui.add(egui::DragValue::new(&mut self.target.port).range(1..=65535));
            ui.checkbox(&mut self.target.tls, "HTTPS");
            ui.label("Base");
            ui.add(egui::TextEdit::singleline(&mut self.base).desired_width(120.0));
            ui.label("Threads");
            ui.add(egui::DragValue::new(&mut self.threads).range(1..=100));
            if running {
                if ui.button("Stop").clicked() {
                    self.queue.clear();
                    if let Some(c) = self.cancel.take() {
                        c.store(true, Ordering::Relaxed);
                    }
                }
            } else if ui.button("Start").clicked() {
                self.start(env);
            }
            if self.sent > 0 {
                let found = self.rows.iter().filter(|r| r.status != 0 && r.status != 404 && r.error.is_empty()).count();
                ui.label(format!("{}/{} done, {found} found", self.done, self.sent));
            }
            ui.colored_label(egui::Color32::LIGHT_RED, &self.message);
        });
        ui.horizontal(|ui| {
            ui.label("Extensions");
            ui.add(egui::TextEdit::singleline(&mut self.extensions).hint_text("php, html, bak").desired_width(160.0));
            ui.checkbox(&mut self.hide_404, "Hide 404");
            ui.checkbox(&mut self.use_cookies, "Use session cookies");
            ui.checkbox(&mut self.recursive, "Recursive").on_hover_text("Scan inside directories that are found");
            if self.recursive {
                ui.label("Max depth");
                ui.add(egui::DragValue::new(&mut self.max_depth).range(1..=8));
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut self.load_path).hint_text("/path/to/wordlist").desired_width(200.0));
            if ui.button("Load wordlist").clicked() {
                match std::fs::read_to_string(&self.load_path) {
                    Ok(t) => self.words = t,
                    Err(e) => self.message = format!("{}: {e}", self.load_path),
                }
            }
            if ui.button("Reset wordlist").clicked() {
                self.words = DEFAULT_WORDS.into();
            }
            ui.weak(format!("{} words", self.words.lines().filter(|w| !w.trim().is_empty()).count()));
        });
        ui.separator();

        let (top, bottom) = crate::vsplit(ui, "disco_split", &mut self.split);
        let mut order: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                !self.hide_404 || r.status == 0 && r.error.is_empty() && self.cancel.is_some() || (r.status != 0 && r.status != 404) || !r.error.is_empty()
            })
            .collect();
        // Interesting statuses first: 2xx, then 3xx, then 401/403, then others.
        let rank = |s: u16| match s {
            200..=299 => 0,
            301 | 302 | 307 | 308 => 1,
            401 | 403 => 2,
            0 => 9,
            _ => 3,
        };
        order.sort_by_key(|&i| (rank(self.rows[i].status), self.rows[i].path.clone()));

        let mut pick = None;
        crate::in_rect(ui, top, |ui| {
            TableBuilder::new(ui)
                .id_salt("disco_table")
                .striped(true)
                .sense(egui::Sense::click())
                .column(Column::remainder().clip(true))
                .column(Column::auto().at_least(50.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::remainder().clip(true))
                .header(20.0, |mut h| {
                    for name in ["Path", "Status", "Length", "Redirect / error"] {
                        h.col(|ui| {
                            ui.strong(name);
                        });
                    }
                })
                .body(|body| {
                    body.rows(18.0, order.len(), |mut row| {
                        let i = order[row.index()];
                        let r = &self.rows[i];
                        row.set_selected(self.selected == Some(i));
                        let status = if !r.error.is_empty() {
                            "err".to_string()
                        } else if r.status == 0 {
                            String::new()
                        } else {
                            r.status.to_string()
                        };
                        let note = if r.error.is_empty() { r.redirect.clone() } else { r.error.clone() };
                        let cells = [r.path.clone(), status, if r.status == 0 { String::new() } else { r.length.to_string() }, note];
                        for (c, text) in cells.into_iter().enumerate() {
                            row.col(|ui| {
                                let mut label = egui::RichText::new(text);
                                if c == 1 && (200..300).contains(&r.status) {
                                    label = label.color(egui::Color32::from_rgb(120, 200, 120));
                                }
                                ui.add(egui::Label::new(label).truncate().selectable(false));
                            });
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            pick = Some(i);
                        }
                        let url = format!("{}{}", self.target.url(), r.path);
                        resp.context_menu(|ui| {
                            let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", r.path, self.target.host_header());
                            send_menu(ui, env, &url, req.as_bytes(), (!r.raw.is_empty()).then_some(r.raw.as_slice()));
                        });
                    });
                });
        });
        if pick.is_some() {
            self.selected = pick;
        }
        crate::in_rect(ui, bottom, |ui| match self.selected.and_then(|i| self.rows.get(i)) {
            Some(r) if !r.raw.is_empty() => message_view(ui, "disco_resp", &r.raw, &mut self.view),
            Some(r) if !r.error.is_empty() => {
                ui.weak(&r.error);
            }
            _ => {
                ui.weak("Select a result with a response.");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_paths() {
        let mut d = Discovery::default();
        d.base = "app".into();
        d.words = "admin\n/login\n# comment\nconfig".into();
        d.extensions = "php, .bak".into();
        let paths = d.paths_for("app");
        assert!(paths.contains(&"/app/admin".to_string()));
        assert!(paths.contains(&"/app/login.php".to_string()));
        assert!(paths.contains(&"/app/config.bak".to_string()));
        assert!(!paths.iter().any(|p| p.contains("comment")));
        // No duplicates.
        let unique: HashSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), paths.len());
    }
}
