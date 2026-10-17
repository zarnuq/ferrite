//! Background search over a snapshot of captured and tool-generated HTTP messages.
use crate::{Env, Event, Viewer, history::History, http::Msg, in_rect, logger::Logger, message_view, send_menu, vsplit};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use regex::{Regex, RegexBuilder};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

const MAX_RESULTS: usize = 10_000;

pub struct Document {
    pub source: String,
    pub url: String,
    pub req: Vec<u8>,
    pub res: Option<Vec<u8>>,
    pub note: String,
}

pub struct Hit {
    doc: Document,
    count: usize,
    location: String,
    excerpt: String,
}

pub struct Results {
    hits: Vec<Hit>,
    truncated: bool,
}

#[derive(Clone)]
struct Options {
    requests: bool,
    responses: bool,
    headers: bool,
    bodies: bool,
    urls: bool,
    notes: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { requests: true, responses: true, headers: true, bodies: true, urls: true, notes: true }
    }
}

fn search(docs: Vec<Document>, re: &Regex, options: &Options, cancel: &AtomicBool) -> Results {
    let mut hits = Vec::new();
    let mut truncated = false;
    for doc in docs {
        if cancel.load(Ordering::Relaxed) { break; }
        let mut count = 0;
        let mut location = String::new();
        let mut excerpt = String::new();
        let mut inspect = |part: &str, text: &str| {
            // A pathological expression can match every position. Bound work and counts per part.
            let mut matches = re.find_iter(text).take(10_000).peekable();
            if let Some(first) = matches.peek() {
                if location.is_empty() {
                    location = part.to_string();
                    let start = text[..first.start()].char_indices().rev().nth(30).map_or(0, |(i, _)| i);
                    excerpt = text[start..].chars().take(160).map(|c| if c.is_control() { ' ' } else { c }).collect();
                }
            }
            count += matches.count();
        };
        if options.urls { inspect("URL", &doc.url); }
        if options.notes { inspect("Note", &doc.note); }
        for (name, enabled, raw) in [
            ("Request", options.requests, Some(doc.req.as_slice())),
            ("Response", options.responses, doc.res.as_deref()),
        ] {
            let Some(raw) = raw.filter(|_| enabled) else { continue };
            let msg = Msg::parse(raw);
            if options.headers {
                let head = Msg { first: msg.first.clone(), headers: msg.headers.clone(), body: Vec::new() }.render();
                inspect(&format!("{name} headers"), &String::from_utf8_lossy(&head));
            }
            if options.bodies {
                inspect(&format!("{name} body"), &String::from_utf8_lossy(&msg.decoded_body()));
            }
        }
        if count > 0 {
            if hits.len() == MAX_RESULTS { truncated = true; break; }
            hits.push(Hit { doc, count, location, excerpt });
        }
    }
    Results { hits, truncated }
}

pub struct Search {
    query: String,
    regex: bool,
    case_sensitive: bool,
    scope_only: bool,
    history: bool,
    logger: bool,
    options: Options,
    run: u64,
    cancel: Option<Arc<AtomicBool>>,
    results: Results,
    selected: Option<usize>,
    message: String,
    req_view: Viewer,
    res_view: Viewer,
    split: f32,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            query: String::new(), regex: false, case_sensitive: false, scope_only: false,
            history: true, logger: false, options: Options::default(), run: 0, cancel: None,
            results: Results { hits: Vec::new(), truncated: false }, selected: None,
            message: String::new(), req_view: Viewer::default(), res_view: Viewer::new(crate::http::View::Pretty), split: 0.5,
        }
    }
}

impl Search {
    pub fn on_result(&mut self, run: u64, results: Results) {
        if run != self.run { return; }
        let stopped = self.cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed));
        self.cancel = None;
        self.results = results;
        self.selected = None;
        self.message = if stopped { "Stopped; partial results shown".into() } else { "Snapshot search complete".into() };
    }

    fn start(&mut self, history: &History, logger: &Logger, env: &Env) {
        if self.query.is_empty() { self.message = "Enter a search term".into(); return; }
        let pattern = if self.regex { self.query.clone() } else { regex::escape(&self.query) };
        let re = match RegexBuilder::new(&pattern).case_insensitive(!self.case_sensitive).build() {
            Ok(re) => re,
            Err(e) => { self.message = format!("Invalid expression: {e}"); return; }
        };
        let scope = crate::rules::current(env.shared);
        let mut docs = Vec::new();
        if self.history {
            docs.extend(history.flows.iter().filter(|f| !self.scope_only || scope.in_scope(&f.url)).map(|f| Document {
                source: format!("Proxy #{}", f.id), url: f.url.clone(), req: f.req.clone(), res: f.res.clone(), note: f.note.clone(),
            }));
        }
        if self.logger { docs.extend(logger.search_documents().into_iter().filter(|d| !self.scope_only || scope.in_scope(&d.url))); }
        self.run += 1;
        let run = self.run;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.message = format!("Searching {} messages…", docs.len());
        let options = self.options.clone();
        self.req_view.find = if self.regex { String::new() } else { self.query.clone() };
        self.res_view.find = self.req_view.find.clone();
        let (tx, ui) = (env.tx.clone(), env.egui.clone());
        env.rt.spawn_blocking(move || {
            let results = search(docs, &re, &options, &cancel);
            let _ = tx.send(Event::Search { run, results });
            ui.request_repaint();
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, history: &History, logger: &Logger, env: &mut Env) {
        let mut start = false;
        ui.horizontal_wrapped(|ui| {
            let input = ui.add(egui::TextEdit::singleline(&mut self.query).hint_text("Search captured messages").desired_width(300.0));
            start |= input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.checkbox(&mut self.regex, "Regex");
            ui.checkbox(&mut self.case_sensitive, "Case sensitive");
            ui.checkbox(&mut self.scope_only, "In-scope only");
            if let Some(cancel) = &self.cancel {
                if ui.button("Stop").clicked() { cancel.store(true, Ordering::Relaxed); }
            } else { start |= ui.button("Search").clicked(); }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Sources:");
            ui.checkbox(&mut self.history, "Proxy history");
            ui.checkbox(&mut self.logger, "Logger");
            ui.separator();
            ui.checkbox(&mut self.options.requests, "Requests");
            ui.checkbox(&mut self.options.responses, "Responses");
            ui.checkbox(&mut self.options.headers, "Headers");
            ui.checkbox(&mut self.options.bodies, "Decoded bodies");
            ui.checkbox(&mut self.options.urls, "URLs");
            ui.checkbox(&mut self.options.notes, "Notes");
        });
        if start && self.cancel.is_none() { self.start(history, logger, env); }
        ui.horizontal(|ui| {
            ui.label(format!("{} matching messages · {} matches", self.results.hits.len(), self.results.hits.iter().map(|h| h.count).sum::<usize>()));
            if self.results.truncated { ui.weak("First 10,000 matching messages shown"); }
            ui.weak(&self.message);
        });
        let (top, bottom) = vsplit(ui, "search_split", &mut self.split);
        let mut clicked = None;
        in_rect(ui, top, |ui| {
            TableBuilder::new(ui).id_salt("search_results").striped(true).sense(egui::Sense::click())
                .column(Column::auto()).column(Column::remainder().clip(true)).column(Column::auto())
                .column(Column::auto()).column(Column::remainder().clip(true))
                .header(20.0, |mut h| { for label in ["Source", "URL", "Matches", "First match", "Excerpt"] { h.col(|ui| { ui.strong(label); }); } })
                .body(|body| body.rows(20.0, self.results.hits.len(), |mut row| {
                    let i = row.index();
                    let hit = &self.results.hits[i];
                    row.set_selected(self.selected == Some(i));
                    for text in [&hit.doc.source, &hit.doc.url, &hit.count.to_string(), &hit.location, &hit.excerpt] {
                        row.col(|ui| { ui.add(egui::Label::new(text).truncate().selectable(false)); });
                    }
                    let response = row.response();
                    if response.clicked() { clicked = Some(i); }
                    response.context_menu(|ui| send_menu(ui, env, &hit.doc.url, &hit.doc.req, hit.doc.res.as_deref()));
                }));
        });
        if clicked.is_some() { self.selected = clicked; }
        in_rect(ui, bottom, |ui| {
            let Some(hit) = self.selected.and_then(|i| self.results.hits.get(i)) else { ui.weak("Select a search result."); return; };
            ui.horizontal(|ui| {
                ui.strong(&hit.doc.url);
                ui.menu_button("Actions", |ui| send_menu(ui, env, &hit.doc.url, &hit.doc.req, hit.doc.res.as_deref()));
            });
            ui.columns(2, |cols| {
                message_view(&mut cols[0], "search_req", &hit.doc.req, &mut self.req_view);
                if let Some(raw) = &hit.doc.res { message_view(&mut cols[1], "search_res", raw, &mut self.res_view); }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Document {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, "秘密 API_KEY=secret".as_bytes()).unwrap();
        let mut res = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        res.extend(gz.finish().unwrap());
        Document { source: "Proxy #1".into(), url: "https://example.com/?q=secret".into(),
            req: b"GET /?q=secret HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(), res: Some(res), note: "secret note".into() }
    }

    #[test]
    fn searches_decoded_bodies_and_respects_parts() {
        let cancel = AtomicBool::new(false);
        let re = RegexBuilder::new("secret").case_insensitive(true).build().unwrap();
        let all = search(vec![document()], &re, &Options::default(), &cancel);
        assert_eq!(all.hits[0].count, 4);
        let bodies = Options { requests: false, urls: false, notes: false, headers: false, ..Default::default() };
        let result = search(vec![document()], &Regex::new("API_KEY=secret").unwrap(), &bodies, &cancel);
        assert_eq!(result.hits[0].count, 1);
        assert_eq!(result.hits[0].location, "Response body");
        assert!(result.hits[0].excerpt.contains("秘密"));
        assert!(search(vec![document()], &Regex::new("SECRET").unwrap(), &bodies, &cancel).hits.is_empty());
        cancel.store(true, Ordering::Relaxed);
        assert!(search(vec![document()], &re, &Options::default(), &cancel).hits.is_empty());
    }
}
