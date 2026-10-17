//! Logger tab: one combined, searchable list of every HTTP request ferrite's tools send
//! (Repeater, Intruder, Discovery, Sequencer, Scanner), like Burp's Logger.

use eframe::egui::{self, Color32};
use egui_extras::{Column, TableBuilder};
use crate::{Viewer, in_rect, message_view, vsplit};
use std::collections::VecDeque;

const MAX_ENTRIES: usize = 10_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

pub struct Entry {
    pub tool: &'static str,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub ms: u128,
    pub created_ms: u64,
    pub req: Vec<u8>,
    pub target: crate::http::Target,
    pub response: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Builds a log entry from a tool's request bytes, target and send result.
pub fn entry(tool: &'static str, target: &crate::http::Target, raw: &[u8], result: &Result<crate::http::Reply, String>) -> Entry {
    let m = crate::http::Msg::parse(raw);
    let mut words = m.first.split_whitespace();
    let method = words.next().unwrap_or("GET").to_string();
    let path = words.next().unwrap_or("/");
    let (status, length, ms) = match result {
        Ok(r) => (r.status, r.raw.len(), r.elapsed.as_millis()),
        Err(_) => (0, 0, 0),
    };
    Entry {
        tool,
        method,
        url: format!("{}{}", target.url(), path),
        status,
        length,
        ms,
        created_ms: crate::http::now_hms().0,
        req: raw.to_vec(),
        target: target.clone(),
        response: result.as_ref().ok().map(|r| r.raw.clone()),
        error: result.as_ref().err().cloned(),
    }
}

pub struct Logger {
    entries: VecDeque<Entry>,
    selected: Option<usize>,
    req_view: Viewer,
    res_view: Viewer,
    split: f32,
    dropped: usize,
    bytes: usize,
    search: String,
    tool_filter: &'static str,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(), selected: None, req_view: Viewer::default(),
            res_view: Viewer::new(crate::http::View::Pretty), split: 0.55, dropped: 0, bytes: 0,
            search: String::new(), tool_filter: "",
        }
    }
}

impl Logger {
    pub fn push(&mut self, e: Entry) {
        self.push_limited(e, MAX_ENTRIES, MAX_BYTES);
    }

    fn push_limited(&mut self, e: Entry, max_entries: usize, max_bytes: usize) {
        let bytes = e.req.len() + e.response.as_ref().map_or(0, Vec::len);
        if bytes > max_bytes {
            self.dropped += 1;
            return;
        }
        while !self.entries.is_empty() && (self.entries.len() >= max_entries || self.bytes + bytes > max_bytes) {
            let old = self.entries.pop_front().unwrap();
            self.bytes -= old.req.len() + old.response.as_ref().map_or(0, Vec::len);
            self.selected = self.selected.and_then(|i| i.checked_sub(1));
            self.dropped += 1;
        }
        self.bytes += bytes;
        self.entries.push_back(e);
    }

    pub fn search_documents(&self) -> Vec<crate::search::Document> {
        self.entries.iter().map(|e| crate::search::Document {
            source: e.tool.into(), url: e.url.clone(), req: e.req.clone(), res: e.response.clone(), note: String::new(),
        }).collect()
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut crate::Env) {
        let tools = ["All", "Repeater", "Intruder", "Discovery", "Sequencer", "Scanner", "Crawler"];
        ui.horizontal(|ui| {
            ui.strong(format!("Logger ({})", self.entries.len()));
            if self.dropped > 0 { ui.weak(format!("{} older entries discarded", self.dropped)); }
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search URL").desired_width(240.0));
            ui.separator();
            for t in tools {
                let active = (self.tool_filter.is_empty() && t == "All") || self.tool_filter == t;
                if ui.selectable_label(active, t).clicked() {
                    self.tool_filter = if t == "All" { "" } else { t };
                }
            }
            if ui.button("Clear").clicked() {
                self.entries.clear();
                self.selected = None;
                self.dropped = 0;
                self.bytes = 0;
            }
        });
        ui.separator();

        let needle = self.search.to_ascii_lowercase();
        let order: Vec<usize> = (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                (self.tool_filter.is_empty() || e.tool == self.tool_filter)
                    && (needle.is_empty() || e.url.to_ascii_lowercase().contains(&needle))
            })
            .collect();

        let (top, bottom) = vsplit(ui, "logger_split", &mut self.split);
        in_rect(ui, bottom, |ui| {
            let Some(e) = self.selected.and_then(|i| self.entries.get(i)) else {
                ui.weak("Select a logged request.");
                return;
            };
            ui.horizontal(|ui| {
                ui.strong(&e.url);
                ui.menu_button("Actions", |ui| crate::send_menu(ui, env, &e.url, &e.req, e.response.as_deref()));
            });
            if let Some(error) = &e.error { ui.colored_label(Color32::LIGHT_RED, error); }
            ui.columns(2, |cols| {
                cols[0].strong("Request");
                message_view(&mut cols[0], "log_req", &e.req, &mut self.req_view);
                cols[1].strong("Response");
                if let Some(raw) = &e.response { message_view(&mut cols[1], "log_res", raw, &mut self.res_view); }
            });
        });
        let mut clicked = None;
        in_rect(ui, top, |ui| TableBuilder::new(ui)
            .id_salt("logger")
            .striped(true)
            .sense(egui::Sense::click())
            .stick_to_bottom(true)
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(60.0))
            .column(Column::remainder().clip(true))
            .column(Column::auto().at_least(50.0))
            .column(Column::auto().at_least(60.0))
            .column(Column::auto().at_least(60.0))
            .column(Column::auto().at_least(70.0))
            .header(20.0, |mut h| {
                for name in ["Tool", "Method", "URL", "Status", "Length", "Time ms", "Started"] {
                    h.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let index = order[row.index()];
                    let e = &self.entries[index];
                    row.set_selected(self.selected == Some(index));
                    let status = if e.status == 0 { "err".to_string() } else { e.status.to_string() };
                    let cells = [
                        e.tool.to_string(),
                        e.method.clone(),
                        e.url.clone(),
                        status,
                        e.length.to_string(),
                        e.ms.to_string(),
                        crate::http::hms(e.created_ms),
                    ];
                    for (c, text) in cells.into_iter().enumerate() {
                        row.col(|ui| {
                            let mut label = egui::RichText::new(text);
                            if c == 3 {
                                label = label.color(match e.status {
                                    200..=299 => Color32::from_rgb(120, 200, 120),
                                    300..=399 => Color32::from_rgb(120, 175, 255),
                                    400..=599 => Color32::from_rgb(230, 150, 60),
                                    _ => Color32::from_rgb(230, 80, 80),
                                });
                            }
                            ui.add(egui::Label::new(label).truncate().selectable(false));
                        });
                    }
                    let resp = row.response();
                    if resp.clicked() { clicked = Some(index); }
                    resp.context_menu(|ui| crate::send_menu(ui, env, &e.url, &e.req, e.response.as_deref()));
                });
            }));
        if clicked.is_some() { self.selected = clicked; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(body: &[u8]) -> Entry {
        let target = crate::http::Target::from_url("http://example.com/").unwrap();
        entry("Repeater", &target, body, &Err("connection refused".into()))
    }

    #[test]
    fn evicts_old_messages_without_moving_selection_to_another_entry() {
        let mut log = Logger::default();
        log.push_limited(item(b"one"), 2, 8);
        log.push_limited(item(b"two"), 2, 8);
        log.selected = Some(1);
        log.push_limited(item(b"three"), 2, 8);
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.selected, Some(0));
        assert_eq!(log.entries[0].req, b"two");
        assert_eq!(log.entries[0].error.as_deref(), Some("connection refused"));
        log.push_limited(item(b"four"), 2, 8);
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.selected, None);
        assert_eq!(log.bytes, 4);
        log.push_limited(item(b"too large"), 2, 8);
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.dropped, 4);
    }
}
