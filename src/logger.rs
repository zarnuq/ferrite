//! Logger tab: one combined, searchable list of every HTTP request ferrite's tools send
//! (Repeater, Intruder, Discovery, Sequencer, Scanner), like Burp's Logger.

use eframe::egui::{self, Color32};
use egui_extras::{Column, TableBuilder};

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
    }
}

#[derive(Default)]
pub struct Logger {
    entries: Vec<Entry>,
    search: String,
    tool_filter: &'static str,
}

impl Logger {
    pub fn push(&mut self, e: Entry) {
        // ponytail: unbounded; cap + ring-buffer if a long fuzzing run floods it
        self.entries.push(e);
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut crate::Env) {
        let tools = ["All", "Repeater", "Intruder", "Discovery", "Sequencer", "Scanner"];
        ui.horizontal(|ui| {
            ui.strong(format!("Logger ({})", self.entries.len()));
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

        TableBuilder::new(ui)
            .id_salt("logger")
            .striped(true)
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
                    let e = &self.entries[order[row.index()]];
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
                    let mut resp = None;
                    for (c, text) in cells.into_iter().enumerate() {
                        let r = row.col(|ui| {
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
                        resp = Some(r.1);
                    }
                    if let Some(resp) = resp {
                        resp.context_menu(|ui| crate::send_menu(ui, env, &e.url, &e.req, None));
                    }
                });
            });
    }
}
