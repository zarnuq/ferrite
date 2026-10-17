//! Proxy tab: HTTP and WebSocket history with filtering, sorting and a message viewer.

use crate::{
    Env, Viewer, in_rect, message_view, vsplit,
    http::{self, Msg, Target, View, hexdump},
    rules::{self, Compiled},
    scanner::{self, Issue},
    send_menu,
};
use eframe::egui::{self, Color32};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct Flow {
    pub id: u64,
    pub url: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub req: Vec<u8>,
    pub res: Option<Vec<u8>>,
    pub status: u16,
    pub mime: String,
    pub ms: Option<u128>,
    pub highlight: Option<Color32>,
    pub note: String,
    pub created_ms: u64,
}

pub struct WsMsg {
    pub url: String,
    pub outgoing: bool,
    pub text: bool,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Id,
    Host,
    Method,
    Path,
    Status,
    Length,
    Mime,
    Time,
    Started,
    Note,
}

impl History {
    pub fn flow(&self, id: u64) -> Option<&Flow> {
        self.index.get(&id).map(|&i| &self.flows[i])
    }
}

pub const HIGHLIGHTS: [(&str, Color32); 6] = [
    ("Red", Color32::from_rgb(120, 30, 30)),
    ("Orange", Color32::from_rgb(130, 75, 20)),
    ("Yellow", Color32::from_rgb(110, 100, 20)),
    ("Green", Color32::from_rgb(30, 90, 40)),
    ("Blue", Color32::from_rgb(30, 60, 120)),
    ("Purple", Color32::from_rgb(80, 40, 110)),
];

pub struct History {
    pub flows: Vec<Flow>,
    pub index: HashMap<u64, usize>,
    pub issues: Vec<Issue>,
    issue_keys: HashSet<String>,
    /// Bumped on every change so other views can cache derived data.
    pub generation: u64,
    pub ws: Vec<WsMsg>,
    show_ws: bool,
    search: String,
    regex: bool,
    scope_only: bool,
    hide_static: bool,
    status_class: u8,
    sort: Col,
    ascending: bool,
    view: Vec<usize>,
    dirty: bool,
    scope: Option<Arc<Compiled>>,
    search_error: bool,
    selected: Option<u64>,
    ws_selected: Option<usize>,
    req_view: Viewer,
    res_view: Viewer,
    split: f32,
}

impl Default for History {
    fn default() -> Self {
        History {
            flows: Vec::new(),
            index: HashMap::new(),
            issues: Vec::new(),
            issue_keys: HashSet::new(),
            generation: 0,
            ws: Vec::new(),
            show_ws: false,
            search: String::new(),
            regex: false,
            scope_only: false,
            hide_static: false,
            status_class: 0,
            sort: Col::Id,
            ascending: true,
            view: Vec::new(),
            dirty: true,
            scope: None,
            search_error: false,
            selected: None,
            ws_selected: None,
            req_view: Viewer::new(View::Raw),
            res_view: Viewer::new(View::Pretty),
            split: 0.55,
        }
    }
}

impl History {
    pub fn on_request(&mut self, id: u64, url: String, raw: Vec<u8>) {
        let m = Msg::parse(&raw);
        let mut words = m.first.split_whitespace();
        let method = words.next().unwrap_or_default().to_string();
        let path = words.next().unwrap_or_default().to_string();
        let host = Target::from_url(&url).map(|t| t.host_header()).unwrap_or_default();
        self.index.insert(id, self.flows.len());
        self.flows.push(Flow {
            id,
            url,
            host,
            method,
            path,
            req: raw,
            res: None,
            status: 0,
            mime: String::new(),
            ms: None,
            highlight: None,
            note: String::new(),
            created_ms: http::now_hms().0,
        });
        self.dirty = true;
        self.generation += 1;
    }

    pub fn on_response(&mut self, id: u64, raw: Vec<u8>, ms: u128) {
        let Some(f) = self.index.get(&id).and_then(|&i| self.flows.get_mut(i)) else {
            return;
        };
        let m = Msg::parse(&raw);
        f.status = m.status();
        f.mime = m
            .header("content-type")
            .map(|v| v.split(';').next().unwrap_or("").rsplit('/').next().unwrap_or("").trim().to_string())
            .unwrap_or_default();
        f.ms = Some(ms);
        // ponytail: scans on the UI thread; move to the proxy runtime if big responses cause stutter
        for finding in scanner::passive(&f.url, &f.req, &raw) {
            if self.issue_keys.insert(finding.key) {
                self.issues.push(Issue {
                    url: f.url.clone(),
                    severity: finding.severity,
                    title: finding.title,
                    detail: finding.detail,
                    req: f.req.clone(),
                    res: raw.clone(),
                });
            }
        }
        f.res = Some(raw);
        self.dirty = true;
        self.generation += 1;
    }

    /// Replaces all captured data (project load). Returns the flow count.
    pub fn replace_all(&mut self, mut flows: Vec<Flow>, ws: Vec<WsMsg>, issues: Vec<Issue>) -> usize {
        // Runtime identities must never match old, still-in-flight responses after a load.
        for flow in &mut flows { flow.id = next_id(); }
        self.index = flows.iter().enumerate().map(|(i, f)| (f.id, i)).collect();
        self.issue_keys = issues.iter().map(|i| format!("{} {}", i.title, i.url)).collect();
        let n = flows.len();
        self.flows = flows;
        self.ws = ws;
        self.issues = issues;
        self.selected = None;
        self.ws_selected = None;
        self.dirty = true;
        self.generation += 1;
        n
    }

    /// Records an issue unless one with the same key exists.
    pub fn add_issue(&mut self, key: String, issue: Issue) {
        if self.issue_keys.insert(key) {
            self.issues.push(issue);
        }
    }

    pub fn on_ws(&mut self, url: String, outgoing: bool, text: bool, data: Vec<u8>) {
        self.ws.push(WsMsg { url, outgoing, text, data });
    }

    // ponytail: refilters every flow on each change, O(n) regex over bodies; incremental filter if history gets huge
    fn refresh(&mut self, scope: &Arc<Compiled>) {
        if !self.dirty && self.scope.as_ref().is_some_and(|s| Arc::ptr_eq(s, scope)) {
            return;
        }
        self.dirty = false;
        self.scope = Some(scope.clone());
        let search = (!self.search.is_empty()).then(|| {
            let pattern = if self.regex { self.search.clone() } else { regex::escape(&self.search) };
            regex::bytes::RegexBuilder::new(&pattern).case_insensitive(true).build().ok()
        });
        self.search_error = matches!(search, Some(None));
        let search = search.flatten();
        self.view = (0..self.flows.len())
            .filter(|&i| {
                let f = &self.flows[i];
                (!self.scope_only || scope.in_scope(&f.url))
                    && (!self.hide_static || !http::is_static(&f.path))
                    && (self.status_class == 0 || (f.status / 100) as u8 == self.status_class)
                    && search.as_ref().is_none_or(|re| {
                        re.is_match(f.url.as_bytes())
                            || re.is_match(f.note.as_bytes())
                            || re.is_match(&f.req)
                            || f.res.as_ref().is_some_and(|r| re.is_match(r))
                    })
            })
            .collect();
        let flows = &self.flows;
        let len = |i: usize| flows[i].res.as_ref().map_or(0, |r| r.len());
        self.view.sort_by(|&a, &b| {
            let (x, y) = (&flows[a], &flows[b]);
            let ord = match self.sort {
                Col::Id => x.id.cmp(&y.id),
                Col::Host => x.host.cmp(&y.host),
                Col::Method => x.method.cmp(&y.method),
                Col::Path => x.path.cmp(&y.path),
                Col::Status => x.status.cmp(&y.status),
                Col::Length => len(a).cmp(&len(b)),
                Col::Mime => x.mime.cmp(&y.mime),
                Col::Time => x.ms.cmp(&y.ms),
                Col::Started => x.created_ms.cmp(&y.created_ms),
                Col::Note => x.note.cmp(&y.note),
            };
            if self.ascending { ord } else { ord.reverse() }
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.show_ws, false, format!("HTTP history ({})", self.flows.len()));
            ui.selectable_value(&mut self.show_ws, true, format!("WebSockets history ({})", self.ws.len()));
            ui.separator();
            if !self.show_ws {
                let search = egui::TextEdit::singleline(&mut self.search).hint_text("Search").desired_width(220.0);
                let search = if self.search_error { search.text_color(Color32::RED) } else { search };
                let changed = ui.add(search).changed()
                    | ui.checkbox(&mut self.regex, "Regex").changed()
                    | ui.checkbox(&mut self.scope_only, "In-scope only").changed()
                    | ui.checkbox(&mut self.hide_static, "Hide images/CSS/fonts").changed();
                ui.separator();
                ui.label("Status");
                for (cls, label) in [(0u8, "All"), (2, "2xx"), (3, "3xx"), (4, "4xx"), (5, "5xx")] {
                    if ui.selectable_label(self.status_class == cls, label).clicked() {
                        self.status_class = cls;
                        self.dirty = true;
                    }
                }
                self.dirty |= changed;
            }
            if ui.button("Clear").clicked() {
                if self.show_ws {
                    self.ws.clear();
                    self.ws_selected = None;
                } else {
                    self.flows.clear();
                    self.index.clear();
                    self.issues.clear();
                    self.issue_keys.clear();
                    self.generation += 1;
                    self.selected = None;
                    self.dirty = true;
                }
            }
        });
        if self.show_ws {
            self.ws_ui(ui, env);
            return;
        }
        let scope = rules::current(env.shared);
        self.refresh(&scope);

        let (top, bottom) = vsplit(ui, "hist_split", &mut self.split);
        in_rect(ui, bottom, |ui| {
            let Some(i) = self.selected.and_then(|id| self.index.get(&id)).copied() else {
                ui.weak("Select a request.");
                return;
            };
            let f = &mut self.flows[i];
            ui.horizontal(|ui| {
                ui.label("Note:");
                ui.add(egui::TextEdit::singleline(&mut f.note).hint_text("annotate this request").desired_width(f32::INFINITY));
            });
            ui.columns(2, |cols| {
                cols[0].strong(format!("Request · {}", f.url));
                message_view(&mut cols[0], "hist_req", &f.req, &mut self.req_view);
                cols[1].strong("Response");
                match &f.res {
                    Some(r) => message_view(&mut cols[1], "hist_res", r, &mut self.res_view),
                    None => {
                        cols[1].weak("Waiting for response…");
                    }
                }
            });
        });

        let mut clicked = None;
        let mut sort_click = None;
        let mut highlight = None;
        in_rect(ui, top, |ui| TableBuilder::new(ui)
            .id_salt("history")
            .striped(true)
            .sense(egui::Sense::click())
            .stick_to_bottom(self.sort == Col::Id && self.ascending)
            .column(Column::auto().at_least(40.0))
            .column(Column::initial(200.0).clip(true).resizable(true))
            .column(Column::auto().at_least(60.0))
            .column(Column::remainder().clip(true))
            .column(Column::auto().at_least(50.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(60.0))
            .column(Column::auto().at_least(60.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for (col, name) in [
                    (Col::Id, "#"),
                    (Col::Host, "Host"),
                    (Col::Method, "Method"),
                    (Col::Path, "URL"),
                    (Col::Status, "Status"),
                    (Col::Length, "Length"),
                    (Col::Mime, "MIME"),
                    (Col::Time, "Time ms"),
                    (Col::Started, "Started"),
                    (Col::Note, "Note"),
                ] {
                    h.col(|ui| {
                        let arrow = match (self.sort == col, self.ascending) {
                            (true, true) => " ⏶",
                            (true, false) => " ⏷",
                            _ => "",
                        };
                        if ui.selectable_label(false, egui::RichText::new(format!("{name}{arrow}")).strong()).clicked() {
                            sort_click = Some(col);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, self.view.len(), |mut row| {
                    let i = self.view[row.index()];
                    let f = &self.flows[i];
                    row.set_selected(self.selected == Some(f.id));
                    let cells = [
                        f.id.to_string(),
                        f.host.clone(),
                        f.method.clone(),
                        f.path.clone(),
                        if f.status == 0 { String::new() } else { f.status.to_string() },
                        f.res.as_ref().map_or(String::new(), |r| r.len().to_string()),
                        f.mime.clone(),
                        f.ms.map_or(String::new(), |m| m.to_string()),
                        http::hms(f.created_ms),
                        f.note.clone(),
                    ];
                    for text in cells {
                        row.col(|ui| {
                            if let Some(c) = f.highlight {
                                ui.painter().rect_filled(ui.max_rect().expand2(egui::vec2(4.0, 1.0)), 0.0, c);
                            }
                            ui.add(egui::Label::new(text).truncate().selectable(false));
                        });
                    }
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some(f.id);
                    }
                    resp.context_menu(|ui| {
                        send_menu(ui, env, &f.url, &f.req, f.res.as_deref());
                        ui.separator();
                        ui.menu_button("Highlight", |ui| {
                            for (name, c) in HIGHLIGHTS {
                                if ui.button(name).clicked() {
                                    highlight = Some((i, Some(c)));
                                    ui.close();
                                }
                            }
                            if ui.button("None").clicked() {
                                highlight = Some((i, None));
                                ui.close();
                            }
                        });
                    });
                });
            }));
        if let Some(id) = clicked {
            self.selected = Some(id);
        }
        if let Some((i, c)) = highlight {
            self.flows[i].highlight = c;
        }
        if let Some(col) = sort_click {
            self.ascending = if self.sort == col { !self.ascending } else { true };
            self.sort = col;
            self.dirty = true;
        }
        // Ctrl+R / Ctrl+I send the selected request to Repeater / Intruder, as in Burp.
        let to_repeater = ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::R));
        let to_intruder = ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::I));
        if let Some(f) = self.selected.and_then(|id| self.flow(id)) {
            if let Some(t) = Target::from_url(&f.url) {
                if to_repeater {
                    env.actions.push(crate::Action::Repeater(t.clone(), f.req.clone()));
                }
                if to_intruder {
                    env.actions.push(crate::Action::Intruder(t, f.req.clone()));
                }
            }
        }
    }

    fn ws_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let (top, bottom) = vsplit(ui, "ws_split", &mut self.split);
        in_rect(ui, bottom, |ui| {
            let Some(m) = self.ws_selected.and_then(|i| self.ws.get(i)) else {
                ui.weak("Select a message.");
                return;
            };
            let text = if m.text { String::from_utf8_lossy(&m.data).into_owned() } else { hexdump(&m.data) };
            egui::ScrollArea::both().id_salt("ws_msg").auto_shrink(false).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
        });
        let mut clicked = None;
        in_rect(ui, top, |ui| TableBuilder::new(ui)
            .id_salt("ws_history")
            .striped(true)
            .sense(egui::Sense::click())
            .stick_to_bottom(true)
            .column(Column::auto().at_least(40.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::remainder().clip(true))
            .column(Column::auto().at_least(60.0))
            .header(20.0, |mut h| {
                for name in ["#", "Direction", "URL", "Length"] {
                    h.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, self.ws.len(), |mut row| {
                    let i = row.index();
                    let m = &self.ws[i];
                    row.set_selected(self.ws_selected == Some(i));
                    let dir = if m.outgoing { "→ To server" } else { "← To client" };
                    for text in [i.to_string(), dir.to_string(), m.url.clone(), m.data.len().to_string()] {
                        row.col(|ui| {
                            ui.add(egui::Label::new(text).truncate().selectable(false));
                        });
                    }
                    let resp = row.response();
                    if resp.clicked() {
                        clicked = Some(i);
                    }
                    let url = m.url.clone();
                    resp.context_menu(|ui| {
                        if ui.button("Open in WS Repeater").clicked() {
                            env.actions.push(crate::Action::WsRepeater(url.clone()));
                            ui.close();
                        }
                        if ui.button("Copy URL").clicked() {
                            ui.ctx().copy_text(url.clone());
                            ui.close();
                        }
                    });
                });
            }));
        if clicked.is_some() {
            self.ws_selected = clicked;
        }
    }
}

/// Shared by the proxy, crawler, HAR importer and project restoration.
pub fn next_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
