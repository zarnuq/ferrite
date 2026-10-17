mod comparer;
mod crawler;
mod decoder;
mod discovery;
mod history;
mod http;
mod intercept;
mod intruder;
mod logger;
mod project;
mod proxy;
mod repeater;
mod rules;
mod scanner;
mod sequencer;
mod settings;
mod target;
mod ws_repeater;

use eframe::egui;
use http::{Target, View};
use rules::{Compiled, Config, Shared};
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock, mpsc},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Request,
    Response,
    WsOut,
    WsIn,
}

/// A message held by the proxy until the Intercept tab forwards (`Some`) or drops (`None`) it.
pub struct Pending {
    pub kind: Kind,
    pub url: String,
    pub raw: Vec<u8>,
    pub reply: oneshot::Sender<Option<Vec<u8>>>,
}

pub enum Event {
    Request { id: u64, url: String, raw: Vec<u8> },
    Response { id: u64, raw: Vec<u8>, ms: u128 },
    Ws { url: String, outgoing: bool, text: bool, data: Vec<u8> },
    Intercept(Pending),
    Repeater { tab: u64, result: Result<http::Reply, String> },
    Intruder { attack: u64, idx: usize, result: Result<http::Reply, String> },
    Discovery { run: u64, idx: usize, result: Result<http::Reply, String> },
    WsRepeater { run: u64, note: ws_repeater::Note },
    Crawler { run: u64, note: crawler::Note },
    Log(logger::Entry),
    Sequencer { run: u64, result: Result<http::Reply, String> },
    Status(String),
    Issue(String, scanner::Issue),
}

/// Cross-tab requests raised from context menus, applied after the frame's UI runs.
pub enum Action {
    Repeater(Target, Vec<u8>),
    Intruder(Target, Vec<u8>),
    Sequencer(Target, Vec<u8>),
    Discovery(Target, Vec<u8>),
    WsRepeater(String),
    Crawl(String),
    Comparer(String, Vec<u8>),
    Decoder(String),
    AddScope(String),
    Scan(Target, Vec<u8>),
}

/// What tabs need from the app: the runtime for network work, the event channel and settings.
pub struct Env<'a> {
    pub rt: &'a tokio::runtime::Handle,
    pub tx: &'a mpsc::Sender<Event>,
    pub egui: &'a egui::Context,
    pub shared: &'a Shared,
    pub actions: &'a mut Vec<Action>,
}

impl Env<'_> {
    /// Runs `fut` on the tokio runtime and delivers its event to the UI.
    pub fn spawn(&self, fut: impl Future<Output = Event> + Send + 'static) {
        let (tx, ui) = (self.tx.clone(), self.egui.clone());
        self.rt.spawn(async move {
            let _ = tx.send(fut.await);
            ui.request_repaint();
        });
    }

    pub fn upstream(&self) -> http::Upstream {
        rules::current(self.shared).cfg.upstream.clone()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Target,
    Proxy,
    Intercept,
    Repeater,
    WsRepeater,
    Intruder,
    Sequencer,
    Discovery,
    Crawler,
    Logger,
    Decoder,
    Comparer,
    Settings,
}

struct App {
    tab: Tab,
    rt: tokio::runtime::Runtime,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    shared: Shared,
    cfg: Config,
    status: String,
    project_path: String,
    egui: egui::Context,
    history: history::History,
    target: target::TargetTab,
    intercept: intercept::Intercept,
    repeater: repeater::Repeater,
    ws_repeater: ws_repeater::WsRepeater,
    intruder: intruder::Intruder,
    sequencer: sequencer::Sequencer,
    discovery: discovery::Discovery,
    crawler: crawler::Crawler,
    logger: logger::Logger,
    decoder: decoder::Decoder,
    comparer: comparer::Comparer,
}

fn main() -> eframe::Result {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("-h" | "--help") => {
            println!(
                "ferrite — a Burp-style intercepting proxy\n\nusage: ferrite [LISTEN_ADDR]\n\nLISTEN_ADDR   address to listen on (default 127.0.0.1:8080)\n\nThe CA certificate and settings live in ~/.config/ferrite.\nImport ca.pem into your browser and point its proxy at the listen address."
            );
            return Ok(());
        }
        Some("-V" | "--version") => {
            println!("ferrite {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let addr: SocketAddr = match arg {
        Some(a) => a.parse().unwrap_or_else(|_| {
            eprintln!("usage: ferrite [LISTEN_ADDR]  (default 127.0.0.1:8080)");
            std::process::exit(2)
        }),
        None => SocketAddr::from(([127, 0, 0, 1], 8080)),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 900.0]).with_app_id("ferrite"),
        ..Default::default()
    };
    eframe::run_native(
        "ferrite",
        options,
        Box::new(move |cc| {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            let (tx, rx) = mpsc::channel();
            let cfg = rules::load();
            let shared: Shared = Arc::new(RwLock::new(Arc::new(Compiled::new(cfg.clone()))));
            let (ptx, ui, psh) = (tx.clone(), cc.egui_ctx.clone(), shared.clone());
            rt.spawn(async move {
                if let Err(e) = proxy::run(addr, psh, ptx.clone(), ui.clone()).await {
                    let _ = ptx.send(Event::Status(format!("Proxy stopped: {e}")));
                    ui.request_repaint();
                }
            });
            let autosave = proxy::config_dir().join("autosave.ferrite");
            let (status, project_path) = if autosave.exists() {
                (
                    format!("Proxy on {addr}. Previous session autosaved — Project menu → Load to restore. CA: {}", proxy::config_dir().join("ca.pem").display()),
                    autosave.to_string_lossy().into_owned(),
                )
            } else {
                (format!("Proxy on {addr}. CA cert: {}", proxy::config_dir().join("ca.pem").display()), String::new())
            };
            Ok(Box::new(App {
                tab: Tab::Proxy,
                rt,
                tx,
                rx,
                shared,
                cfg,
                status,
                project_path,
                egui: cc.egui_ctx.clone(),
                history: Default::default(),
                target: Default::default(),
                intercept: Default::default(),
                repeater: Default::default(),
                ws_repeater: Default::default(),
                intruder: Default::default(),
                sequencer: Default::default(),
                discovery: Default::default(),
                crawler: Default::default(),
                logger: Default::default(),
                decoder: Default::default(),
                comparer: Default::default(),
            }))
        }),
    )
}

impl App {
    fn drain(&mut self) {
        for ev in self.rx.try_iter() {
            match ev {
                Event::Request { id, url, raw } => self.history.on_request(id, url, raw),
                Event::Response { id, raw, ms } => self.history.on_response(id, raw, ms),
                Event::Ws { url, outgoing, text, data } => self.history.on_ws(url, outgoing, text, data),
                Event::Intercept(p) => self.intercept.push(p, &self.cfg),
                Event::Repeater { tab, result } => self.repeater.on_result(tab, result),
                Event::Intruder { attack, idx, result } => self.intruder.on_result(attack, idx, result),
                Event::Sequencer { run, result } => self.sequencer.on_result(run, result),
                Event::Discovery { run, idx, result } => self.discovery.on_result(run, idx, result),
                Event::WsRepeater { run, note } => self.ws_repeater.on_note(run, note),
                Event::Crawler { run, note } => self.crawler.on_note(run, note),
                Event::Log(e) => self.logger.push(e),
                Event::Status(s) => self.status = s,
                Event::Issue(key, issue) => self.history.add_issue(key, issue),
            }
        }
    }

    fn apply(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Repeater(t, raw) => {
                    self.repeater.add(t, raw);
                    self.tab = Tab::Repeater;
                }
                Action::Intruder(t, raw) => {
                    self.intruder.load(t, raw);
                    self.tab = Tab::Intruder;
                }
                Action::Sequencer(t, raw) => {
                    self.sequencer.load(t, raw);
                    self.tab = Tab::Sequencer;
                }
                Action::Discovery(t, raw) => {
                    self.discovery.load(t, raw);
                    self.tab = Tab::Discovery;
                }
                Action::WsRepeater(url) => {
                    self.ws_repeater.load(url);
                    self.tab = Tab::WsRepeater;
                }
                Action::Crawl(url) => {
                    self.crawler.load(url);
                    self.tab = Tab::Crawler;
                }
                Action::Comparer(label, data) => self.comparer.add(label, data),
                Action::Decoder(text) => {
                    self.decoder.load(text);
                    self.tab = Tab::Decoder;
                }
                Action::Scan(t, raw) => {
                    let upstream = rules::current(&self.shared).cfg.upstream.clone();
                    let (tx, ui) = (self.tx.clone(), self.egui.clone());
                    self.rt.spawn(scanner::active(t, raw, upstream, tx, ui));
                    self.status = "Active scan started…".into();
                }
                Action::AddScope(url) => {
                    if let Some(t) = Target::from_url(&url) {
                        let rule = format!(r"^https?://{}(:\d+)?/", regex::escape(&t.host));
                        if !self.cfg.include.contains(&rule) {
                            self.cfg.include.push(rule);
                        }
                    }
                }
            }
        }
    }

    /// Hands edited settings to the proxy when they change.
    fn publish(&self) {
        let old = rules::current(&self.shared);
        if old.cfg != self.cfg {
            *self.shared.write().unwrap() = Arc::new(Compiled::new(self.cfg.clone()));
            // Save unless only the intercept toggle moved.
            let mut a = old.cfg.clone();
            a.intercept.on = self.cfg.intercept.on;
            if a != self.cfg {
                rules::save(&self.cfg);
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        ui.ctx().set_theme(match self.cfg.theme {
            rules::Theme::System => egui::ThemePreference::System,
            rules::Theme::Dark => egui::ThemePreference::Dark,
            rules::Theme::Light => egui::ThemePreference::Light,
        });
        let mut actions = Vec::new();
        let egui_ctx = ui.ctx().clone();

        egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                let pending = self.intercept.queue.len();
                let intercept = if pending > 0 { format!("Intercept ({pending})") } else { "Intercept".into() };
                let issues = self.history.issues.len();
                for (tab, label) in [
                    (Tab::Target, if issues > 0 { format!("Target ({issues} issues)") } else { "Target".into() }),
                    (Tab::Proxy, "Proxy".to_string()),
                    (Tab::Intercept, intercept),
                    (Tab::Repeater, "Repeater".into()),
                    (Tab::WsRepeater, "WS Repeater".into()),
                    (Tab::Intruder, "Intruder".into()),
                    (Tab::Sequencer, "Sequencer".into()),
                    (Tab::Discovery, "Discovery".into()),
                    (Tab::Crawler, "Crawler".into()),
                    (Tab::Logger, "Logger".into()),
                    (Tab::Decoder, "Decoder".into()),
                    (Tab::Comparer, "Comparer".into()),
                    (Tab::Settings, "Settings".into()),
                ] {
                    ui.selectable_value(&mut self.tab, tab, label);
                }
                ui.separator();
                let on = self.cfg.intercept.on;
                if ui
                    .selectable_label(on, if on { "Intercept is on" } else { "Intercept is off" })
                    .clicked()
                {
                    self.cfg.intercept.on = !on;
                }
                ui.separator();
                ui.menu_button("Project", |ui| {
                    ui.label("Save/load history, WebSockets and issues as a .ferrite file.");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.project_path).hint_text("/path/to/session.ferrite").desired_width(320.0));
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() && !self.project_path.is_empty() {
                            let path = if self.project_path.ends_with(".ferrite") { self.project_path.clone() } else { format!("{}.ferrite", self.project_path) };
                            self.status = match project::save(&self.history, &path) {
                                Ok(()) => format!("Saved {} flows to {path}", self.history.flows.len()),
                                Err(e) => format!("Save failed: {e}"),
                            };
                            ui.close();
                        }
                        if ui.button("Load").clicked() && !self.project_path.is_empty() {
                            self.status = match project::load(&mut self.history, &self.project_path) {
                                Ok(n) => format!("Loaded {n} flows from {}", self.project_path),
                                Err(e) => format!("Load failed: {e}"),
                            };
                            ui.close();
                        }
                        if ui.button("Export HAR").on_hover_text("HAR 1.2 for other tools; .gz suffix gzips it").clicked() && !self.project_path.is_empty() {
                            let path = if self.project_path.ends_with(".har") || self.project_path.ends_with(".har.gz") {
                                self.project_path.clone()
                            } else {
                                format!("{}.har", self.project_path.trim_end_matches(".ferrite"))
                            };
                            self.status = match project::export_har(&self.history, &path) {
                                Ok(n) => format!("Exported {n} entries to {path}"),
                                Err(e) => format!("HAR export failed: {e}"),
                            };
                            ui.close();
                        }
                    });
                });
                ui.menu_button("Help", |ui| {
                    ui.label("Keyboard shortcuts");
                    egui::Grid::new("shortcuts").striped(true).show(ui, |ui| {
                        for (k, v) in [
                            ("Ctrl+R", "Send selected request to Repeater"),
                            ("Ctrl+I", "Send selected request to Intruder"),
                            ("Ctrl+Enter", "Send request (Repeater)"),
                            ("Ctrl+F", "Forward (Intercept)"),
                        ] {
                            ui.strong(k);
                            ui.label(v);
                            ui.end_row();
                        }
                    });
                    ui.separator();
                    ui.label("ferrite — a Burp-style proxy. CA and settings live in ~/.config/ferrite.");
                });
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| ui.label(&self.status));

        egui::CentralPanel::default().show(ui, |ui| {
            let mut env = Env {
                rt: self.rt.handle(),
                tx: &self.tx,
                egui: &egui_ctx,
                shared: &self.shared,
                actions: &mut actions,
            };
            match self.tab {
                Tab::Target => self.target.ui(ui, &self.history, &mut env),
                Tab::Proxy => self.history.ui(ui, &mut env),
                Tab::Intercept => self.intercept.ui(ui, &mut self.cfg, &mut env),
                Tab::Repeater => self.repeater.ui(ui, &mut env),
                Tab::WsRepeater => self.ws_repeater.ui(ui, &mut env),
                Tab::Intruder => self.intruder.ui(ui, &mut env),
                Tab::Sequencer => self.sequencer.ui(ui, &mut env),
                Tab::Discovery => self.discovery.ui(ui, &mut env),
                Tab::Crawler => self.crawler.ui(ui, &mut env),
                Tab::Logger => self.logger.ui(ui, &mut env),
                Tab::Decoder => self.decoder.ui(ui),
                Tab::Comparer => self.comparer.ui(ui),
                Tab::Settings => settings::ui(ui, &mut self.cfg),
            }
        });

        self.intercept.release_if_off(&self.cfg);
        self.apply(actions);
        self.publish();
    }

    /// Autosave the session so an accidental close doesn't lose captured traffic.
    fn on_exit(&mut self) {
        if !self.history.flows.is_empty() {
            let path = proxy::config_dir().join("autosave.ferrite");
            let _ = project::save(&self.history, &path.to_string_lossy());
        }
    }
}

/// View mode and search text of one message viewer.
#[derive(Default)]
pub struct Viewer {
    pub mode: View,
    pub find: String,
}

impl Viewer {
    pub fn new(mode: View) -> Viewer {
        Viewer { mode, find: String::new() }
    }
}

/// Colours an HTTP message: start line, header names, and search matches (case-insensitive).
fn highlight(ui: &egui::Ui, text: &str, find: &str) -> egui::text::LayoutJob {
    use egui::{Color32, TextFormat};
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let dark = ui.visuals().dark_mode;
    let normal = ui.visuals().text_color();
    let first = if dark { Color32::from_rgb(240, 170, 90) } else { Color32::from_rgb(170, 80, 0) };
    let name = if dark { Color32::from_rgb(120, 175, 255) } else { Color32::from_rgb(20, 80, 180) };
    let hit_bg = if dark { Color32::from_rgb(120, 100, 20) } else { Color32::from_rgb(255, 225, 120) };

    // Base colour boundaries: (start, colour).
    let mut base = vec![(0, normal)];
    let head_end = [text.find("\r\n\r\n"), text.find("\n\n")].into_iter().flatten().min().unwrap_or(text.len());
    let looks_http = text.starts_with("HTTP/") || text.split(' ').nth(2).is_some_and(|v| v.starts_with("HTTP/"));
    if looks_http {
        let mut pos = 0;
        for (i, line) in text[..head_end].split('\n').enumerate() {
            if i == 0 {
                base = vec![(0, first)];
            } else if let Some(colon) = line.find(':') {
                base.push((pos, name));
                base.push((pos + colon, normal));
            }
            pos += line.len() + 1;
        }
        base.push((head_end.min(text.len()), normal));
    }
    let mut hits = Vec::new();
    if !find.is_empty() && find.len() <= text.len() {
        let (hay, needle) = (text.to_ascii_lowercase(), find.to_ascii_lowercase());
        let mut from = 0;
        while let Some(i) = hay[from..].find(&needle) {
            hits.push((from + i, from + i + needle.len()));
            from += i + needle.len().max(1);
            if hits.len() >= 10_000 {
                break;
            }
        }
    }
    let mut cuts: Vec<usize> = base.iter().map(|b| b.0).chain(hits.iter().flat_map(|h| [h.0, h.1])).collect();
    cuts.push(text.len());
    cuts.sort_unstable();
    cuts.dedup();
    let mut job = egui::text::LayoutJob::default();
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b || !text.is_char_boundary(a) || !text.is_char_boundary(b) {
            continue;
        }
        let color = base.iter().rev().find(|(s, _)| *s <= a).map_or(normal, |b| b.1);
        let hit = hits.iter().any(|h| h.0 <= a && b <= h.1);
        let fmt = TextFormat {
            font_id: font.clone(),
            color,
            background: if hit { hit_bg } else { Color32::TRANSPARENT },
            ..Default::default()
        };
        job.append(&text[a..b], 0.0, fmt);
    }
    job
}

fn text_box(ui: &mut egui::Ui, text: &mut dyn egui::TextBuffer, find: &str) -> egui::text_edit::TextEditOutput {
    let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap: f32| {
        let mut job = highlight(ui, buf.as_str(), find);
        job.wrap.max_width = wrap;
        ui.fonts_mut(|f| f.layout_job(job))
    };
    egui::TextEdit::multiline(text)
        .font(egui::TextStyle::Monospace)
        .desired_width(f32::INFINITY)
        .min_size(ui.available_size())
        .layouter(&mut layouter)
        .show(ui)
}

/// Read-only message viewer with Raw / Pretty / Hex / Params modes and search.
pub fn message_view(ui: &mut egui::Ui, id: &str, raw: &[u8], v: &mut Viewer) {
    let text = http::render_view(raw, v.mode);
    ui.horizontal(|ui| {
        ui.selectable_value(&mut v.mode, View::Raw, "Raw");
        ui.selectable_value(&mut v.mode, View::Pretty, "Pretty");
        ui.selectable_value(&mut v.mode, View::Hex, "Hex");
        ui.selectable_value(&mut v.mode, View::Params, "Params");
        ui.weak(format!("{} bytes", raw.len()));
        ui.add(egui::TextEdit::singleline(&mut v.find).hint_text("Search").desired_width(140.0));
        if !v.find.is_empty() {
            let n = text.to_ascii_lowercase().matches(&v.find.to_ascii_lowercase()).count();
            ui.weak(format!("{n} matches"));
        }
    });
    egui::ScrollArea::both().id_salt(id).auto_shrink(false).show(ui, |ui| {
        text_box(ui, &mut text.as_str(), &v.find);
    });
}

/// Editable raw message box filling the available space.
pub fn editor(ui: &mut egui::Ui, id: &str, text: &mut String) -> egui::text_edit::TextEditOutput {
    egui::ScrollArea::both()
        .id_salt(id)
        .auto_shrink(false)
        .show(ui, |ui| text_box(ui, text, ""))
        .inner
}

/// Context-menu entries shared by every place that shows a request.
pub fn send_menu(ui: &mut egui::Ui, env: &mut Env, url: &str, req: &[u8], res: Option<&[u8]>) {
    let target = Target::from_url(url);
    if let Some(t) = &target {
        if ui.button("Send to Repeater").clicked() {
            env.actions.push(Action::Repeater(t.clone(), req.to_vec()));
            ui.close();
        }
        if ui.button("Send to Intruder").clicked() {
            env.actions.push(Action::Intruder(t.clone(), req.to_vec()));
            ui.close();
        }
        if ui.button("Send to Sequencer").clicked() {
            env.actions.push(Action::Sequencer(t.clone(), req.to_vec()));
            ui.close();
        }
        if ui.button("Send to Discovery").clicked() {
            env.actions.push(Action::Discovery(t.clone(), req.to_vec()));
            ui.close();
        }
        if ui.button("Spider from here").clicked() {
            env.actions.push(Action::Crawl(url.to_string()));
            ui.close();
        }
        if ui.button("Do active scan").on_hover_text("Probe query and form parameters for SQLi, XSS, traversal, SSTI and open redirects").clicked() {
            env.actions.push(Action::Scan(t.clone(), crate::repeater::as_http1(t, req).into_bytes()));
            ui.close();
        }
    }
    if ui.button("Send request to Comparer").clicked() {
        env.actions.push(Action::Comparer(format!("req {url}"), req.to_vec()));
        ui.close();
    }
    if let Some(res) = res {
        if ui.button("Send response to Comparer").clicked() {
            env.actions.push(Action::Comparer(format!("res {url}"), res.to_vec()));
            ui.close();
        }
        if ui.button("Copy response body").clicked() {
            let body = http::Msg::parse(res).decoded_body();
            ui.ctx().copy_text(String::from_utf8_lossy(&body).into_owned());
            ui.close();
        }
    }
    if ui.button("Send URL to Decoder").clicked() {
        env.actions.push(Action::Decoder(url.to_string()));
        ui.close();
    }
    ui.separator();
    if ui.button("Copy URL").clicked() {
        ui.ctx().copy_text(url.to_string());
        ui.close();
    }
    if ui.button("Copy as curl").clicked() {
        ui.ctx().copy_text(http::curl(url, req));
        ui.close();
    }
    if ui.button("Copy as Python requests").clicked() {
        ui.ctx().copy_text(http::python(url, req));
        ui.close();
    }
    if ui.button("Copy as fetch").clicked() {
        ui.ctx().copy_text(http::fetch_js(url, req));
        ui.close();
    }
    if ui.button("Generate CSRF PoC (copy)").clicked() {
        ui.ctx().copy_text(http::csrf_poc(url, req));
        ui.close();
    }
    if ui.button("Add host to scope").clicked() {
        env.actions.push(Action::AddScope(url.to_string()));
        ui.close();
    }
}

/// Splits the remaining space into left and right rects at `*frac`, with a draggable handle.
pub fn hsplit(ui: &mut egui::Ui, id: &str, frac: &mut f32) -> (egui::Rect, egui::Rect) {
    let avail = ui.available_rect_before_wrap();
    ui.allocate_rect(avail, egui::Sense::hover());
    let x = avail.left() + avail.width() * *frac;
    let handle = egui::Rect::from_x_y_ranges(x - 3.0..=x + 3.0, avail.y_range());
    let resp = ui.interact(handle, ui.scope_id().with(id), egui::Sense::drag());
    if resp.hovered() || resp.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
    }
    if let Some(p) = resp.interact_pointer_pos().filter(|_| resp.dragged()) {
        *frac = ((p.x - avail.left()) / avail.width()).clamp(0.1, 0.9);
    }
    let stroke = ui.visuals().widgets.noninteractive.bg_stroke;
    ui.painter().vline(x, avail.y_range(), stroke);
    (
        egui::Rect::from_x_y_ranges(avail.left()..=x - 4.0, avail.y_range()),
        egui::Rect::from_x_y_ranges(x + 4.0..=avail.right(), avail.y_range()),
    )
}

/// Splits the remaining space into top and bottom rects at `*frac`, with a draggable handle.
pub fn vsplit(ui: &mut egui::Ui, id: &str, frac: &mut f32) -> (egui::Rect, egui::Rect) {
    let avail = ui.available_rect_before_wrap();
    ui.allocate_rect(avail, egui::Sense::hover());
    let y = avail.top() + avail.height() * *frac;
    let handle = egui::Rect::from_x_y_ranges(avail.x_range(), y - 3.0..=y + 3.0);
    let resp = ui.interact(handle, ui.scope_id().with(id), egui::Sense::drag());
    if resp.hovered() || resp.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
    }
    if let Some(p) = resp.interact_pointer_pos().filter(|_| resp.dragged()) {
        *frac = ((p.y - avail.top()) / avail.height()).clamp(0.1, 0.9);
    }
    let stroke = ui.visuals().widgets.noninteractive.bg_stroke;
    ui.painter().hline(avail.x_range(), y, stroke);
    (
        egui::Rect::from_x_y_ranges(avail.x_range(), avail.top()..=y - 4.0),
        egui::Rect::from_x_y_ranges(avail.x_range(), y + 4.0..=avail.bottom()),
    )
}

/// Runs `add` in a child UI confined and clipped to `rect`.
pub fn in_rect<R>(ui: &mut egui::Ui, rect: egui::Rect, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        ui.shrink_clip_rect(rect);
        add(ui)
    })
    .inner
}
