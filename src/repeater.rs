//! Repeater tab: edit a raw request and resend it, one tab per request.

use crate::{
    Env, Viewer, Event, editor,
    http::{self, Target},
    message_view, send_menu,
};
use eframe::egui;

struct Tab {
    id: u64,
    name: String,
    target: Target,
    request: String,
    response: Option<Vec<u8>>,
    info: String,
    busy: bool,
    update_length: bool,
    /// Sent requests and their responses, for back/forward.
    past: Vec<(String, Option<Vec<u8>>)>,
    pos: usize,
}

#[derive(Default)]
pub struct Repeater {
    tabs: Vec<Tab>,
    renaming: Option<usize>,
    current: usize,
    next_id: u64,
    view: Viewer,
}

/// History may hold HTTP/2 requests; the raw client speaks HTTP/1.1.
pub fn as_http1(target: &Target, raw: &[u8]) -> String {
    let raw = match raw.split(|&b| b == b'\n').next() {
        Some(line) if line.trim_ascii_end().ends_with(b"HTTP/2") => http::to_http1(raw, &target.host_header()),
        _ => raw.to_vec(),
    };
    String::from_utf8_lossy(&raw).into_owned()
}

impl Repeater {
    pub fn add(&mut self, target: Target, raw: Vec<u8>) {
        self.next_id += 1;
        let request = as_http1(&target, &raw);
        self.tabs.push(Tab {
            id: self.next_id,
            name: self.next_id.to_string(),
            target,
            request,
            response: None,
            info: String::new(),
            busy: false,
            update_length: true,
            past: Vec::new(),
            pos: 0,
        });
        self.current = self.tabs.len() - 1;
    }

    pub fn on_result(&mut self, id: u64, result: Result<http::Reply, String>) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == id) else { return };
        tab.busy = false;
        match result {
            Ok(r) => {
                tab.info = format!("{} · {} bytes · {} ms", r.status, r.raw.len(), r.elapsed.as_millis());
                tab.response = Some(r.raw);
            }
            Err(e) => {
                tab.info = format!("Error: {e}");
                tab.response = None;
            }
        }
        if let Some(last) = tab.past.last_mut() {
            last.1 = tab.response.clone();
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let mut close = None;
        ui.horizontal_wrapped(|ui| {
            for (i, tab) in self.tabs.iter_mut().enumerate() {
                if self.renaming == Some(i) {
                    let r = ui.add(egui::TextEdit::singleline(&mut tab.name).desired_width(120.0));
                    r.request_focus();
                    if r.lost_focus() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.renaming = None;
                    }
                    continue;
                }
                let r = ui.selectable_label(self.current == i, &tab.name).on_hover_text("Double-click to rename");
                if r.clicked() {
                    self.current = i;
                }
                if r.double_clicked() {
                    self.renaming = Some(i);
                }
                if r.middle_clicked() {
                    close = Some(i);
                }
                r.context_menu(|ui| {
                    if ui.button("Rename").clicked() {
                        self.renaming = Some(i);
                        ui.close();
                    }
                    if ui.button("Close tab").clicked() {
                        close = Some(i);
                        ui.close();
                    }
                });
            }
            if ui.button("+").on_hover_text("New tab").clicked() {
                let t = Target { host: "example.com".into(), port: 443, tls: true };
                self.add(t, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
            }
        });
        if let Some(i) = close {
            self.renaming = None;
            self.tabs.remove(i);
            self.current = self.current.min(self.tabs.len().saturating_sub(1));
        }
        let Some(tab) = self.tabs.get_mut(self.current) else {
            ui.add_space(20.0);
            ui.weak("Send a request here from Proxy history (right-click → Send to Repeater, or Ctrl+R).");
            return;
        };
        ui.separator();

        let mut send = ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter));
        ui.horizontal(|ui| {
            send |= ui
                .add_enabled(!tab.busy, egui::Button::new(if tab.busy { "Sending…" } else { "Send" }))
                .on_hover_text("Ctrl+Enter")
                .clicked();
            if ui.add_enabled(tab.pos > 0, egui::Button::new("<")).clicked() {
                tab.pos -= 1;
                (tab.request, tab.response) = tab.past[tab.pos].clone();
            }
            if ui.add_enabled(tab.pos + 1 < tab.past.len(), egui::Button::new(">")).clicked() {
                tab.pos += 1;
                (tab.request, tab.response) = tab.past[tab.pos].clone();
            }
            ui.separator();
            ui.label("Target");
            ui.add(egui::TextEdit::singleline(&mut tab.target.host).desired_width(220.0));
            ui.add(egui::DragValue::new(&mut tab.target.port).range(1..=65535));
            ui.checkbox(&mut tab.target.tls, "HTTPS");
            ui.checkbox(&mut tab.update_length, "Update Content-Length");
            let redirect = tab.response.as_deref().and_then(|r| {
                let m = http::Msg::parse(r);
                (300..400).contains(&m.status()).then(|| m.header("location").map(str::to_string)).flatten()
            });
            if let Some(location) = redirect {
                if ui.add_enabled(!tab.busy, egui::Button::new("Follow redirection")).on_hover_text(&location).clicked() {
                    let status = tab.response.as_deref().map_or(0, |r| http::Msg::parse(r).status());
                    (tab.target, tab.request) = http::follow_redirect(&tab.target, &tab.request, &location, status);
                    send = true;
                }
            }
            ui.separator();
            ui.label(&tab.info);
        });
        if send && !tab.busy {
            tab.busy = true;
            tab.past.push((tab.request.clone(), None));
            tab.pos = tab.past.len() - 1;
            let bytes = http::to_wire(&tab.request, tab.update_length);
            let (id, target, upstream) = (tab.id, tab.target.clone(), env.upstream());
            let (tx, ui) = (env.tx.clone(), env.egui.clone());
            env.rt.spawn(async move {
                let result = http::send(&target, &bytes, &upstream).await;
                let _ = tx.send(Event::Log(crate::logger::entry("Repeater", &target, &bytes, &result)));
                let _ = tx.send(Event::Repeater { tab: id, result });
                ui.request_repaint();
            });
        }

        let url = format!(
            "{}{}",
            tab.target.url(),
            tab.request.split_whitespace().nth(1).filter(|p| p.starts_with('/')).unwrap_or("/")
        );
        ui.columns(2, |cols| {
            cols[0].strong("Request");
            let out = editor(&mut cols[0], "rep_req", &mut tab.request);
            out.response.context_menu(|ui| {
                send_menu(ui, env, &url, tab.request.as_bytes(), tab.response.as_deref());
            });
            cols[1].strong("Response");
            match &tab.response {
                Some(r) => message_view(&mut cols[1], "rep_res", r, &mut self.view),
                None => {
                    cols[1].weak("No response yet.");
                }
            }
        });
    }
}
