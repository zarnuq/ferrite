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
    group: String,
    target: Target,
    request: String,
    response: Option<Vec<u8>>,
    info: String,
    busy: bool,
    http2: bool,
    update_length: bool,
    use_cookies: bool,
    /// Sent requests and their responses, for back/forward.
    past: Vec<Exchange>,
    inspect: bool,
    inspector: crate::inspector::Inspector,
    pos: usize,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Exchange {
    target: Target,
    request: String,
    response: Option<Vec<u8>>,
    info: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct SavedState {
    tabs: Vec<SavedTab>,
    current: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedTab {
    name: String,
    #[serde(default)]
    group: String,
    target: Target,
    request: String,
    response: Option<Vec<u8>>,
    info: String,
    #[serde(default)]
    http2: bool,
    update_length: bool,
    #[serde(default)]
    use_cookies: bool,
    past: Vec<Exchange>,
    pos: usize,
}

pub struct Repeater {
    tabs: Vec<Tab>,
    renaming: Option<usize>,
    current: usize,
    next_id: u64,
    group_filter:String,
    group_mode: crate::groups::Mode,
    view: Viewer,
}

impl Default for Repeater {
    fn default() -> Self {
        Self { tabs: Vec::new(), renaming: None, current: 0, next_id: 0, group_filter:String::new(),group_mode: Default::default(), view: Viewer::new(http::View::Pretty) }
    }
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
    pub fn is_empty(&self) -> bool { self.tabs.is_empty() }

    pub fn save_state(&self) -> SavedState {
        SavedState {
            current: self.current,
            tabs: self.tabs.iter().map(|t| SavedTab {
                name: t.name.clone(), group: t.group.clone(), target: t.target.clone(), request: t.request.clone(),
                response: t.response.clone(), info: t.info.clone(), http2:t.http2, update_length: t.update_length,
                past: t.past.clone(), pos: t.pos, use_cookies: t.use_cookies,
            }).collect(),
        }
    }

    pub fn restore(&mut self, state: SavedState) {
        self.tabs.clear();
        self.group_filter.clear();
        self.renaming = None;
        for saved in state.tabs {
            // Never reuse an id: responses from pre-load sends must not update restored tabs.
            self.next_id += 1;
            self.tabs.push(Tab {
                id: self.next_id, name: saved.name, group: saved.group, target: saved.target, request: saved.request,
                response: saved.response, info: saved.info, http2:saved.http2,update_length: saved.update_length,
                pos: saved.pos.min(saved.past.len().saturating_sub(1)), past: saved.past,
                busy: false, inspect: false, use_cookies: saved.use_cookies, inspector: Default::default(),
            });
        }
        self.current = state.current.min(self.tabs.len().saturating_sub(1));
    }

    pub fn add(&mut self, target: Target, raw: Vec<u8>) {
        self.next_id += 1;
        let request = as_http1(&target, &raw);
        self.tabs.push(Tab {
            id: self.next_id,
            name: self.next_id.to_string(),
            group: self.group_filter.clone(),
            target,
            request,
            response: None,
            info: String::new(),
            busy: false,
            http2:false,
            update_length: true,
            use_cookies: false,
            past: Vec::new(),
            pos: 0,
            inspect: false,
            inspector: Default::default(),
        });
        self.current = self.tabs.len() - 1;
    }

    pub fn on_sent(&mut self, id: u64, request: Vec<u8>) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == id) {
            tab.request = String::from_utf8_lossy(&request).into_owned();
            if let Some(last) = tab.past.last_mut() { last.request = tab.request.clone(); }
        }
    }

    pub fn on_result(&mut self, id: u64, result: Result<http::Reply, String>) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == id) else { return };
        tab.busy = false;
        match result {
            Ok(r) => {
                tab.info = format!("{} · {} bytes · {} ms", r.status, r.raw.len(), r.elapsed.as_millis());
                tab.response = Some(crate::retention::clip(r.raw));
            }
            Err(e) => {
                tab.info = format!("Error: {e}");
                tab.response = None;
            }
        }
        if let Some(last) = tab.past.last_mut() {
            last.response = tab.response.clone();
            last.info = tab.info.clone();
        }
    }

    fn send_group(&mut self, env: &Env) {
        let Some(current) = self.tabs.get(self.current) else { return };
        let group = current.group.clone(); let target = current.target.clone();
        let indices: Vec<_> = self.tabs.iter().enumerate().filter(|(_,t)| t.group == group).map(|(i,_)| i).collect();
        let invalid = group.is_empty() || indices.len() > 100 || indices.iter().any(|&i| self.tabs[i].busy || self.tabs[i].target.url() != target.url());
        if invalid { self.tabs[self.current].info = "Groups need 1–100 idle tabs on the same origin".into(); return; }
        if crate::rules::current(env.shared).cfg.session_macros.iter().any(|m| m.enabled) {
            self.tabs[self.current].info = "Disable session macros for synchronized sends; tokens must be prepared before the group".into(); return;
        }
        let mut jobs = Vec::new();
        for i in indices {
            let tab = &mut self.tabs[i];
            let session = env.session(tab.use_cookies);
            let bytes = session.prepare(&target, &http::to_wire(&tab.request, tab.update_length));
            tab.request = String::from_utf8_lossy(&bytes).into_owned();
            tab.busy = true;
            tab.past.push(Exchange { target: target.clone(), request: tab.request.clone(), response: None, info: String::new() });
            tab.pos = tab.past.len()-1;
            jobs.push((tab.id, bytes, session));
        }
        let mode = self.group_mode;
        let upstream = env.upstream(); let (tx, ctx) = (env.tx.clone(), env.egui.clone());
        env.rt.spawn(async move {
            let results = crate::groups::send(target.clone(), jobs.iter().map(|(_,r,_)| r.clone()).collect(), upstream, mode).await;
            for (index,result) in results {
                let (id,raw,session) = &jobs[index];
                session.capture(&target,raw,&result);
                let _ = tx.send(Event::Log(crate::logger::entry("Repeater", &target, raw, &result)));
                let _ = tx.send(Event::Repeater { tab: *id, result });
            }
            ctx.request_repaint();
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui|{
            egui::ComboBox::from_id_salt("repeater_group_filter").selected_text(if self.group_filter.is_empty(){"All groups"}else{&self.group_filter}).show_ui(ui,|ui|{
                ui.selectable_value(&mut self.group_filter,String::new(),"All groups");
                let groups:std::collections::BTreeSet<_>=self.tabs.iter().map(|t|t.group.clone()).filter(|g|!g.is_empty()).collect();
                for group in groups{if ui.selectable_value(&mut self.group_filter,group.clone(),&group).clicked(){if let Some(i)=self.tabs.iter().position(|t|t.group==group){self.current=i;}}}
            });
            ui.weak("Parallel / last-byte sync prepares all connections before releasing requests. HTTP/2 multiplexing does not guarantee one TCP packet.");
        });
        let mut close = None;
        let mut duplicate = None;
        ui.horizontal_wrapped(|ui| {
            for (i, tab) in self.tabs.iter_mut().enumerate() {
                if !self.group_filter.is_empty()&&tab.group!=self.group_filter{continue;}
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
                    if ui.button("Duplicate tab").clicked() {
                        duplicate = Some((tab.target.clone(), tab.request.as_bytes().to_vec(),tab.group.clone(),tab.http2));
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
            if i < self.current { self.current -= 1; }
            self.current = self.current.min(self.tabs.len().saturating_sub(1));
            if !self.group_filter.is_empty(){if let Some(i)=self.tabs.iter().position(|t|t.group==self.group_filter){self.current=i;}else{self.group_filter.clear();}}
        }
        if let Some((target, request,group,http2)) = duplicate { self.add(target, request); let t=&mut self.tabs[self.current];t.group=group;t.http2=http2; }
        let mut send_group = false;
        if let Some(tab) = self.tabs.get_mut(self.current) {
            ui.horizontal(|ui| {
                ui.label("Group");
                ui.add(egui::TextEdit::singleline(&mut tab.group).hint_text("Name to group tabs").desired_width(140.0));
                egui::ComboBox::from_id_salt("group_send_mode").selected_text(self.group_mode.label()).show_ui(ui, |ui| {
                    for (mode,label) in crate::groups::Mode::ALL { ui.selectable_value(&mut self.group_mode,mode,label); }
                });
                send_group = ui.add_enabled(!tab.group.is_empty() && !tab.busy, egui::Button::new("Send group")).clicked();
            });
        }
        if send_group { self.send_group(env); }
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
            if ui.add_enabled(!tab.busy && tab.pos > 0, egui::Button::new("<")).clicked() {
                tab.pos -= 1;
                let saved = &tab.past[tab.pos];
                tab.target = saved.target.clone();
                tab.request = saved.request.clone();
                tab.response = saved.response.clone();
                tab.info = saved.info.clone();
            }
            if ui.add_enabled(!tab.busy && tab.pos + 1 < tab.past.len(), egui::Button::new(">")).clicked() {
                tab.pos += 1;
                let saved = &tab.past[tab.pos];
                tab.target = saved.target.clone();
                tab.request = saved.request.clone();
                tab.response = saved.response.clone();
                tab.info = saved.info.clone();
            }
            ui.separator();
            ui.label("Target");
            ui.add(egui::TextEdit::singleline(&mut tab.target.host).desired_width(220.0));
            ui.add(egui::DragValue::new(&mut tab.target.port).range(1..=65535));
            ui.checkbox(&mut tab.target.tls, "HTTPS");
            ui.checkbox(&mut tab.http2,"HTTP/2").on_hover_text("Send over HTTP/2; the editor uses HTTP/1-style headers. HTTPS requires h2 ALPN; plain HTTP uses prior knowledge.");
            ui.checkbox(&mut tab.update_length, "Update Content-Length");
            ui.checkbox(&mut tab.use_cookies, "Use session cookies");
            let redirect = tab.response.as_deref().and_then(|r| {
                let m = http::Msg::parse(r);
                (300..400).contains(&m.status()).then(|| m.header("location").map(str::to_string)).flatten()
            });
            if let Some(location) = redirect {
                if ui.add_enabled(!tab.busy, egui::Button::new("Follow redirection")).on_hover_text(&location).clicked() {
                    let status = tab.response.as_deref().map_or(0, |r| http::Msg::parse(r).status());
                    match http::follow_redirect(&tab.target, &tab.request, &location, status) {
                        Ok((target, request)) => { tab.target = target; tab.request = request; send = true; }
                        Err(error) => tab.info = error,
                    }
                }
            }
            ui.separator();
            ui.label(&tab.info);
        });
        if send && !tab.busy {
            tab.busy = true;
            let session = env.session(tab.use_cookies);
            let bytes = session.prepare(&tab.target, &http::to_wire(&tab.request, tab.update_length));
            tab.request = String::from_utf8_lossy(&bytes).into_owned();
            tab.past.push(Exchange {
                target: tab.target.clone(), request: tab.request.clone(), response: None, info: String::new(),
            });
            if tab.past.len() > 100 { tab.past.remove(0); }
            tab.pos = tab.past.len() - 1;
            let http2=tab.http2;
            let (id, target, upstream) = (tab.id, tab.target.clone(), env.upstream());
            let (tx, ui) = (env.tx.clone(), env.egui.clone());
            env.rt.spawn(async move {
                let (bytes, result) = session.send_protocol(&target, &bytes, &upstream,http2).await;
                let _ = tx.send(Event::RepeaterSent { tab: id, request: bytes.clone() });
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
            cols[0].horizontal(|ui| {
                ui.strong("Request");
                ui.selectable_value(&mut tab.inspect, false, "Raw");
                ui.selectable_value(&mut tab.inspect, true, "Inspector");
            });
            if tab.inspect {
                tab.inspector.ui(&mut cols[0], &mut tab.request, tab.id);
            } else {
                let out = editor(&mut cols[0], "rep_req", &mut tab.request);
                out.response.context_menu(|ui| {
                    send_menu(ui, env, &url, tab.request.as_bytes(), tab.response.as_deref());
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_tabs_preserve_edits_and_exchanges_and_ignore_old_replies() {
        let mut repeater = Repeater::default();
        let target = Target::from_url("https://example.com:8443/").unwrap();
        repeater.add(target.clone(), b"GET /edited HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
        let tab = &mut repeater.tabs[0];
        tab.name = "Authorization checks".into();
        tab.http2=true;tab.group="Access checks".into();
        tab.update_length = false;
        tab.past.push(Exchange {
            target: target.clone(), request: "GET /first HTTP/1.1\r\n\r\n".into(),
            response: Some(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec()), info: "403 · 10 ms".into(),
        });
        let old_id = tab.id;
        tab.busy = true;
        let bytes = serde_json::to_vec(&repeater.save_state()).unwrap();
        repeater.restore(serde_json::from_slice(&bytes).unwrap());
        let tab = &repeater.tabs[0];
        assert_eq!(tab.name, "Authorization checks");
        assert!(tab.http2);assert_eq!(tab.group,"Access checks");
        assert_eq!(tab.target.port, 8443);
        assert!(!tab.update_length);
        assert!(!tab.busy);
        assert!(tab.request.contains("/edited"));
        assert!(tab.past[0].request.contains("/first"));
        assert_eq!(tab.past[0].info, "403 · 10 ms");
        assert_ne!(tab.id, old_id);
        repeater.on_result(old_id, Err("stale response".into()));
        assert!(repeater.tabs[0].info.is_empty());
    }
}
