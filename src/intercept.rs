//! Intercept tab: holds proxied messages until the user forwards, edits or drops them.

use crate::{Action, Env, Kind, Pending, editor, http::{Msg, Target}, rules::Config};
use eframe::egui;
use std::collections::VecDeque;

#[derive(Default)]
pub struct Intercept {
    pub queue: VecDeque<Pending>,
    text: String,
    loaded: bool,
}

impl Intercept {
    pub fn push(&mut self, p: Pending, cfg: &Config) {
        if cfg.intercept.on {
            self.queue.push_back(p);
        } else {
            let _ = p.reply.send(Some(p.raw));
        }
    }

    /// Turning intercept off lets everything held go through unchanged.
    pub fn release_if_off(&mut self, cfg: &Config) {
        if !cfg.intercept.on {
            for p in self.queue.drain(..) {
                let _ = p.reply.send(Some(p.raw));
            }
            self.loaded = false;
        }
    }

    fn forward(&mut self) {
        let Some(p) = self.queue.pop_front() else { return };
        let edited = self.text != String::from_utf8_lossy(&p.raw);
        let out = match (edited, p.kind) {
            (false, _) => p.raw,
            (true, Kind::Request | Kind::Response) => {
                let mut m = Msg::parse(self.text.as_bytes());
                m.fix_content_length();
                m.render()
            }
            (true, Kind::WsOut | Kind::WsIn) => self.text.clone().into_bytes(),
        };
        let _ = p.reply.send(Some(out));
        self.loaded = false;
    }

    fn drop_current(&mut self) {
        if let Some(p) = self.queue.pop_front() {
            let _ = p.reply.send(None);
        }
        self.loaded = false;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, cfg: &mut Config, env: &mut Env) {
        // The proxy gives up on a message if its client disconnected; skip those.
        while self.queue.front().is_some_and(|p| p.reply.is_closed()) {
            self.queue.pop_front();
            self.loaded = false;
        }
        if !self.loaded {
            if let Some(p) = self.queue.front() {
                self.text = String::from_utf8_lossy(&p.raw).into_owned();
                self.loaded = true;
            }
        }
        let has = !self.queue.is_empty();
        ui.horizontal(|ui| {
            if ui.add_enabled(has, egui::Button::new("Forward")).on_hover_text("Ctrl+F").clicked() {
                self.forward();
            }
            if ui.add_enabled(has, egui::Button::new("Drop")).clicked() {
                self.drop_current();
            }
            let label = if cfg.intercept.on { "Intercept is on" } else { "Intercept is off" };
            ui.toggle_value(&mut cfg.intercept.on, label);
            ui.separator();
            ui.checkbox(&mut cfg.intercept.requests, "Requests");
            ui.checkbox(&mut cfg.intercept.responses, "Responses");
            ui.checkbox(&mut cfg.intercept.websockets, "WebSockets");
            ui.checkbox(&mut cfg.intercept.scope_only, "In-scope only");
            ui.checkbox(&mut cfg.intercept.skip_static, "Skip images/CSS/fonts");
        });
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::F)) {
            self.forward();
        }
        let Some(p) = self.queue.front() else {
            ui.add_space(20.0);
            ui.weak(if cfg.intercept.on { "Waiting for traffic…" } else { "Intercept is off." });
            return;
        };
        let what = match p.kind {
            Kind::Request => "Request to",
            Kind::Response => "Response from",
            Kind::WsOut => "WebSocket message to",
            Kind::WsIn => "WebSocket message from",
        };
        let (kind, url) = (p.kind, p.url.clone());
        ui.horizontal(|ui| {
            ui.strong(format!("{what} {url}"));
            ui.weak(format!("({} queued)", self.queue.len()));
            if kind == Kind::Request {
                if let Some(t) = Target::from_url(&url) {
                    if ui.button("Send to Repeater").clicked() {
                        env.actions.push(Action::Repeater(t, self.text.clone().into_bytes()));
                    }
                }
            }
        });
        editor(ui, "intercept_edit", &mut self.text);
    }
}
