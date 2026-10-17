//! WebSocket Repeater: open a WebSocket connection to a target and send/receive
//! messages by hand, like Burp's WebSocket repeater. One connection at a time.

use crate::{Env, Event, http};
use eframe::egui::{self, Color32};
use hudsucker::{
    futures::{SinkExt, StreamExt},
    tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message},
};
use std::sync::Arc;
use tokio::sync::mpsc;

/// What the UI tells the live connection task to do.
pub enum Cmd {
    Text(String),
    Binary(Vec<u8>),
    Ping,
    Close,
}

/// What the connection task reports back to the UI.
pub enum Note {
    Connected,
    Received(Message),
    Error(String),
    Closed,
}

enum Dir {
    Sent,
    Received,
    Info,
}

struct Line {
    dir: Dir,
    text: String,
}

pub struct WsRepeater {
    url: String,
    input: String,
    binary: bool,
    log: Vec<Line>,
    tx: Option<mpsc::UnboundedSender<Cmd>>,
    run: u64,
    connected: bool,
}

impl Default for WsRepeater {
    fn default() -> Self {
        WsRepeater {
            url: "wss://echo.websocket.org/".into(),
            input: String::new(),
            binary: false,
            log: Vec::new(),
            tx: None,
            run: 0,
            connected: false,
        }
    }
}

impl WsRepeater {
    /// Seeds the URL from a WebSocket flow sent here.
    pub fn load(&mut self, url: String) {
        self.url = url;
    }

    pub fn on_note(&mut self, run: u64, note: Note) {
        if run != self.run {
            return;
        }
        match note {
            Note::Connected => {
                self.connected = true;
                self.log.push(Line { dir: Dir::Info, text: "— connected —".into() });
            }
            Note::Received(msg) => {
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => format!("[binary {} bytes] {}", b.len(), String::from_utf8_lossy(&b)),
                    Message::Ping(_) => "[ping]".into(),
                    Message::Pong(_) => "[pong]".into(),
                    Message::Close(_) => "[close]".into(),
                    Message::Frame(_) => return,
                };
                self.log.push(Line { dir: Dir::Received, text });
            }
            Note::Error(e) => {
                self.log.push(Line { dir: Dir::Info, text: format!("— error: {e} —") });
                self.connected = false;
                self.tx = None;
            }
            Note::Closed => {
                self.log.push(Line { dir: Dir::Info, text: "— closed —".into() });
                self.connected = false;
                self.tx = None;
            }
        }
    }

    fn connect(&mut self, env: &Env) {
        self.run += 1;
        self.connected = false;
        self.log.push(Line { dir: Dir::Info, text: format!("— connecting to {} —", self.url) });
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        self.tx = Some(cmd_tx);
        let (url, run) = (self.url.clone(), self.run);
        let (ev_tx, ui) = (env.tx.clone(), env.egui.clone());
        let notify = move |n: Note| {
            let _ = ev_tx.send(Event::WsRepeater { run, note: n });
            ui.request_repaint();
        };
        // ponytail: ignores the upstream proxy; route through it if WS-over-proxy is needed
        env.rt.spawn(async move {
            let connector = Connector::Rustls(Arc::new(http::insecure_tls()));
            let stream = match connect_async_tls_with_config(&url, None, false, Some(connector)).await {
                Ok((s, _)) => s,
                Err(e) => return notify(Note::Error(e.to_string())),
            };
            notify(Note::Connected);
            let (mut write, mut read) = stream.split();
            loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => match cmd {
                        Some(Cmd::Text(t)) => { if write.send(Message::Text(t.into())).await.is_err() { break; } }
                        Some(Cmd::Binary(b)) => { if write.send(Message::Binary(b.into())).await.is_err() { break; } }
                        Some(Cmd::Ping) => { let _ = write.send(Message::Ping(Vec::new().into())).await; }
                        Some(Cmd::Close) | None => { let _ = write.send(Message::Close(None)).await; break; }
                    },
                    msg = read.next() => match msg {
                        Some(Ok(m)) => {
                            let close = matches!(m, Message::Close(_));
                            notify(Note::Received(m));
                            if close { break; }
                        }
                        Some(Err(e)) => return notify(Note::Error(e.to_string())),
                        None => break,
                    },
                }
            }
            notify(Note::Closed);
        });
    }

    fn send(&mut self) {
        if self.input.is_empty() {
            return;
        }
        let Some(tx) = &self.tx else { return };
        let text = std::mem::take(&mut self.input);
        let cmd = if self.binary { Cmd::Binary(text.clone().into_bytes()) } else { Cmd::Text(text.clone()) };
        if tx.send(cmd).is_ok() {
            self.log.push(Line { dir: Dir::Sent, text });
        } else {
            self.connected = false;
            self.tx = None;
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.label("URL");
            ui.add(egui::TextEdit::singleline(&mut self.url).desired_width(400.0).hint_text("wss://host/path"));
            if self.connected {
                if ui.button("Disconnect").clicked() {
                    if let Some(tx) = &self.tx {
                        let _ = tx.send(Cmd::Close);
                    }
                }
                ui.colored_label(Color32::from_rgb(120, 200, 120), "● connected");
            } else {
                if ui.button("Connect").clicked() {
                    self.connect(env);
                }
                ui.weak("○ disconnected");
            }
            if ui.button("Clear log").clicked() {
                self.log.clear();
            }
        });
        ui.horizontal(|ui| {
            let send = ui.add_enabled(self.connected, egui::Button::new("Send")).clicked();
            ui.checkbox(&mut self.binary, "Binary");
            if self.connected && ui.button("Ping").clicked() {
                if let Some(tx) = &self.tx {
                    let _ = tx.send(Cmd::Ping);
                }
            }
            let enter = ui.add(egui::TextEdit::singleline(&mut self.input).desired_width(f32::INFINITY).hint_text("message, Enter to send")).lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (send || enter) && self.connected {
                self.send();
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink(false).stick_to_bottom(true).show(ui, |ui| {
            for line in &self.log {
                let (prefix, color) = match line.dir {
                    Dir::Sent => ("→ ", Color32::from_rgb(120, 175, 255)),
                    Dir::Received => ("← ", Color32::from_rgb(120, 200, 120)),
                    Dir::Info => ("", ui.visuals().weak_text_color()),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.add(egui::Label::new(egui::RichText::new(format!("{prefix}{}", line.text)).monospace().color(color)));
                });
            }
        });
    }
}
