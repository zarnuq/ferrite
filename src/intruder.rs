//! Intruder tab: marks § positions in a request and fires payload combinations at it.

use crate::{
    Env, Viewer, Event, editor, in_rect, vsplit,
    http::{self, Target, View},
    message_view, repeater::as_http1, send_menu,
};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use regex::Regex;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq)]
enum Attack {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
    /// The unmodified request repeated, e.g. for race conditions.
    Null,
}

impl Attack {
    const ALL: [Attack; 5] = [Attack::Sniper, Attack::BatteringRam, Attack::Pitchfork, Attack::ClusterBomb, Attack::Null];

    fn label(self) -> &'static str {
        match self {
            Attack::Sniper => "Sniper",
            Attack::BatteringRam => "Battering ram",
            Attack::Pitchfork => "Pitchfork",
            Attack::ClusterBomb => "Cluster bomb",
            Attack::Null => "Null payloads (repeat)",
        }
    }
}

/// Characters Burp URL-encodes in payloads by default.
const PAYLOAD_ENCODE: &AsciiSet =
    &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'%').add(b'&').add(b'+').add(b',').add(b'/').add(b':').add(b';')
        .add(b'<').add(b'=').add(b'>').add(b'?').add(b'@').add(b'[').add(b'\\').add(b']').add(b'^').add(b'`')
        .add(b'{').add(b'|').add(b'}');

const MAX_REQUESTS: usize = 1_000_000;

/// Expands a § template into (payloads, request text) pairs for the chosen attack.
fn generate(
    template: &str,
    attack: Attack,
    sets: &[Vec<String>],
    repeat: usize,
) -> Result<Vec<(Vec<String>, String)>, String> {
    let parts: Vec<&str> = template.split('§').collect();
    if parts.len() % 2 == 0 {
        return Err("Unbalanced § markers".into());
    }
    let n = parts.len() / 2;
    if attack == Attack::Null {
        let plain = template.replace('§', "");
        return Ok((1..=repeat.min(MAX_REQUESTS)).map(|i| (vec![format!("null {i}")], plain.clone())).collect());
    }
    if n == 0 {
        return Err("No § positions marked".into());
    }
    let defaults: Vec<&str> = (0..n).map(|i| parts[2 * i + 1]).collect();
    let build = |vals: &[&str]| {
        let mut s = String::with_capacity(template.len());
        for (i, p) in parts.iter().enumerate() {
            s.push_str(if i % 2 == 0 { p } else { vals[i / 2] });
        }
        s
    };
    let list = |i: usize| sets.get(i).map(|s| s.as_slice()).unwrap_or_default();
    let mut out = Vec::new();
    match attack {
        Attack::Sniper => {
            for pos in 0..n {
                for p in list(0) {
                    let mut v = defaults.clone();
                    v[pos] = p;
                    out.push((vec![p.clone()], build(&v)));
                }
            }
        }
        Attack::BatteringRam => {
            for p in list(0) {
                out.push((vec![p.clone()], build(&vec![p.as_str(); n])));
            }
        }
        Attack::Pitchfork => {
            let len = (0..n).map(|i| list(i).len()).min().unwrap_or(0);
            for k in 0..len {
                let v: Vec<&str> = (0..n).map(|i| list(i)[k].as_str()).collect();
                out.push((v.iter().map(|s| s.to_string()).collect(), build(&v)));
            }
        }
        Attack::ClusterBomb => {
            let total = (0..n).try_fold(1usize, |acc, i| acc.checked_mul(list(i).len()));
            match total {
                Some(0) => {}
                Some(t) if t <= MAX_REQUESTS => {
                    let mut idx = vec![0usize; n];
                    'outer: loop {
                        let v: Vec<&str> = (0..n).map(|i| list(i)[idx[i]].as_str()).collect();
                        out.push((v.iter().map(|s| s.to_string()).collect(), build(&v)));
                        for i in (0..n).rev() {
                            idx[i] += 1;
                            if idx[i] < list(i).len() {
                                continue 'outer;
                            }
                            idx[i] = 0;
                        }
                        break;
                    }
                }
                _ => return Err(format!("More than {MAX_REQUESTS} requests")),
            }
        }
        Attack::Null => unreachable!(),
    }
    if out.len() > MAX_REQUESTS {
        return Err(format!("More than {MAX_REQUESTS} requests"));
    }
    Ok(out)
}

/// Marks parameter values in the request line, Cookie header and body, like Burp's "Auto §".
fn auto_mark(template: &str) -> String {
    let params = Regex::new(r"([?&;]\s*|^\s*)([^=&;?\s]+)=([^&;\s#]*)").unwrap();
    let json = Regex::new(r#"("[^"]+"\s*:\s*")([^"]*)(")"#).unwrap();
    let mark = |s: &str| params.replace_all(s, "$1$2=§$3§").into_owned();
    let blank = [template.find("\n\n"), template.find("\r\n\r\n")].into_iter().flatten().min();
    let (head, body) = match blank {
        Some(i) => template.split_at(i),
        None => (template, ""),
    };
    let mut out = String::new();
    for (n, line) in head.split_inclusive('\n').enumerate() {
        if n == 0 {
            match line.split_once('?') {
                Some((path, rest)) => {
                    let (query, tail) = rest.split_once(' ').unwrap_or((rest, ""));
                    out += &format!("{path}?{}{}{tail}", mark(query), if tail.is_empty() { "" } else { " " });
                }
                None => out += line,
            }
        } else if let Some(v) = line.strip_prefix("Cookie:").or_else(|| line.strip_prefix("cookie:")) {
            out += &format!("{}:{}", &line[..6], mark(v));
        } else {
            out += line;
        }
    }
    let trimmed = body.trim_start();
    let body = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        json.replace_all(body, "$1§$2§$3").into_owned()
    } else if body.contains('=') {
        let lead = body.len() - trimmed.len();
        format!("{}{}", &body[..lead], mark(trimmed))
    } else {
        body.to_string()
    };
    out + &body
}

struct Row {
    payloads: String,
    req: Vec<u8>,
    res: Option<Vec<u8>>,
    status: u16,
    ms: u128,
    error: String,
    grep: bool,
    extract: String,
    done: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Id,
    Payload,
    Status,
    Length,
    Time,
    Grep,
    Extract,
}

pub struct Intruder {
    target: Target,
    template: String,
    selection: Option<(usize, usize)>,
    attack: Attack,
    sets: Vec<String>,
    set: usize,
    load_path: String,
    numbers: (i64, i64, i64),
    encode: bool,
    prefix: String,
    suffix: String,
    repeat: usize,
    extract: String,
    threads: usize,
    delay_ms: u64,
    grep: String,
    attack_id: u64,
    rows: Vec<Row>,
    done: usize,
    cancel: Option<Arc<AtomicBool>>,
    selected: Option<usize>,
    sort: (Col, bool),
    view: Viewer,
    message: String,
    split: f32,
}

impl Default for Intruder {
    fn default() -> Self {
        Intruder {
            target: Target { host: "example.com".into(), port: 443, tls: true },
            template: "GET /?q=§x§ HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            selection: None,
            attack: Attack::Sniper,
            sets: vec![String::new()],
            set: 0,
            load_path: String::new(),
            numbers: (1, 100, 1),
            encode: true,
            prefix: String::new(),
            suffix: String::new(),
            repeat: 20,
            extract: String::new(),
            threads: 10,
            delay_ms: 0,
            grep: String::new(),
            attack_id: 0,
            rows: Vec::new(),
            done: 0,
            cancel: None,
            selected: None,
            sort: (Col::Id, true),
            view: Viewer::new(View::Raw),
            message: String::new(),
            split: 0.45,
        }
    }
}

impl Intruder {
    pub fn load(&mut self, target: Target, raw: Vec<u8>) {
        self.template = as_http1(&target, &raw);
        self.target = target;
    }

    pub fn on_result(&mut self, attack: u64, idx: usize, result: Result<http::Reply, String>) {
        if attack != self.attack_id {
            return;
        }
        let Some(row) = self.rows.get_mut(idx) else { return };
        row.done = true;
        self.done += 1;
        match result {
            Ok(r) => {
                row.status = r.status;
                row.ms = r.elapsed.as_millis();
                row.grep = !self.grep.is_empty() && memmem(&r.raw, self.grep.as_bytes());
                row.extract = extract(&self.extract, &r.raw);
                row.res = Some(r.raw);
            }
            Err(e) => row.error = e,
        }
        if self.done == self.rows.len() {
            self.cancel = None;
        }
    }

    fn positions(&self) -> usize {
        self.template.matches('§').count() / 2
    }

    fn sets_needed(&self) -> usize {
        match self.attack {
            Attack::Sniper | Attack::BatteringRam | Attack::Null => 1,
            _ => self.positions().max(1),
        }
    }

    fn start(&mut self, env: &Env) {
        let sets: Vec<Vec<String>> = self
            .sets
            .iter()
            .map(|s| {
                s.lines()
                    .map(|p| format!("{}{p}{}", self.prefix, self.suffix))
                    .map(|p| if self.encode { utf8_percent_encode(&p, PAYLOAD_ENCODE).to_string() } else { p })
                    .collect()
            })
            .collect();
        let requests = match generate(&self.template, self.attack, &sets, self.repeat) {
            Ok(r) if r.is_empty() => {
                self.message = "No payloads.".into();
                return;
            }
            Ok(r) => r,
            Err(e) => {
                self.message = e;
                return;
            }
        };
        self.message.clear();
        self.attack_id += 1;
        self.done = 0;
        self.selected = None;
        self.rows = requests
            .into_iter()
            .map(|(payloads, text)| Row {
                payloads: payloads.join(", "),
                req: http::to_wire(&text, true),
                res: None,
                status: 0,
                ms: 0,
                error: String::new(),
                grep: false,
                extract: String::new(),
                done: false,
            })
            .collect();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let jobs: Vec<Vec<u8>> = self.rows.iter().map(|r| r.req.clone()).collect();
        let (tx, ui, target, upstream) = (env.tx.clone(), env.egui.clone(), self.target.clone(), env.upstream());
        let (attack, threads, delay) = (self.attack_id, self.threads.max(1), self.delay_ms);
        env.rt.spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(threads));
            for (idx, raw) in jobs.into_iter().enumerate() {
                let permit = limit.clone().acquire_owned().await.unwrap();
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let (tx, ui, target, upstream) = (tx.clone(), ui.clone(), target.clone(), upstream.clone());
                tokio::spawn(async move {
                    let result = http::send(&target, &raw, &upstream).await;
                    let _ = tx.send(Event::Log(crate::logger::entry("Intruder", &target, &raw, &result)));
                    let _ = tx.send(Event::Intruder { attack, idx, result });
                    ui.request_repaint();
                    drop(permit);
                });
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        let running = self.cancel.is_some();
        ui.horizontal(|ui| {
            ui.label("Target");
            ui.add(egui::TextEdit::singleline(&mut self.target.host).desired_width(200.0));
            ui.add(egui::DragValue::new(&mut self.target.port).range(1..=65535));
            ui.checkbox(&mut self.target.tls, "HTTPS");
            ui.separator();
            egui::ComboBox::from_id_salt("attack")
                .selected_text(self.attack.label())
                .show_ui(ui, |ui| {
                    for a in Attack::ALL {
                        ui.selectable_value(&mut self.attack, a, a.label());
                    }
                });
            ui.label("Threads");
            ui.add(egui::DragValue::new(&mut self.threads).range(1..=200));
            ui.label("Delay ms");
            ui.add(egui::DragValue::new(&mut self.delay_ms).range(0..=60_000));
            ui.separator();
            if running {
                if ui.button("Stop").clicked() {
                    if let Some(c) = self.cancel.take() {
                        c.store(true, Ordering::Relaxed);
                    }
                }
            } else if ui.button("Start attack").clicked() {
                self.start(env);
            }
            if !self.rows.is_empty() {
                ui.label(format!("{}/{} done", self.done, self.rows.len()));
            }
            ui.colored_label(egui::Color32::LIGHT_RED, &self.message);
        });

        let needed = self.sets_needed();
        self.sets.resize(needed, String::new());
        self.set = self.set.min(needed - 1);

        let (top, bottom) = vsplit(ui, "intruder_split", &mut self.split);
        in_rect(ui, bottom, |ui| self.results_ui(ui, env));
        in_rect(ui, top, |ui| ui.columns(2, |cols| {
            let ui = &mut cols[0];
            ui.horizontal(|ui| {
                ui.strong(format!("Positions ({})", self.positions()));
                if ui.button("Add §").on_hover_text("Wrap the selection in § markers").clicked() {
                    self.add_marker();
                }
                if ui.button("Clear §").clicked() {
                    self.template = self.template.replace('§', "");
                }
                if ui.button("Auto §").clicked() {
                    self.template = auto_mark(&self.template.replace('§', ""));
                }
            });
            let out = editor(ui, "intruder_tpl", &mut self.template);
            if let Some(r) = out.cursor_range {
                let (a, b) = (r.primary.index, r.secondary.index);
                self.selection = Some((a.min(b).into(), a.max(b).into()));
            }

            let ui = &mut cols[1];
            ui.horizontal_wrapped(|ui| {
                ui.strong("Payload set");
                for i in 0..needed {
                    ui.selectable_value(&mut self.set, i, (i + 1).to_string());
                }
                ui.weak(format!("{} payloads", self.sets[self.set].lines().count()));
                ui.checkbox(&mut self.encode, "URL-encode special chars");
            });
            if self.attack == Attack::Null {
                ui.horizontal(|ui| {
                    ui.label("Send the request");
                    ui.add(egui::DragValue::new(&mut self.repeat).range(1..=MAX_REQUESTS));
                    ui.label("times. Set threads to the same number to fire them together.");
                });
                return;
            }
            ui.horizontal(|ui| {
                ui.label("Prefix");
                ui.add(egui::TextEdit::singleline(&mut self.prefix).desired_width(100.0));
                ui.label("Suffix");
                ui.add(egui::TextEdit::singleline(&mut self.suffix).desired_width(100.0));
            });
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.load_path).hint_text("/path/to/wordlist").desired_width(220.0));
                if ui.button("Load file").clicked() {
                    match std::fs::read(&self.load_path) {
                        Ok(b) => self.sets[self.set] = String::from_utf8_lossy(&b).into_owned(),
                        Err(e) => self.message = format!("{}: {e}", self.load_path),
                    }
                }
                ui.separator();
                let (from, to, step) = &mut self.numbers;
                ui.add(egui::DragValue::new(from).prefix("from "));
                ui.add(egui::DragValue::new(to).prefix("to "));
                ui.add(egui::DragValue::new(step).prefix("step ").range(1..=i64::MAX));
                if ui.button("Numbers").clicked() {
                    let (from, to, step) = self.numbers;
                    let nums: Vec<String> = (from..=to).step_by(step.max(1) as usize).take(MAX_REQUESTS).map(|n| n.to_string()).collect();
                    self.sets[self.set] = nums.join("\n");
                }
                if ui.button("Clear").clicked() {
                    self.sets[self.set].clear();
                }
            });
            editor(ui, "intruder_set", &mut self.sets[self.set]);
        }));
    }

    /// Wraps the last editor selection (char offsets) in § markers.
    fn add_marker(&mut self) {
        let Some((a, b)) = self.selection else { return };
        let byte = |c: usize| self.template.char_indices().nth(c).map_or(self.template.len(), |(i, _)| i);
        let (a, b) = (byte(a), byte(b));
        self.template.insert(b, '§');
        self.template.insert(a, '§');
        self.selection = None;
    }

    fn results_ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.strong("Results");
            ui.label("Grep match");
            if ui.text_edit_singleline(&mut self.grep).changed() {
                for r in &mut self.rows {
                    r.grep = !self.grep.is_empty() && r.res.as_ref().is_some_and(|b| memmem(b, self.grep.as_bytes()));
                }
            }
            ui.label("Extract regex");
            let valid = self.extract.is_empty() || Regex::new(&self.extract).is_ok();
            let mut edit = egui::TextEdit::singleline(&mut self.extract).hint_text("token=(\\w+)").desired_width(200.0);
            if !valid {
                edit = edit.text_color(egui::Color32::LIGHT_RED);
            }
            if ui.add(edit).changed() {
                for r in &mut self.rows {
                    r.extract = r.res.as_deref().map(|b| extract(&self.extract, b)).unwrap_or_default();
                }
            }
            if !self.rows.is_empty() && ui.button("Copy CSV").clicked() {
                ui.ctx().copy_text(results_csv(&self.rows));
            }
        });
        let len = |r: &Row| r.res.as_ref().map_or(0, |b| b.len());
        let mut order: Vec<usize> = (0..self.rows.len()).collect();
        let (col, asc) = self.sort;
        if col != Col::Id || !asc {
            let rows = &self.rows;
            order.sort_by(|&a, &b| {
                let (x, y) = (&rows[a], &rows[b]);
                let o = match col {
                    Col::Id => a.cmp(&b),
                    Col::Payload => x.payloads.cmp(&y.payloads),
                    Col::Status => x.status.cmp(&y.status),
                    Col::Length => len(x).cmp(&len(y)),
                    Col::Time => x.ms.cmp(&y.ms),
                    Col::Grep => x.grep.cmp(&y.grep),
                    Col::Extract => x.extract.cmp(&y.extract),
                };
                if asc { o } else { o.reverse() }
            });
        }
        ui.columns(2, |cols| {
            let mut clicked = None;
            let mut sort_click = None;
            TableBuilder::new(&mut cols[0])
                .id_salt("intruder_table")
                .striped(true)
                .sense(egui::Sense::click())
                .column(Column::auto().at_least(40.0))
                .column(Column::remainder().clip(true))
                .column(Column::auto().at_least(50.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::auto().at_least(40.0))
                .column(Column::auto().at_least(80.0).clip(true))
                .header(20.0, |mut h| {
                    for (c, name) in [
                        (Col::Id, "#"),
                        (Col::Payload, "Payload"),
                        (Col::Status, "Status"),
                        (Col::Length, "Length"),
                        (Col::Time, "Time ms"),
                        (Col::Grep, "Grep"),
                        (Col::Extract, "Extract"),
                    ] {
                        h.col(|ui| {
                            if ui.selectable_label(col == c, egui::RichText::new(name).strong()).clicked() {
                                sort_click = Some(c);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(18.0, order.len(), |mut row| {
                        let i = order[row.index()];
                        let r = &self.rows[i];
                        row.set_selected(self.selected == Some(i));
                        let status = if !r.error.is_empty() {
                            "error".to_string()
                        } else if r.done {
                            r.status.to_string()
                        } else {
                            String::new()
                        };
                        let cells = [
                            (i + 1).to_string(),
                            r.payloads.clone(),
                            status,
                            if r.done { len(r).to_string() } else { String::new() },
                            if r.done { r.ms.to_string() } else { String::new() },
                            if r.grep { "✔".into() } else { String::new() },
                            r.extract.clone(),
                        ];
                        for text in cells {
                            row.col(|ui| {
                                ui.add(egui::Label::new(text).truncate().selectable(false));
                            });
                        }
                        let resp = row.response();
                        if resp.clicked() {
                            clicked = Some(i);
                        }
                        resp.context_menu(|ui| {
                            let path = String::from_utf8_lossy(&r.req).split_whitespace().nth(1).unwrap_or("/").to_string();
                            send_menu(ui, env, &format!("{}{path}", self.target.url()), &r.req, r.res.as_deref());
                        });
                    });
                });
            if clicked.is_some() {
                self.selected = clicked;
            }
            if let Some(c) = sort_click {
                self.sort = (c, if self.sort.0 == c { !self.sort.1 } else { true });
            }
            let ui = &mut cols[1];
            match self.selected.and_then(|i| self.rows.get(i)) {
                Some(r) => {
                    let raw = match (&r.res, r.error.is_empty()) {
                        (Some(res), _) => res.clone(),
                        (None, false) => r.error.clone().into_bytes(),
                        (None, true) => r.req.clone(),
                    };
                    message_view(ui, "intruder_msg", &raw, &mut self.view);
                }
                None => {
                    ui.weak("Select a result.");
                }
            }
        });
    }
}

/// First capture group (or whole match) of `pattern` in the response.
fn extract(pattern: &str, raw: &[u8]) -> String {
    let Ok(re) = regex::bytes::Regex::new(pattern) else { return String::new() };
    if pattern.is_empty() {
        return String::new();
    }
    re.captures(raw)
        .and_then(|c| c.get(1).or_else(|| c.get(0)))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// Intruder results as CSV (RFC 4180 quoting) for pasting into a spreadsheet or report.
fn results_csv(rows: &[Row]) -> String {
    fn q(s: &str) -> String {
        if s.contains([',', '"', '\n']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let mut out = String::from("payload,status,length,time_ms,grep,extract,error\n");
    for r in rows {
        let len = r.res.as_ref().map_or(0, |b| b.len());
        out += &format!(
            "{},{},{},{},{},{},{}\n",
            q(&r.payloads),
            r.status,
            len,
            r.ms,
            r.grep,
            q(&r.extract),
            q(&r.error),
        );
    }
    out
}

fn memmem(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn attacks() {
        let t = "a=§1§&b=§2§";
        let one = [s(&["x", "y"])];
        let reqs = |a, sets: &[Vec<String>]| generate(t, a, sets, 0).unwrap().into_iter().map(|r| r.1).collect::<Vec<_>>();
        assert_eq!(reqs(Attack::Sniper, &one), ["a=x&b=2", "a=y&b=2", "a=1&b=x", "a=1&b=y"]);
        assert_eq!(reqs(Attack::BatteringRam, &one), ["a=x&b=x", "a=y&b=y"]);
        let two = [s(&["x", "y"]), s(&["p", "q", "r"])];
        assert_eq!(reqs(Attack::Pitchfork, &two), ["a=x&b=p", "a=y&b=q"]);
        assert_eq!(reqs(Attack::ClusterBomb, &two).len(), 6);
        assert_eq!(reqs(Attack::ClusterBomb, &two)[1], "a=x&b=q");
        assert!(generate("a=§1", Attack::Sniper, &one, 0).is_err());
        assert_eq!(generate("x=§1§", Attack::Null, &[], 3).unwrap().len(), 3);
        assert_eq!(generate("x=§1§", Attack::Null, &[], 3).unwrap()[0].1, "x=1");
        assert_eq!(extract(r"id=(\d+)", b"a id=42 b"), "42");
    }

    #[test]
    fn csv_quotes() {
        let rows = vec![Row {
            payloads: "a,b".into(),
            req: Vec::new(),
            res: Some(vec![0u8; 10]),
            status: 200,
            ms: 12,
            error: String::new(),
            grep: true,
            extract: "x\"y".into(),
            done: true,
        }];
        let csv = results_csv(&rows);
        assert!(csv.lines().next().unwrap().starts_with("payload,status"));
        assert!(csv.contains("\"a,b\",200,10,12,true,\"x\"\"y\","));
    }

    #[test]
    fn auto_marks() {
        let t = "POST /p?a=1&b=2 HTTP/1.1\nCookie: s=abc; t=1\n\nu=me&p=pw";
        assert_eq!(auto_mark(t), "POST /p?a=§1§&b=§2§ HTTP/1.1\nCookie: s=§abc§; t=§1§\n\nu=§me§&p=§pw§");
        assert_eq!(auto_mark("POST / HTTP/1.1\n\n{\"a\": \"b\"}"), "POST / HTTP/1.1\n\n{\"a\": \"§b§\"}");
    }
}
