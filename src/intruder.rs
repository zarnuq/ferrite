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
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
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

/// Stores the template and payload sets once, constructing requests only as workers need them.
struct AttackPlan {
    parts: Vec<String>,
    attack: Attack,
    sets: Vec<Vec<String>>,
    total: usize,
    cursor: usize,
}

impl AttackPlan {
    fn new(template: &str, attack: Attack, sets: Vec<Vec<String>>, repeat: usize) -> Result<Self, String> {
        let parts: Vec<String> = template.split('§').map(str::to_string).collect();
        if parts.len() % 2 == 0 { return Err("Unbalanced § markers".into()); }
        let n = parts.len() / 2;
        if attack != Attack::Null && n == 0 { return Err("No § positions marked".into()); }
        let len = |i| sets.get(i).map_or(0, Vec::len);
        let count = match attack {
            Attack::Null => Some(repeat),
            Attack::Sniper => n.checked_mul(len(0)),
            Attack::BatteringRam => Some(len(0)),
            Attack::Pitchfork => Some((0..n).map(len).min().unwrap_or(0)),
            Attack::ClusterBomb if (0..n).any(|i| len(i) == 0) => Some(0),
            Attack::ClusterBomb => (0..n).try_fold(1usize, |acc, i| acc.checked_mul(len(i))),
        };
        let total = count.filter(|&count| count <= MAX_REQUESTS)
            .ok_or_else(|| format!("More than {MAX_REQUESTS} requests"))?;
        Ok(Self { parts, attack, sets, total, cursor: 0 })
    }
}

impl Iterator for AttackPlan {
    type Item = (Vec<String>, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == self.total { return None; }
        let k = self.cursor;
        self.cursor += 1;
        let n = self.parts.len() / 2;
        let mut values: Vec<&str> = (0..n).map(|i| self.parts[2 * i + 1].as_str()).collect();
        let payloads = match self.attack {
            Attack::Null => vec![format!("null {}", k + 1)],
            Attack::Sniper => {
                let list = &self.sets[0];
                let payload = &list[k % list.len()];
                values[k / list.len()] = payload;
                vec![payload.clone()]
            }
            Attack::BatteringRam => {
                let payload = &self.sets[0][k];
                values.fill(payload);
                vec![payload.clone()]
            }
            Attack::Pitchfork => {
                for (i, value) in values.iter_mut().enumerate() { *value = &self.sets[i][k]; }
                values.iter().map(|s| s.to_string()).collect()
            }
            Attack::ClusterBomb => {
                let mut index = k;
                for i in (0..n).rev() {
                    values[i] = &self.sets[i][index % self.sets[i].len()];
                    index /= self.sets[i].len();
                }
                values.iter().map(|s| s.to_string()).collect()
            }
        };
        let mut request = String::new();
        for (i, part) in self.parts.iter().enumerate() {
            request.push_str(if i % 2 == 0 { part } else { values[i / 2] });
        }
        Some((payloads, request))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.cursor;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AttackPlan {}

#[cfg(test)]
fn generate(template: &str, attack: Attack, sets: &[Vec<String>], repeat: usize) -> Result<Vec<(Vec<String>, String)>, String> {
    Ok(AttackPlan::new(template, attack, sets.to_vec(), repeat)?.collect())
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

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct SavedDraft {
    target: Target,
    template: String,
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
    filter: String,
    grep_only: bool,
    errors_only: bool,
    use_cookies: bool,
}

#[derive(Serialize, Deserialize)]
struct SavedResults {
    target: Target,
    total: usize,
    rows: Vec<Row>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct SavedState {
    draft: Option<SavedDraft>,
    results: Option<SavedResults>,
}

pub struct Intruder {
    target: Target,
    result_target: Option<Target>,
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
    filter: String,
    grep_only: bool,
    errors_only: bool,
    use_cookies: bool,
    attack_id: u64,
    rows: Vec<Row>,
    done: usize,
    total: usize,
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
            result_target: None,
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
            filter: String::new(),
            grep_only: false,
            errors_only: false,
            use_cookies: false,
            attack_id: 0,
            rows: Vec::new(),
            done: 0,
            total: 0,
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
    fn draft(&self) -> SavedDraft {
        SavedDraft { target: self.target.clone(), template: self.template.clone(), attack: self.attack,
            sets: self.sets.clone(), set: self.set, load_path: self.load_path.clone(), numbers: self.numbers,
            encode: self.encode, prefix: self.prefix.clone(), suffix: self.suffix.clone(), repeat: self.repeat,
            extract: self.extract.clone(), threads: self.threads, delay_ms: self.delay_ms, grep: self.grep.clone(),
            filter: self.filter.clone(), grep_only: self.grep_only, errors_only: self.errors_only, use_cookies: self.use_cookies }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.draft() == Self::default().draft()
    }

    pub fn save_state(&self) -> SavedState {
        SavedState { draft: Some(self.draft()), results: self.result_target.as_ref().map(|target|
            SavedResults { target: target.clone(), total: self.total, rows: self.rows.clone() }) }
    }

    pub fn restore(&mut self, state: SavedState) {
        if let Some(cancel) = &self.cancel { cancel.store(true, Ordering::Relaxed); }
        let attack_id = self.attack_id + 1;
        *self = Self::default();
        self.attack_id = attack_id;
        if let Some(draft) = state.draft {
            self.target = draft.target;
            self.template = draft.template;
            self.attack = draft.attack;
            self.sets = draft.sets;
            self.sets.resize(self.sets.len().max(1), String::new());
            self.set = draft.set.min(self.sets.len() - 1);
            self.load_path = draft.load_path;
            self.numbers = (draft.numbers.0, draft.numbers.1, draft.numbers.2.max(1));
            self.encode = draft.encode;
            self.prefix = draft.prefix;
            self.suffix = draft.suffix;
            self.repeat = draft.repeat.clamp(1, MAX_REQUESTS);
            self.extract = draft.extract;
            self.threads = draft.threads.clamp(1, 200);
            self.delay_ms = draft.delay_ms.min(60_000);
            self.grep = draft.grep;
            self.filter = draft.filter;
            self.grep_only = draft.grep_only;
            self.errors_only = draft.errors_only;
            self.use_cookies = draft.use_cookies;
        }
        if let Some(results) = state.results {
            self.result_target = Some(results.target);
            self.rows = results.rows;
            self.total = results.total.max(self.rows.len());
            for row in &mut self.rows {
                if !row.done {
                    row.done = true;
                    row.error = "Request was unfinished when this project was saved".into();
                }
            }
            self.done = self.rows.len();
            self.message = format!("Restored {} results; attacks are not resumed automatically", self.done);
        }
    }

    pub fn load(&mut self, target: Target, raw: Vec<u8>) {
        self.template = as_http1(&target, &raw);
        self.target = target;
    }

    pub fn on_queued(&mut self, attack: u64, idx: usize, payloads: String, request: Vec<u8>) {
        if attack != self.attack_id || idx != self.rows.len() { return; }
        self.rows.push(Row { payloads, req: request, res: None, status: 0, ms: 0,
            error: String::new(), grep: false, extract: String::new(), done: false });
    }

    pub fn on_result(&mut self, attack: u64, idx: usize, request: Vec<u8>, result: Result<http::Reply, String>) {
        if attack != self.attack_id {
            return;
        }
        let Some(row) = self.rows.get_mut(idx) else { return };
        if row.done { return; }
        row.req = request;
        row.done = true;
        self.done += 1;
        match result {
            Ok(r) => {
                row.status = r.status;
                row.ms = r.elapsed.as_millis();
                row.grep = grep_match(&self.grep, &r.raw);
                row.extract = extract(&self.extract, &r.raw);
                row.res = Some(r.raw);
            }
            Err(e) => row.error = e,
        }
    }

    pub fn on_done(&mut self, attack: u64) {
        if attack == self.attack_id {
            self.cancel = None;
            self.message = format!("Finished: {} sent, {} not sent", self.done, self.total - self.done);
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
        let requests = match AttackPlan::new(&self.template, self.attack, sets, self.repeat) {
            Ok(r) if r.len() == 0 => {
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
        self.total = requests.len();
        self.result_target = Some(self.target.clone());
        self.selected = None;
        self.rows.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (tx, ui, target, upstream) = (env.tx.clone(), env.egui.clone(), self.target.clone(), env.upstream());
        let (attack, threads, delay) = (self.attack_id, self.threads.max(1), self.delay_ms);
        let session = env.session(self.use_cookies);
        env.rt.spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(threads));
            let mut tasks = tokio::task::JoinSet::new();
            let mut requests = requests.enumerate();
            loop {
                while tasks.try_join_next().is_some() {}
                let permit = limit.clone().acquire_owned().await.unwrap();
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let Some((idx, (payloads, text))) = requests.next() else { break; };
                let raw = http::to_wire(&text, true);
                let _ = tx.send(Event::IntruderQueued { attack, idx, payloads: payloads.join(", "), request: raw.clone() });
                ui.request_repaint();
                let (tx, ui, target, upstream) = (tx.clone(), ui.clone(), target.clone(), upstream.clone());
                let session = session.clone();
                tasks.spawn(async move {
                    let (raw, result) = session.send(&target, &raw, &upstream).await;
                    let _ = tx.send(Event::Log(crate::logger::entry("Intruder", &target, &raw, &result)));
                    let _ = tx.send(Event::Intruder { attack, idx, request: raw, result });
                    ui.request_repaint();
                    drop(permit);
                });
                if delay > 0 {
                    // Short sleeps keep Stop responsive during a long configured delay.
                    let until = tokio::time::Instant::now() + Duration::from_millis(delay);
                    while tokio::time::Instant::now() < until && !cancel.load(Ordering::Relaxed) {
                        tokio::time::sleep(until.saturating_duration_since(tokio::time::Instant::now()).min(Duration::from_millis(50))).await;
                    }
                }
            }
            while tasks.join_next().await.is_some() {}
            let _ = tx.send(Event::IntruderDone { attack });
            ui.request_repaint();
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
                    if let Some(c) = &self.cancel {
                        c.store(true, Ordering::Relaxed);
                        self.message = "Stopping; waiting for active requests…".into();
                    }
                }
            } else if ui.button("Start attack").clicked() {
                self.start(env);
            }
            ui.checkbox(&mut self.use_cookies, "Use session cookies");
            if !self.rows.is_empty() {
                ui.label(format!("{}/{} done", self.done, self.total));
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
                    r.grep = r.res.as_ref().is_some_and(|b| grep_match(&self.grep, b));
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
        ui.horizontal_wrapped(|ui| {
            ui.label("Filter results");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(180.0).hint_text("Payload, status, extraction or error"));
            ui.checkbox(&mut self.grep_only, "Grep matches only");
            ui.checkbox(&mut self.errors_only, "Errors only");
            ui.weak("Grep and extraction search headers and decoded bodies.");
        });
        if let Some(target) = &self.result_target {
            ui.weak(format!("Results from {} — {} of {} requests dispatched", target.url(), self.rows.len(), self.total));
        }
        let len = |r: &Row| r.res.as_ref().map_or(0, |b| b.len());
        let needle = self.filter.to_lowercase();
        let mut order: Vec<usize> = (0..self.rows.len()).filter(|&i| {
            let r = &self.rows[i];
            (!self.grep_only || r.grep) && (!self.errors_only || !r.error.is_empty())
                && (needle.is_empty() || format!("{} {} {} {}", r.payloads, r.status, r.extract, r.error).to_lowercase().contains(&needle))
        }).collect();
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
                        } else if self.cancel.is_none() {
                            "not sent".to_string()
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
                            let target = self.result_target.as_ref().unwrap_or(&self.target);
                            send_menu(ui, env, &format!("{}{path}", target.url()), &r.req, r.res.as_deref());
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
    let decoded = analysis_bytes(raw);
    re.captures(&decoded)
        .and_then(|c| c.get(1).or_else(|| c.get(0)))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .unwrap_or_default()
}

fn analysis_bytes(raw: &[u8]) -> Vec<u8> {
    if !raw.starts_with(b"HTTP/") { return raw.to_vec(); }
    let msg = http::Msg::parse(raw);
    let body = msg.decoded_body();
    let mut bytes = msg.first.into_bytes();
    for (name, value) in &msg.headers {
        bytes.extend_from_slice(format!("\r\n{name}: {value}").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes.extend_from_slice(&body);
    bytes
}

fn grep_match(pattern: &str, raw: &[u8]) -> bool {
    !pattern.is_empty() && memmem(&analysis_bytes(raw), pattern.as_bytes())
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

    #[test]
    fn analyzes_decoded_responses() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"Welcome account=alice token=abc123").unwrap();
        let body = encoder.finish().unwrap();
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nX-Result: accepted\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", body.len()).into_bytes();
        raw.extend(body);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        assert!(grep_match("account=alice", &raw));
        assert!(grep_match("X-Result: accepted", &raw));
        assert!(!grep_match("", &raw));
        assert_eq!(extract(r"token=(\w+)", &raw), "abc123");
        assert_eq!(extract("[", &raw), "");
    }

    #[test]
    fn plans_large_attacks_without_expanding_requests() {
        let template = format!("POST / HTTP/1.1\r\n\r\n{}", "x".repeat(1024 * 1024));
        let mut plan = AttackPlan::new(&template, Attack::Null, Vec::new(), MAX_REQUESTS).unwrap();
        assert_eq!(plan.len(), MAX_REQUESTS);
        assert_eq!(plan.parts.len(), 1, "store one template rather than a million request copies");
        assert_eq!(plan.next().unwrap().1, template);
        assert_eq!(plan.len(), MAX_REQUESTS - 1);
        assert!(AttackPlan::new("x", Attack::Null, Vec::new(), MAX_REQUESTS + 1).is_err());
        let template = "§a§§b§";
        let sets = vec![vec![String::new(); 1001]; 2];
        assert!(AttackPlan::new(template, Attack::ClusterBomb, sets, 0).is_err());
        assert_eq!(generate(template, Attack::Pitchfork, &[], 0).unwrap().len(), 0);
        assert_eq!(generate(template, Attack::ClusterBomb, &[vec![], s(&["x"])], 0).unwrap().len(), 0);
    }

    #[test]
    fn projects_restore_drafts_results_and_reject_old_events() {
        let target = Target::from_url("https://app.example/").unwrap();
        let mut intruder = Intruder { target: target.clone(), result_target: Some(target.clone()),
            template: "GET /?id=§1§ HTTP/1.1\r\nHost: app.example\r\n\r\n".into(),
            sets: vec!["alice\nbob".into()], prefix: "user-".into(), use_cookies: true, grep: "accepted".into(),
            extract: "token=(\\w+)".into(), filter: "alice".into(), grep_only: true, total: 3, attack_id: 42, ..Default::default() };
        let request = b"GET /?id=user-alice HTTP/1.1\r\nHost: app.example\r\n\r\n".to_vec();
        intruder.on_queued(42, 0, "user-alice".into(), request.clone());
        intruder.on_result(42, 0, request.clone(), Ok(http::Reply {
            raw: b"HTTP/1.1 200 OK\r\n\r\naccepted token=abc".to_vec(), status: 200, elapsed: Duration::from_millis(12) }));
        intruder.on_queued(42, 1, "user-bob".into(), request.clone());
        // Drafts may target another server while results retain the server actually contacted.
        intruder.load(Target::from_url("https://draft.example/").unwrap(), b"GET /draft HTTP/1.1\r\n\r\n".to_vec());
        let saved: SavedState = serde_json::from_slice(&serde_json::to_vec(&intruder.save_state()).unwrap()).unwrap();
        let old_cancel = Arc::new(AtomicBool::new(false));
        intruder.cancel = Some(old_cancel.clone());
        intruder.restore(saved);
        assert!(old_cancel.load(Ordering::Relaxed));
        assert!(intruder.cancel.is_none());
        assert_eq!(intruder.target.host, "draft.example");
        assert_eq!(intruder.result_target.as_ref().unwrap().host, "app.example");
        assert_eq!(intruder.sets, ["alice\nbob"]);
        assert_eq!(intruder.prefix, "user-");
        assert!(intruder.use_cookies && intruder.grep_only);
        assert_eq!(intruder.filter, "alice");
        assert_eq!(intruder.rows[0].extract, "abc");
        assert!(intruder.rows[0].grep);
        assert_eq!(intruder.rows[0].ms, 12);
        assert_eq!(intruder.rows[1].error, "Request was unfinished when this project was saved");
        intruder.on_result(42, 1, request.clone(), Err("stale response".into()));
        intruder.on_queued(42, 2, "stale payload".into(), request);
        intruder.on_done(42);
        assert_eq!(intruder.rows.len(), 2);
        assert!(!intruder.rows[1].error.contains("stale"));
        assert!(intruder.message.starts_with("Restored"));
        intruder.restore(SavedState::default());
        assert!(intruder.is_empty(), "legacy projects restore a fresh Intruder");
    }

    #[tokio::test]
    async fn stop_waits_for_completion_and_interrupts_delay() {
        use std::sync::{RwLock, mpsc};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port(), tls: false };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0; 1024];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&buf[..n]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntoken=1").await.unwrap();
            raw
        });
        let shared = Arc::new(RwLock::new(Arc::new(crate::rules::Compiled::new(Default::default()))));
        let jar = Arc::default();
        let (tx, rx) = mpsc::channel();
        let mut actions = Vec::new();
        let mut intruder = Intruder { target: target.clone(), template: format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", target.host_header()),
            attack: Attack::Null, repeat: 10, threads: 1, delay_ms: 60_000, grep: "token=1".into(), ..Default::default() };
        intruder.start(&Env { rt: &tokio::runtime::Handle::current(), tx: &tx, egui: &egui::Context::default(),
            shared: &shared, jar: &jar, actions: &mut actions });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        Event::IntruderQueued { attack, idx, payloads, request } => {
                            intruder.on_queued(attack, idx, payloads, request);
                            // Loading a new request must not change actions on this attack's results.
                            intruder.load(Target::from_url("https://other.example/").unwrap(), b"GET /other HTTP/1.1\r\n\r\n".to_vec());
                        }
                        Event::Intruder { attack, idx, request, result } => {
                            intruder.on_result(attack, idx, request, result);
                            assert!(intruder.cancel.is_some());
                            intruder.cancel.as_ref().unwrap().store(true, Ordering::Relaxed);
                        }
                        Event::IntruderDone { attack } => intruder.on_done(attack),
                        _ => {},
                    }
                }
                if intruder.cancel.is_none() { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("Stop must interrupt the configured delay");
        assert_eq!(intruder.done, 1);
        assert!(intruder.rows[0].grep);
        assert!(intruder.message.contains("9 not sent"));
        assert_eq!(intruder.rows.len(), 1, "unsent requests should not be expanded or stored");
        assert_eq!(intruder.result_target.as_ref().unwrap().url(), target.url());
        assert_eq!(intruder.target.host, "other.example");
        assert_eq!(server.await.unwrap(), intruder.rows[0].req);
    }
}
