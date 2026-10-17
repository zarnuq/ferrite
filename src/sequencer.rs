//! Sequencer tab: collects tokens from repeated requests and estimates their randomness.

use crate::{
    Env, Event, editor,
    http::{self, Target},
    repeater::as_http1,
};
use eframe::egui;
use regex::bytes::Regex;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const DEFAULT_PATTERN: &str = r"(?i)set-cookie:\s*[^=]+=([^;\r\n]+)";

pub struct Sequencer {
    target: Target,
    request: String,
    pattern: String,
    samples: usize,
    threads: usize,
    tokens: Vec<String>,
    sent: usize,
    misses: usize,
    run: u64,
    cancel: Option<Arc<AtomicBool>>,
    report: Option<(usize, String)>,
}

impl Default for Sequencer {
    fn default() -> Self {
        Sequencer {
            target: Target { host: "example.com".into(), port: 443, tls: true },
            request: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            pattern: DEFAULT_PATTERN.into(),
            samples: 200,
            threads: 5,
            tokens: Vec::new(),
            sent: 0,
            misses: 0,
            run: 0,
            cancel: None,
            report: None,
        }
    }
}

fn entropy(counts: impl Iterator<Item = usize>, total: usize) -> f64 {
    counts
        .map(|c| c as f64 / total as f64)
        .filter(|&p| p > 0.0)
        .map(|p| -p * p.log2())
        .sum()
}

/// Text report: uniqueness, character set, per-position entropy, bit balance, sequential check.
fn report(tokens: &[String]) -> String {
    let n = tokens.len();
    if n < 2 {
        return "Need at least 2 tokens.".into();
    }
    let unique = tokens.iter().collect::<HashSet<_>>().len();
    let lens: Vec<usize> = tokens.iter().map(|t| t.chars().count()).collect();
    let (min, max) = (*lens.iter().min().unwrap(), *lens.iter().max().unwrap());
    let charset: BTreeSet<char> = tokens.iter().flat_map(|t| t.chars()).collect();
    let chars: Vec<Vec<char>> = tokens.iter().map(|t| t.chars().collect()).collect();

    let mut per_pos = Vec::new();
    for p in 0..max {
        let mut counts: HashMap<char, usize> = HashMap::new();
        let mut total = 0;
        for t in &chars {
            if let Some(&c) = t.get(p) {
                *counts.entry(c).or_default() += 1;
                total += 1;
            }
        }
        per_pos.push(entropy(counts.into_values(), total));
    }
    let bits: f64 = per_pos.iter().sum();
    // With n samples no single position can show more than log2(n) bits.
    let ceiling = (n as f64).log2();
    let low: Vec<usize> = per_pos.iter().enumerate().filter(|(_, h)| **h < 0.5).map(|(i, _)| i).collect();

    let index: HashMap<char, usize> = charset.iter().enumerate().map(|(i, &c)| (c, i)).collect();
    let width = (charset.len().max(2) as f64).log2().ceil() as usize;
    let (mut ones, mut total_bits) = (0usize, 0usize);
    for t in &chars {
        for c in t {
            ones += index[c].count_ones() as usize;
            total_bits += width;
        }
    }
    let ratio = ones as f64 / total_bits.max(1) as f64;

    let nums: Option<Vec<i128>> = tokens.iter().map(|t| t.parse().ok()).collect();
    let sequential = nums.is_some_and(|v| {
        let d: HashSet<i128> = v.windows(2).map(|w| w[1] - w[0]).collect();
        d.len() <= 2
    });

    let verdict = if sequential || unique < n {
        "POOR: tokens repeat or follow a sequence."
    } else if bits >= 100.0 {
        "GOOD: high per-position entropy."
    } else if bits >= 64.0 {
        "REASONABLE: moderate entropy."
    } else {
        "POOR: low entropy, tokens may be predictable."
    };
    let mut out = format!(
        "Samples: {n}\nUnique: {unique}{}\nLength: {min}..{max} chars\nCharacter set ({} chars): {}\n\n\
         Estimated entropy: {bits:.1} bits (sum of per-position Shannon entropy)\n\
         Per-position ceiling with {n} samples: {ceiling:.1} bits\n\
         Bit balance: {:.1}% ones (ideal 50%)\n",
        if unique < n { "  ← DUPLICATES" } else { "" },
        charset.len(),
        charset.iter().collect::<String>(),
        ratio * 100.0,
    );
    if !low.is_empty() {
        out += &format!("Near-constant positions (<0.5 bits): {low:?}\n");
    }
    if sequential {
        out += "Tokens are numeric and sequential.\n";
    }
    out += &format!("\nVerdict: {verdict}\n\nPer-position entropy (bits):\n");
    for (i, h) in per_pos.iter().enumerate() {
        out += &format!("{i:>4}  {h:5.2}  {}\n", "#".repeat((h * 4.0).round() as usize));
    }
    out
}

impl Sequencer {
    pub fn load(&mut self, target: Target, raw: Vec<u8>) {
        self.request = as_http1(&target, &raw);
        self.target = target;
    }

    pub fn on_result(&mut self, run: u64, result: Result<http::Reply, String>) {
        if run != self.run {
            return;
        }
        let token = result.ok().and_then(|r| {
            let re = Regex::new(&self.pattern).ok()?;
            let c = re.captures(&r.raw)?;
            let m = c.get(1).or_else(|| c.get(0))?;
            Some(String::from_utf8_lossy(m.as_bytes()).into_owned())
        });
        match token {
            Some(t) => self.tokens.push(t),
            None => self.misses += 1,
        }
        if self.tokens.len() + self.misses >= self.sent {
            self.cancel = None;
        }
    }

    fn start(&mut self, env: &Env) {
        self.run += 1;
        self.tokens.clear();
        self.misses = 0;
        self.sent = self.samples;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let raw = http::to_wire(&self.request, true);
        let (tx, ui, target, upstream) = (env.tx.clone(), env.egui.clone(), self.target.clone(), env.upstream());
        let (run, samples, threads) = (self.run, self.samples, self.threads.max(1));
        env.rt.spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(threads));
            for _ in 0..samples {
                let permit = limit.clone().acquire_owned().await.unwrap();
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let (tx, ui, target, upstream, raw) = (tx.clone(), ui.clone(), target.clone(), upstream.clone(), raw.clone());
                tokio::spawn(async move {
                    let result = http::send(&target, &raw, &upstream).await;
                    let _ = tx.send(Event::Log(crate::logger::entry("Sequencer", &target, &raw, &result)));
                    let _ = tx.send(Event::Sequencer { run, result });
                    ui.request_repaint();
                    drop(permit);
                });
            }
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.label("Target");
            ui.add(egui::TextEdit::singleline(&mut self.target.host).desired_width(200.0));
            ui.add(egui::DragValue::new(&mut self.target.port).range(1..=65535));
            ui.checkbox(&mut self.target.tls, "HTTPS");
            ui.separator();
            ui.label("Samples");
            ui.add(egui::DragValue::new(&mut self.samples).range(2..=100_000));
            ui.label("Threads");
            ui.add(egui::DragValue::new(&mut self.threads).range(1..=50));
            if self.cancel.is_some() {
                if ui.button("Stop").clicked() {
                    if let Some(c) = self.cancel.take() {
                        c.store(true, Ordering::Relaxed);
                    }
                }
            } else if ui.button("Start live capture").clicked() {
                self.start(env);
            }
            ui.label(format!("{} tokens, {} misses", self.tokens.len(), self.misses));
            if ui.button("Copy tokens").clicked() {
                ui.ctx().copy_text(self.tokens.join("\n"));
            }
        });
        ui.horizontal(|ui| {
            ui.label("Token regex (group 1)");
            let valid = Regex::new(&self.pattern).is_ok();
            let mut edit = egui::TextEdit::singleline(&mut self.pattern).desired_width(500.0).font(egui::TextStyle::Monospace);
            if !valid {
                edit = edit.text_color(egui::Color32::LIGHT_RED);
            }
            ui.add(edit);
            if ui.small_button("Reset").clicked() {
                self.pattern = DEFAULT_PATTERN.into();
            }
        });
        ui.separator();
        if self.report.as_ref().is_none_or(|(n, _)| *n != self.tokens.len()) {
            self.report = Some((self.tokens.len(), report(&self.tokens)));
        }
        ui.columns(2, |cols| {
            cols[0].strong("Request");
            editor(&mut cols[0], "seq_req", &mut self.request);
            cols[1].strong("Analysis");
            egui::ScrollArea::both().id_salt("seq_report").auto_shrink(false).show(&mut cols[1], |ui| {
                ui.monospace(&self.report.as_ref().unwrap().1);
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_tokens() {
        let seq: Vec<String> = (1000..1100).map(|i| i.to_string()).collect();
        assert!(report(&seq).contains("sequential"));
        // xorshift: stand-in for random tokens.
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let random: Vec<String> = (0..500)
            .map(|_| {
                (0..4)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        format!("{x:016x}")
                    })
                    .collect()
            })
            .collect();
        let r = report(&random);
        assert!(r.contains("GOOD"), "{r}");
        assert!(report(&["a".into(), "a".into()]).contains("DUPLICATES"));
    }
}
