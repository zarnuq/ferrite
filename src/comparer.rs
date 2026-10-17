//! Comparer tab: diff any two collected items by lines or words.

use eframe::egui::{self, Color32, TextFormat, text::LayoutJob};
use similar::{ChangeTag, TextDiff};

#[derive(Default)]
pub struct Comparer {
    items: Vec<(String, String)>,
    a: usize,
    b: usize,
    words: bool,
    paste: String,
    cache: Option<((usize, usize, bool), LayoutJob, String)>,
}

impl Comparer {
    pub fn add(&mut self, label: String, data: Vec<u8>) {
        self.items.push((label, String::from_utf8_lossy(&data).into_owned()));
        // New item becomes B, previous B becomes A, so two sends compare directly.
        self.a = self.b;
        self.b = self.items.len() - 1;
        self.cache = None;
    }

    fn diff(&self, ui: &egui::Ui) -> (LayoutJob, String) {
        let (a, b) = (&self.items[self.a].1, &self.items[self.b].1);
        let diff = if self.words { TextDiff::from_words(a, b) } else { TextDiff::from_lines(a, b) };
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let text_color = ui.visuals().text_color();
        let mut job = LayoutJob::default();
        let (mut added, mut removed) = (0, 0);
        for change in diff.iter_all_changes() {
            let (bg, prefix) = match change.tag() {
                ChangeTag::Equal => (Color32::TRANSPARENT, if self.words { "" } else { "  " }),
                ChangeTag::Delete => {
                    removed += 1;
                    (Color32::from_rgb(110, 30, 30), if self.words { "" } else { "- " })
                }
                ChangeTag::Insert => {
                    added += 1;
                    (Color32::from_rgb(30, 90, 40), if self.words { "" } else { "+ " })
                }
            };
            let fmt = TextFormat { font_id: font.clone(), color: text_color, background: bg, ..Default::default() };
            job.append(&format!("{prefix}{}", change.to_string_lossy()), 0.0, fmt);
        }
        let unit = if self.words { "words" } else { "lines" };
        (job, format!("{removed} {unit} removed, {added} added · A {} bytes, B {} bytes", a.len(), b.len()))
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        ui.horizontal(|ui| {
            for (which, label) in [(0, "A"), (1, "B")] {
                let idx = if which == 0 { &mut self.a } else { &mut self.b };
                let text = self.items.get(*idx).map_or("—".to_string(), |i| format!("{}: {}", *idx + 1, i.0));
                egui::ComboBox::from_label(label).width(350.0).selected_text(text).show_ui(ui, |ui| {
                    for (i, item) in self.items.iter().enumerate() {
                        changed |= ui.selectable_value(idx, i, format!("{}: {}", i + 1, item.0)).changed();
                    }
                });
            }
            changed |= ui.radio_value(&mut self.words, false, "Lines").changed();
            changed |= ui.radio_value(&mut self.words, true, "Words").changed();
            if ui.button("Swap A/B").clicked() {
                std::mem::swap(&mut self.a, &mut self.b);
                self.cache = None;
            }
            if ui.button("Clear").clicked() {
                *self = Comparer::default();
            }
        });
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.paste).hint_text("Paste text to add as an item").desired_width(400.0));
            if ui.button("Add").clicked() && !self.paste.is_empty() {
                let text = std::mem::take(&mut self.paste);
                self.add("pasted".into(), text.into_bytes());
            }
        });
        ui.separator();
        if self.items.len() < 2 {
            ui.weak("Send two requests or responses here (right-click → Send to Comparer), or paste text.");
            return;
        }
        if changed {
            self.cache = None;
        }
        let key = (self.a, self.b, self.words);
        if self.cache.as_ref().is_none_or(|c| c.0 != key) {
            let (job, summary) = self.diff(ui);
            self.cache = Some((key, job, summary));
        }
        let (_, job, summary) = self.cache.as_ref().unwrap();
        ui.label(summary);
        egui::ScrollArea::both().auto_shrink(false).show(ui, |ui| {
            ui.label(job.clone());
        });
    }
}
