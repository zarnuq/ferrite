//! Settings tab: target scope, match & replace rules and upstream proxy.

use crate::{
    http::Upstream,
    proxy::config_dir,
    rules::{self, Config, Part, Rule},
};
use eframe::egui::{self, Color32};

fn pattern_box(ui: &mut egui::Ui, text: &mut String, regex: bool, width: f32) {
    let valid = text.is_empty() || rules::compile(text, regex).is_some();
    let mut edit = egui::TextEdit::singleline(text).desired_width(width).font(egui::TextStyle::Monospace);
    if !valid {
        edit = edit.text_color(Color32::LIGHT_RED);
    }
    ui.add(edit);
}

fn list_ui(ui: &mut egui::Ui, id: &str, list: &mut Vec<String>) {
    let mut remove = None;
    for (i, item) in list.iter_mut().enumerate() {
        ui.push_id((id, i), |ui| {
            ui.horizontal(|ui| {
                pattern_box(ui, item, true, 420.0);
                if ui.small_button("✖").clicked() {
                    remove = Some(i);
                }
            });
        });
    }
    if let Some(i) = remove {
        list.remove(i);
    }
    if ui.button("Add").clicked() {
        list.push(String::new());
    }
}

pub fn ui(ui: &mut egui::Ui, cfg: &mut Config) {
    egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        ui.heading("Appearance");
        ui.horizontal(|ui| {
            ui.label("Theme");
            ui.selectable_value(&mut cfg.theme, crate::rules::Theme::System, "System");
            ui.selectable_value(&mut cfg.theme, crate::rules::Theme::Dark, "Dark");
            ui.selectable_value(&mut cfg.theme, crate::rules::Theme::Light, "Light");
        });
        ui.add_space(12.0);

        ui.heading("Proxy");
        ui.label(format!(
            "CA certificate: {}  — import it into your browser as a trusted authority.",
            config_dir().join("ca.pem").display()
        ));
        ui.label("Listen address is set on the command line: ferrite 127.0.0.1:8080");
        ui.horizontal(|ui| {
            if ui.button("Copy CA path").clicked() {
                ui.ctx().copy_text(config_dir().join("ca.pem").to_string_lossy().into_owned());
            }
            if ui.button("Copy config dir").clicked() {
                ui.ctx().copy_text(config_dir().to_string_lossy().into_owned());
            }
        });
        ui.add_space(12.0);

        ui.heading("Target scope");
        ui.label("Regexes matched against the full URL. No include rules means everything is in scope.");
        ui.strong("Include");
        list_ui(ui, "include", &mut cfg.include);
        ui.strong("Exclude");
        list_ui(ui, "exclude", &mut cfg.exclude);
        ui.checkbox(&mut cfg.record_scope_only, "Record in-scope traffic only (still proxies everything)");
        ui.add_space(12.0);

        ui.heading("TLS pass-through");
        ui.label("Host regexes tunnelled without interception (e.g. pinned apps or noisy telemetry).");
        list_ui(ui, "passthrough", &mut cfg.passthrough);
        ui.add_space(12.0);

        ui.heading("Response modification");
        ui.checkbox(&mut cfg.mods.unhide_hidden, "Unhide hidden form fields");
        ui.checkbox(&mut cfg.mods.enable_disabled, "Enable disabled form fields");
        ui.checkbox(&mut cfg.mods.remove_maxlength, "Remove input field length limits");
        ui.checkbox(&mut cfg.mods.remove_js_validation, "Remove JavaScript and HTML5 form validation");
        ui.checkbox(&mut cfg.mods.strip_secure, "Remove Secure flag from cookies");
        ui.add_space(12.0);

        ui.heading("Match and replace");
        ui.label("Applied to proxied traffic. Header rules match whole \"Name: value\" lines; an empty match adds the replacement as a new header.");
        let mut remove = None;
        egui::Grid::new("rules").striped(true).num_columns(6).show(ui, |ui| {
            for name in ["On", "Item", "Match", "Replace", "Regex", ""] {
                ui.strong(name);
            }
            ui.end_row();
            for (i, r) in cfg.rules.iter_mut().enumerate() {
                ui.checkbox(&mut r.enabled, "");
                egui::ComboBox::from_id_salt(("part", i)).selected_text(r.part.label()).show_ui(ui, |ui| {
                    for p in Part::ALL {
                        ui.selectable_value(&mut r.part, p, p.label());
                    }
                });
                pattern_box(ui, &mut r.find, r.regex, 280.0);
                ui.add(egui::TextEdit::singleline(&mut r.replace).desired_width(280.0).font(egui::TextStyle::Monospace));
                ui.checkbox(&mut r.regex, "");
                if ui.small_button("✖").clicked() {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
        if let Some(i) = remove {
            cfg.rules.remove(i);
        }
        if ui.button("Add rule").clicked() {
            cfg.rules.push(Rule {
                enabled: true,
                part: Part::RequestHeader,
                find: "^User-Agent: .*$".into(),
                replace: "User-Agent: ferrite".into(),
                regex: true,
            });
        }
        ui.add_space(12.0);

        ui.heading("Upstream proxy");
        ui.label("Outbound traffic from the proxy, Repeater and Intruder goes through this.");
        let (mut kind, mut addr) = match &cfg.upstream {
            Upstream::None => (0, String::new()),
            Upstream::Http(a) => (1, a.clone()),
            Upstream::Socks5(a) => (2, a.clone()),
        };
        ui.horizontal(|ui| {
            ui.radio_value(&mut kind, 0, "None");
            ui.radio_value(&mut kind, 1, "HTTP");
            ui.radio_value(&mut kind, 2, "SOCKS5");
            ui.add_enabled(
                kind != 0,
                egui::TextEdit::singleline(&mut addr).hint_text("127.0.0.1:8081").desired_width(200.0),
            );
        });
        cfg.upstream = match kind {
            1 => Upstream::Http(addr),
            2 => Upstream::Socks5(addr),
            _ => Upstream::None,
        };
    });
}
