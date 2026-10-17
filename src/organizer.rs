//! A saved worklist of interesting exchanges, independent of live Proxy history.
use crate::{Env, Viewer, http::{Msg, View}, in_rect, message_view, send_menu, vsplit};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
enum Status { #[default] New, InProgress, Done }
impl Status {
    const ALL: [Self; 3] = [Self::New, Self::InProgress, Self::Done];
    fn label(self) -> &'static str { match self { Self::New => "New", Self::InProgress => "In progress", Self::Done => "Done" } }
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    name: String,
    url: String,
    req: Vec<u8>,
    res: Option<Vec<u8>>,
    tags: String,
    note: String,
    status: Status,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SavedState { items: Vec<Item> }

pub struct Organizer {
    state: SavedState,
    selected: Option<usize>,
    search: String,
    status: Option<Status>,
    scope_only: bool,
    req_view: Viewer,
    res_view: Viewer,
    split: f32,
}
impl Default for Organizer {
    fn default() -> Self {
        Self { state: SavedState::default(), selected: None, search: String::new(), status: None, scope_only: false,
            req_view: Viewer::default(), res_view: Viewer::new(View::Pretty), split: 0.45 }
    }
}
impl Organizer {
    pub fn is_empty(&self) -> bool { self.state.items.is_empty() }
    pub fn saved(&self) -> &SavedState { &self.state }
    pub fn restore(&mut self, state: SavedState) { self.state = state; self.selected = None; }
    pub fn add(&mut self, url: String, req: Vec<u8>, res: Option<Vec<u8>>) {
        let method = Msg::parse(&req).first.split_whitespace().next().unwrap_or("GET").to_string();
        self.state.items.push(Item { name: format!("{method} {url}"), url, req, res, tags: String::new(), note: String::new(), status: Status::New });
        self.selected = Some(self.state.items.len() - 1);
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!("Organizer ({})", self.state.items.len()));
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search names, tags, notes or URLs").desired_width(280.0));
            ui.selectable_value(&mut self.status, None, "All");
            for status in Status::ALL { ui.selectable_value(&mut self.status, Some(status), status.label()); }
            ui.checkbox(&mut self.scope_only, "In-scope only");
        });
        ui.weak("Add interesting requests from any request’s Actions menu. Organizer snapshots and annotations are saved in projects.");
        let scope = crate::rules::current(env.shared);
        let needle = self.search.to_ascii_lowercase();
        let visible: Vec<_> = self.state.items.iter().enumerate().filter(|(_, item)| {
            self.status.is_none_or(|s| s == item.status) && (!self.scope_only || scope.in_scope(&item.url))
                && [&item.name, &item.url, &item.tags, &item.note].iter().any(|s| s.to_ascii_lowercase().contains(&needle))
        }).map(|(i, _)| i).collect();
        let (top, bottom) = vsplit(ui, "organizer_split", &mut self.split);
        let mut selected = None;
        in_rect(ui, top, |ui| {
            TableBuilder::new(ui).id_salt("organizer_items").striped(true).sense(egui::Sense::click())
                .column(Column::auto()).column(Column::remainder().clip(true)).column(Column::remainder().clip(true))
                .column(Column::auto()).column(Column::initial(140.0).clip(true))
                .header(20.0, |mut h| { for name in ["Progress", "Name", "URL", "HTTP", "Tags"] { h.col(|ui| { ui.strong(name); }); } })
                .body(|body| body.rows(20.0, visible.len(), |mut row| {
                    let i = visible[row.index()]; let item = &self.state.items[i];
                    row.set_selected(self.selected == Some(i));
                    let status = item.res.as_ref().map(|r| Msg::parse(r).status().to_string()).unwrap_or_default();
                    for text in [item.status.label(), &item.name, &item.url, &status, &item.tags] {
                        row.col(|ui| { ui.add(egui::Label::new(text).truncate().selectable(false)); });
                    }
                    let response = row.response();
                    if response.clicked() { selected = Some(i); }
                    response.context_menu(|ui| send_menu(ui, env, &item.url, &item.req, item.res.as_deref()));
                }));
        });
        if selected.is_some() { self.selected = selected; }
        let mut remove = None;
        in_rect(ui, bottom, |ui| {
            let Some(i) = self.selected.filter(|&i| i < self.state.items.len()) else { ui.weak("Select an organized exchange."); return; };
            let item = &mut self.state.items[i];
            ui.horizontal_wrapped(|ui| {
                ui.label("Name"); ui.add(egui::TextEdit::singleline(&mut item.name).desired_width(300.0));
                egui::ComboBox::from_id_salt("organizer_progress").selected_text(item.status.label()).show_ui(ui, |ui| {
                    for status in Status::ALL { ui.selectable_value(&mut item.status, status, status.label()); }
                });
                ui.menu_button("Actions", |ui| send_menu(ui, env, &item.url, &item.req, item.res.as_deref()));
                if ui.button("Remove from Organizer").clicked() { remove = Some(i); }
            });
            ui.horizontal(|ui| {
                ui.label("Tags"); ui.add(egui::TextEdit::singleline(&mut item.tags).hint_text("auth, needs retest").desired_width(240.0));
                ui.label("Notes"); ui.add(egui::TextEdit::singleline(&mut item.note).desired_width(f32::INFINITY));
            });
            ui.columns(2, |cols| {
                message_view(&mut cols[0], "organizer_request", &item.req, &mut self.req_view);
                if let Some(raw) = &item.res { message_view(&mut cols[1], "organizer_response", raw, &mut self.res_view); }
            });
        });
        if let Some(i) = remove { self.state.items.remove(i); self.selected = None; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saves_independent_snapshots_and_annotations() {
        let mut organizer = Organizer::default();
        organizer.add("https://example.com/admin".into(), b"GET /admin HTTP/1.1\r\n\r\n".to_vec(), Some(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec()));
        organizer.state.items[0].tags = "auth, retest".into();
        organizer.state.items[0].note = "Check lower-privilege account".into();
        organizer.state.items[0].status = Status::InProgress;
        let serialized = serde_json::to_vec(organizer.saved()).unwrap();
        organizer.restore(serde_json::from_slice(&serialized).unwrap());
        assert!(organizer.state.items[0].note.contains("lower-privilege"));
        assert_eq!(organizer.state.items[0].status.label(), "In progress");
        assert_eq!(Msg::parse(organizer.state.items[0].res.as_ref().unwrap()).status(), 403);
        assert!(organizer.selected.is_none());
    }
}
