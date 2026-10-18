//! Target tab: site map built from history, and passive scanner issues.

use crate::{
    Env, Viewer, hsplit,
    history::History,
    http::{Target, View},
    in_rect, message_view, rules, send_menu, vsplit,
};
use eframe::egui::{self, collapsing_header::CollapsingState};
use egui_extras::{Column, TableBuilder};
use std::collections::BTreeMap;

#[derive(Default)]
struct Node {
    children: BTreeMap<String, Node>,
}

/// Site map key path for a flow: origin, then path segments; the last keeps its query.
fn key_path(url: &str, path: &str) -> Option<Vec<String>> {
    let origin = Target::from_url(url)?.url();
    let mut out = vec![origin];
    let (p, q) = path.split_once('?').map_or((path, None), |(p, q)| (p, Some(q)));
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    for (i, s) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        out.push(match (last, q) {
            (true, Some(q)) => format!("{s}?{q}"),
            _ => s.to_string(),
        });
    }
    if segs.is_empty() {
        out.push(q.map_or("/".to_string(), |q| format!("/?{q}")));
    }
    Some(out)
}

pub struct TargetTab {
    show_issues: bool,
    scope_only: bool,
    scope: Option<std::sync::Arc<rules::Compiled>>,
    tree: Option<(u64, bool, Node)>,
    node: Vec<String>,
    node_flows: Option<(u64, Vec<String>, Vec<usize>)>,
    flow: Option<u64>,
    issue: Option<usize>,
    req_view: Viewer,
    res_view: Viewer,
    hsplit: f32,
    vsplit: f32,
}

impl Default for TargetTab {
    fn default() -> Self {
        TargetTab {
            show_issues: false,
            scope_only: false,
            scope: None,
            tree: None,
            node: Vec::new(),
            node_flows: None,
            flow: None,
            issue: None,
            req_view: Viewer::new(View::Raw),
            res_view: Viewer::new(View::Pretty),
            hsplit: 0.3,
            vsplit: 0.45,
        }
    }
}

fn show_node(
    ui: &mut egui::Ui,
    name: &str,
    node: &Node,
    path: &mut Vec<String>,
    selected: &[String],
    clicked: &mut Option<Vec<String>>,
    env: &mut Env,
) {
    path.push(name.to_string());
    let is_selected = selected == path.as_slice();
    if node.children.is_empty() {
        let response = ui.selectable_label(is_selected, name);
        if response.clicked() || response.secondary_clicked() {
            *clicked = Some(path.clone());
        }
        response.context_menu(|ui| host_scope_menu(ui, env, &path[0]));
    } else {
        let id = ui.make_persistent_id(path.join("\u{0}"));
        CollapsingState::load_with_default_open(ui.ctx(), id, false)
            .show_header(ui, |ui| {
                let response = ui.selectable_label(is_selected, name);
                if response.clicked() || response.secondary_clicked() {
                    *clicked = Some(path.clone());
                }
                response.context_menu(|ui| host_scope_menu(ui, env, &path[0]));
            })
            .body(|ui| {
                for (k, child) in &node.children {
                    show_node(ui, k, child, path, selected, clicked, env);
                }
            });
    }
    path.pop();
}

fn host_scope_menu(ui: &mut egui::Ui, env: &mut Env, origin: &str) {
    if ui.button("Add host to scope").clicked() {
        env.actions.push(crate::Action::AddScope(origin.to_string()));
        ui.close();
    }
    if ui.button("Copy origin").clicked() {
        ui.ctx().copy_text(origin.to_string());
        ui.close();
    }
}

impl TargetTab {
    pub fn ui(&mut self, ui: &mut egui::Ui, history: &History, env: &mut Env) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.show_issues, false, "Site map");
            ui.selectable_value(&mut self.show_issues, true, format!("Issues ({})", history.issues.len()));
            if !self.show_issues {
                ui.separator();
                ui.checkbox(&mut self.scope_only, "In-scope only");
            }
        });
        let (left, right) = hsplit(ui, "target_h", &mut self.hsplit);
        if self.show_issues {
            in_rect(ui, left, |ui| self.issues_list(ui, history));
            in_rect(ui, right, |ui| match self.issue.and_then(|i| history.issues.get(i)) {
                Some(issue) => {
                    ui.heading(format!("{} · {}", issue.title, issue.severity.label()));
                    ui.label(&issue.detail);
                    ui.separator();
                    self.pair_view(ui, env, &issue.url, &issue.req, Some(&issue.res));
                }
                None => {
                    ui.weak("Select an issue.");
                }
            });
            return;
        }

        let scope = rules::current(env.shared);
        if self.tree.as_ref().is_none_or(|(g, s, _)| *g != history.generation || *s != self.scope_only)
            || self.scope.as_ref().is_none_or(|old| !std::sync::Arc::ptr_eq(old, &scope))
        {
            let mut root = Node::default();
            for f in &history.flows {
                if self.scope_only && !scope.in_scope(&f.url) {
                    continue;
                }
                if let Some(keys) = key_path(&f.url, &f.path) {
                    let mut n = &mut root;
                    for k in keys {
                        n = n.children.entry(k).or_default();
                    }
                }
            }
            self.tree = Some((history.generation, self.scope_only, root));
            self.scope = Some(scope.clone());
            self.node_flows = None;
        }

        let mut clicked = None;
        in_rect(ui, left, |ui| {
            egui::ScrollArea::both().id_salt("sitemap").auto_shrink(false).show(ui, |ui| {
                let root = &self.tree.as_ref().unwrap().2;
                if root.children.is_empty() {
                    ui.weak("No traffic yet.");
                }
                let mut path = Vec::new();
                for (k, child) in &root.children {
                    show_node(ui, k, child, &mut path, &self.node, &mut clicked, env);
                }
            });
        });
        if let Some(c) = clicked {
            self.node = c;
            self.flow = None;
        }

        // Flows under the selected node, cached per history generation.
        if self.node_flows.as_ref().is_none_or(|(g, n, _)| *g != history.generation || *n != self.node) {
            let list = history
                .flows
                .iter()
                .enumerate()
                .filter(|(_, f)| (!self.scope_only || scope.in_scope(&f.url))
                    && key_path(&f.url, &f.path).is_some_and(|k| !self.node.is_empty() && k.starts_with(&self.node)))
                .map(|(i, _)| i)
                .collect();
            self.node_flows = Some((history.generation, self.node.clone(), list));
        }
        in_rect(ui, right, |ui| {
            let (top, bottom) = vsplit(ui, "target_v", &mut self.vsplit);
            let list = &self.node_flows.as_ref().unwrap().2;
            let mut pick = None;
            in_rect(ui, top, |ui| {
                TableBuilder::new(ui)
                    .id_salt("target_flows")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .column(Column::auto().at_least(40.0))
                    .column(Column::auto().at_least(60.0))
                    .column(Column::remainder().clip(true))
                    .column(Column::auto().at_least(50.0))
                    .column(Column::auto().at_least(60.0))
                    .header(20.0, |mut h| {
                        for name in ["#", "Method", "URL", "Status", "Length"] {
                            h.col(|ui| {
                                ui.strong(name);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(18.0, list.len(), |mut row| {
                            let f = &history.flows[list[row.index()]];
                            row.set_selected(self.flow == Some(f.id));
                            let cells = [
                                f.id.to_string(),
                                f.method.clone(),
                                f.url.clone(),
                                if f.status == 0 { String::new() } else { f.status.to_string() },
                                f.res.as_ref().map_or(String::new(), |r| r.len().to_string()),
                            ];
                            for text in cells {
                                row.col(|ui| {
                                    ui.add(egui::Label::new(text).truncate().selectable(false));
                                });
                            }
                            let resp = row.response();
                            if resp.clicked() {
                                pick = Some(f.id);
                            }
                            resp.context_menu(|ui| send_menu(ui, env, &f.url, &f.req, f.res.as_deref()));
                        });
                    });
            });
            if pick.is_some() {
                self.flow = pick;
            }
            in_rect(ui, bottom, |ui| self.flow_detail(ui, history, self.flow, env));
        });
    }

    fn issues_list(&mut self, ui: &mut egui::Ui, history: &History) {
        let mut order: Vec<usize> = (0..history.issues.len()).collect();
        order.sort_by(|&a, &b| history.issues[b].severity.cmp(&history.issues[a].severity).then(a.cmp(&b)));
        let mut pick = None;
        TableBuilder::new(ui)
            .id_salt("issues")
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::auto().at_least(60.0))
            .column(Column::initial(260.0).clip(true).resizable(true))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for name in ["Severity", "Issue", "Host"] {
                    h.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, order.len(), |mut row| {
                    let i = order[row.index()];
                    let issue = &history.issues[i];
                    row.set_selected(self.issue == Some(i));
                    row.col(|ui| {
                        let color = match issue.severity {
                            crate::scanner::Severity::High => egui::Color32::from_rgb(230, 80, 80),
                            crate::scanner::Severity::Medium => egui::Color32::from_rgb(230, 150, 60),
                            crate::scanner::Severity::Low => egui::Color32::from_rgb(220, 200, 90),
                            crate::scanner::Severity::Info => ui.visuals().weak_text_color(),
                        };
                        ui.add(egui::Label::new(egui::RichText::new(issue.severity.label()).color(color)).selectable(false));
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(issue.title).truncate().selectable(false));
                    });
                    row.col(|ui| {
                        let host = Target::from_url(&issue.url).map(|t| t.host_header()).unwrap_or_default();
                        ui.add(egui::Label::new(host).truncate().selectable(false));
                    });
                    if row.response().clicked() {
                        pick = Some(i);
                    }
                    row.response().on_hover_text(&issue.url);
                });
            });
        if pick.is_some() {
            self.issue = pick;
        }
    }

    fn flow_detail(&mut self, ui: &mut egui::Ui, history: &History, flow: Option<u64>, env: &mut Env) {
        match flow.and_then(|id| history.flow(id)) {
            Some(f) => self.pair_view(ui, env, &f.url, &f.req, f.res.as_deref()),
            None => {
                ui.weak("Select an item.");
            }
        }
    }

    fn pair_view(&mut self, ui: &mut egui::Ui, env: &mut Env, url: &str, req: &[u8], res: Option<&[u8]>) {
        ui.horizontal(|ui| {
            ui.strong(url);
            ui.menu_button("Actions", |ui| send_menu(ui, env, url, req, res));
        });
        ui.columns(2, |cols| {
            message_view(&mut cols[0], "target_req", req, &mut self.req_view);
            match res {
                Some(r) => message_view(&mut cols[1], "target_res", r, &mut self.res_view),
                None => {
                    cols[1].weak("No response.");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_paths() {
        assert_eq!(key_path("https://a.com/x/y?z=1", "/x/y?z=1").unwrap(), ["https://a.com", "x", "y?z=1"]);
        assert_eq!(key_path("http://a.com:8080/", "/").unwrap(), ["http://a.com:8080", "/"]);
        assert_eq!(key_path("https://a.com/?q", "/?q").unwrap(), ["https://a.com", "/?q"]);
    }
}

#[cfg(test)]
#[path = "tests/target_scope_regression.rs"]
mod robust_scope_tests;
