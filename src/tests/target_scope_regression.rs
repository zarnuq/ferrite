use super::*;
use std::sync::{Arc, Mutex, RwLock, mpsc};

fn frame(
    ctx: &egui::Context,
    tab: &mut TargetTab,
    history: &History,
    shared: &rules::Shared,
    actions: &mut Vec<crate::Action>,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    let (tx, _rx) = mpsc::channel();
    let jar = Arc::new(Mutex::new(crate::session::Jar::default()));
    let rt = tokio::runtime::Handle::current();
    let mut env = Env {
        listen_addr: "127.0.0.1:8080".parse().unwrap(),
        rt: &rt,
        tx: &tx,
        egui: ctx,
        shared,
        jar: &jar,
        actions,
    };
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            )),
            events,
            ..Default::default()
        },
        |ui| {
            egui::CentralPanel::default().show(ui, |ui| tab.ui(ui, history, &mut env));
        },
    );
    // Headless tests intentionally do not upload font textures to a renderer.
    output.textures_delta.clear();
    output
}
fn history() -> History {
    let mut history = History::default();
    for (id, url) in [
        (1, "http://one.test/allowed"),
        (2, "http://one.test/hidden"),
        (3, "http://two.test/"),
    ] {
        let path = crate::http::url_path(url);
        history.on_request(
            id,
            url.into(),
            format!("GET {path} HTTP/1.1\r\n\r\n").into_bytes(),
        );
    }
    history
}
fn shared(include: Vec<String>) -> rules::Shared {
    Arc::new(RwLock::new(Arc::new(rules::Compiled::new(rules::Config {
        include,
        ..Default::default()
    }))))
}

#[tokio::test]
async fn scope_changes_refresh_site_map_without_new_traffic() {
    let ctx = egui::Context::default();
    let history = history();
    let mut tab = TargetTab {
        scope_only: true,
        ..Default::default()
    };
    let shared = shared(vec![r"^http://one\.test/".into()]);
    let mut actions = Vec::new();
    frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    assert!(
        tab.tree
            .as_ref()
            .unwrap()
            .2
            .children
            .contains_key("http://one.test")
    );
    assert!(
        !tab.tree
            .as_ref()
            .unwrap()
            .2
            .children
            .contains_key("http://two.test")
    );
    *shared.write().unwrap() = Arc::new(rules::Compiled::new(rules::Config {
        include: vec![r"^http://two\.test/".into()],
        ..Default::default()
    }));
    frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    assert!(
        !tab.tree
            .as_ref()
            .unwrap()
            .2
            .children
            .contains_key("http://one.test")
    );
    assert!(
        tab.tree
            .as_ref()
            .unwrap()
            .2
            .children
            .contains_key("http://two.test")
    );
}

#[tokio::test]
async fn selected_host_table_filters_excluded_paths_and_refreshes_on_toggle() {
    let ctx = egui::Context::default();
    let history = history();
    let mut tab = TargetTab {
        scope_only: true,
        node: vec!["http://one.test".into()],
        ..Default::default()
    };
    let shared = shared(vec![r"^http://one\.test/allowed$".into()]);
    let mut actions = Vec::new();
    frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    assert_eq!(tab.node_flows.as_ref().unwrap().2, vec![0]);
    tab.scope_only = false;
    frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    assert_eq!(tab.node_flows.as_ref().unwrap().2, vec![0, 1]);
}

fn text_position(output: &egui::FullOutput, label: &str) -> Option<egui::Pos2> {
    fn find(shape: &egui::epaint::Shape, label: &str) -> Option<egui::Pos2> {
        match shape {
            egui::epaint::Shape::Text(text) if text.galley.job.text == label => {
                Some(text.galley.rect.translate(text.pos.to_vec2()).center())
            }
            egui::epaint::Shape::Vec(shapes) => shapes.iter().find_map(|s| find(s, label)),
            _ => None,
        }
    }
    output
        .shapes
        .iter()
        .find_map(|shape| find(&shape.shape, label))
}
fn click(position: egui::Pos2, button: egui::PointerButton) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(position),
        egui::Event::PointerButton {
            pos: position,
            button,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
        egui::Event::PointerButton {
            pos: position,
            button,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        },
    ]
}

#[tokio::test]
async fn right_click_site_map_host_emits_scope_action_for_that_host() {
    let ctx = egui::Context::default();
    let history = history();
    let mut tab = TargetTab::default();
    let shared = shared(vec![]);
    let mut actions = Vec::new();
    let output = frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    let host = text_position(&output, "http://one.test").expect("host label was not drawn");
    frame(
        &ctx,
        &mut tab,
        &history,
        &shared,
        &mut actions,
        click(host, egui::PointerButton::Secondary),
    );
    let output = frame(&ctx, &mut tab, &history, &shared, &mut actions, vec![]);
    let item =
        text_position(&output, "Add host to scope").expect("right-click scope menu was not drawn");
    frame(
        &ctx,
        &mut tab,
        &history,
        &shared,
        &mut actions,
        click(item, egui::PointerButton::Primary),
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a,crate::Action::AddScope(origin)if origin=="http://one.test"))
    );
}
