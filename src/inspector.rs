//! Editable, decoded request parameters for Repeater. Changes are explicit and local:
//! untouched parameter groups retain their original wire representation.
use crate::http::Msg;
use eframe::egui;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind { Query, Form, Cookie }

impl Kind {
    const ALL: [Self; 3] = [Self::Query, Self::Form, Self::Cookie];
    fn label(self) -> &'static str { match self { Self::Query => "Query", Self::Form => "Form", Self::Cookie => "Cookie" } }
}

#[derive(Clone, Debug, PartialEq)]
struct Param { kind: Kind, name: String, value: String }

fn params(request: &str) -> Vec<Param> {
    let msg = Msg::parse(request.as_bytes());
    let mut out = Vec::new();
    let path = msg.first.split_whitespace().nth(1).unwrap_or("/");
    if let Some((_, query)) = path.split_once('?') {
        out.extend(crate::http::form_pairs(query).into_iter().map(|(name, value)| Param { kind: Kind::Query, name, value }));
    }
    if msg.header("content-type").is_some_and(|h| h.to_ascii_lowercase().contains("application/x-www-form-urlencoded")) {
        out.extend(crate::http::form_pairs(&String::from_utf8_lossy(&msg.decoded_body())).into_iter().map(|(name, value)| Param { kind: Kind::Form, name, value }));
    }
    for (_, value) in msg.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("cookie")) {
        out.extend(value.split(';').filter_map(|s| s.trim().split_once('=')).map(|(name, value)| Param { kind: Kind::Cookie, name: name.into(), value: value.into() }));
    }
    out
}

fn rewrite(request: &str, edited: &[Param], json: Option<&str>) -> Result<String, String> {
    let original = params(request);
    let mut msg = Msg::parse(request.as_bytes());
    for kind in Kind::ALL {
        let before: Vec<_> = original.iter().filter(|p| p.kind == kind).collect();
        let after: Vec<_> = edited.iter().filter(|p| p.kind == kind).collect();
        if before == after { continue; }
        let encoded = || url::form_urlencoded::Serializer::new(String::new()).extend_pairs(after.iter().map(|p| (&p.name, &p.value))).finish();
        match kind {
            Kind::Query => {
                let parts: Vec<_> = msg.first.split_whitespace().collect();
                if parts.len() != 3 { return Err("Request line must contain method, path and HTTP version".into()); }
                let path = parts[1].split('?').next().unwrap_or("/");
                let query = encoded();
                msg.first = format!("{} {}{} {}", parts[0], path, if query.is_empty() { String::new() } else { format!("?{query}") }, parts[2]);
            }
            Kind::Form => {
                if json.is_some() { return Err("Choose a form body or a JSON body".into()); }
                msg.body = encoded().into_bytes();
                msg.set_header("Content-Type", "application/x-www-form-urlencoded".into());
                fix_body_headers(&mut msg);
            }
            Kind::Cookie => {
                if after.iter().any(|p| p.name.is_empty() || p.name.contains([';', '=', '\r', '\n']) || p.value.contains([';', '\r', '\n'])) {
                    return Err("Cookie names and values cannot contain delimiters or newlines".into());
                }
                let value = after.iter().map(|p| format!("{}={}", p.name, p.value)).collect::<Vec<_>>().join("; ");
                msg.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                if !value.is_empty() { msg.set_header("Cookie", value); }
            }
        }
    }
    if let Some(json) = json {
        serde_json::from_str::<serde_json::Value>(json).map_err(|e| format!("Invalid JSON: {e}"))?;
        if msg.decoded_body() != json.as_bytes() {
            msg.body = json.as_bytes().to_vec();
            fix_body_headers(&mut msg);
        }
    }
    Ok(String::from_utf8_lossy(&msg.render()).into_owned())
}

fn fix_body_headers(msg: &mut Msg) {
    msg.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding") && !k.eq_ignore_ascii_case("transfer-encoding"));
    msg.set_header("Content-Length", msg.body.len().to_string());
}

/// Move form parameters between URL and body without losing duplicate names.
fn change_method(request: &str) -> Result<String, String> {
    let mut msg = Msg::parse(request.as_bytes());
    let parts: Vec<_> = msg.first.split_whitespace().map(str::to_string).collect();
    if parts.len() != 3 { return Err("Invalid request line".into()); }
    let (path, query) = parts[1].split_once('?').unwrap_or((&parts[1], ""));
    match parts[0].as_str() {
        "GET" => {
            if !msg.body.is_empty() { return Err("GET already has a body; move it manually before conversion".into()); }
            msg.first = format!("POST {path} {}", parts[2]);
            msg.body = query.as_bytes().to_vec();
            msg.set_header("Content-Type", "application/x-www-form-urlencoded".into());
            fix_body_headers(&mut msg);
        }
        "POST" => {
            if !msg.body.is_empty() && !msg.header("content-type").is_some_and(|h| h.to_ascii_lowercase().contains("application/x-www-form-urlencoded")) {
                return Err("POST to GET requires a form body; convert JSON to form first".into());
            }
            let decoded = msg.decoded_body();
            let body = std::str::from_utf8(&decoded).map_err(|_| "Form body is not UTF-8")?;
            let encoded = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(crate::http::form_pairs(body)).finish();
            let query = [query, &encoded].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("&");
            msg.first = format!("GET {path}{} {}", if query.is_empty() { String::new() } else { format!("?{query}") }, parts[2]);
            msg.body.clear();
            msg.headers.retain(|(k, _)| !["content-type", "content-length", "content-encoding", "transfer-encoding"].iter().any(|name| k.eq_ignore_ascii_case(name)));
        }
        _ => return Err("Method conversion supports GET and POST".into()),
    }
    Ok(String::from_utf8_lossy(&msg.render()).into_owned())
}

/// Explicitly convert a flat JSON object and a URL-encoded form. Repeated names
/// map to arrays, and nested objects are rejected rather than silently flattened.
fn change_body_encoding(request: &str) -> Result<String, String> {
    let mut msg = Msg::parse(request.as_bytes());
    let ctype = msg.header("content-type").unwrap_or("").to_ascii_lowercase();
    let body = msg.decoded_body();
    if ctype.contains("application/x-www-form-urlencoded") {
        let text = std::str::from_utf8(&body).map_err(|_| "Form body is not UTF-8")?;
        let mut object = serde_json::Map::new();
        for (name, value) in crate::http::form_pairs(text) {
            let value = serde_json::Value::String(value);
            match object.entry(name) {
                serde_json::map::Entry::Vacant(entry) => { entry.insert(value); }
                serde_json::map::Entry::Occupied(mut entry) => {
                    match entry.get_mut() {
                        serde_json::Value::Array(values) => values.push(value),
                        old => *old = serde_json::Value::Array(vec![old.clone(), value]),
                    }
                }
            }
        }
        msg.body = serde_json::to_vec_pretty(&object).map_err(|e| e.to_string())?;
        msg.set_header("Content-Type", "application/json".into());
    } else if ctype.contains("json") {
        let object: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&body).map_err(|e| format!("Use a JSON object: {e}"))?;
        let mut pairs = Vec::new();
        for (name, value) in object {
            let values = match value { serde_json::Value::Array(values) => values, other => vec![other] };
            for value in values {
                let text = match value {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => return Err("Nested JSON objects/arrays cannot be represented as flat form parameters".into()),
                    other => other.to_string(),
                };
                pairs.push((name.clone(), text));
            }
        }
        msg.body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish().into_bytes();
        msg.set_header("Content-Type", "application/x-www-form-urlencoded".into());
    } else { return Err("Body conversion supports JSON objects and URL-encoded forms".into()); }
    fix_body_headers(&mut msg);
    Ok(String::from_utf8_lossy(&msg.render()).into_owned())
}

#[derive(Default)]
pub struct Inspector {
    source: String,
    params: Vec<Param>,
    json: Option<String>,
    error: String,
    add_kind: usize,
}

impl Inspector {
    fn load(&mut self, request: &str) {
        self.source = request.into();
        self.params = params(request);
        let msg = Msg::parse(request.as_bytes());
        self.json = msg.header("content-type").filter(|h| h.to_ascii_lowercase().contains("json"))
            .map(|_| String::from_utf8_lossy(&msg.decoded_body()).into_owned());
        self.error.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, request: &mut String, id: u64) {
        if self.source != *request { self.load(request); }
        ui.push_id(id, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Apply changes").clicked() {
                    match rewrite(&self.source, &self.params, self.json.as_deref()) {
                        Ok(updated) => { *request = updated; self.load(request); }
                        Err(e) => self.error = e,
                    }
                }
                if ui.button("Reset").clicked() { self.load(request); }
            });
            ui.horizontal(|ui| {
                for (label, convert) in [("GET ↔ POST", change_method as fn(&str) -> Result<String, String>), ("JSON ↔ form", change_body_encoding)] {
                    if ui.button(label).on_hover_text("Apply parameter edits, then convert the request").clicked() {
                        match rewrite(&self.source, &self.params, self.json.as_deref()).and_then(|raw| convert(&raw)) {
                            Ok(updated) => { *request = updated; self.load(request); }
                            Err(error) => self.error = error,
                        }
                    }
                }
                ui.weak("Query and form values are decoded.");
            });
            if !self.error.is_empty() { ui.colored_label(egui::Color32::LIGHT_RED, &self.error); }
            egui::ScrollArea::both().id_salt("request_inspector").show(ui, |ui| {
                let mut remove = None;
                egui::Grid::new("parameter_grid").striped(true).show(ui, |ui| {
                    ui.strong("Type"); ui.strong("Name"); ui.strong("Value"); ui.label(""); ui.end_row();
                    for (i, param) in self.params.iter_mut().enumerate() {
                        ui.label(param.kind.label());
                        ui.add(egui::TextEdit::singleline(&mut param.name).id_salt(("name", i)).min_size(egui::vec2(140.0, 20.0)));
                        ui.add(egui::TextEdit::singleline(&mut param.value).id_salt(("value", i)).min_size(egui::vec2(220.0, 20.0)));
                        if ui.button("Remove").clicked() { remove = Some(i); }
                        ui.end_row();
                    }
                });
                if let Some(i) = remove { self.params.remove(i); }
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("param_kind").selected_text(Kind::ALL[self.add_kind].label()).show_ui(ui, |ui| {
                        for (i, kind) in Kind::ALL.iter().enumerate() { ui.selectable_value(&mut self.add_kind, i, kind.label()); }
                    });
                    if ui.button("Add parameter").clicked() {
                        self.params.push(Param { kind: Kind::ALL[self.add_kind], name: "name".into(), value: String::new() });
                    }
                });
                if let Some(json) = &mut self.json {
                    ui.separator();
                    ui.strong("JSON body");
                    if ui.button("Format JSON").clicked() {
                        match serde_json::from_str::<serde_json::Value>(json) {
                            Ok(value) => *json = serde_json::to_string_pretty(&value).unwrap(),
                            Err(e) => self.error = e.to_string(),
                        }
                    }
                    ui.add(egui::TextEdit::multiline(json).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(12));
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn edits_duplicate_params_and_cookies_without_rewriting_untouched_groups() {
        let request = "POST /login?a=one&a=two&raw=%2f HTTP/1.1\r\nHost: example.com\r\nCookie: sid=old; token=abc==\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\nx=%2f";
        let mut edited = params(request);
        edited[1].value = "two & 三".into();
        edited.iter_mut().find(|p| p.name == "sid").unwrap().value = "new".into();
        let output = rewrite(request, &edited, None).unwrap();
        let parsed = Msg::parse(output.as_bytes());
        assert!(parsed.first.contains("a=one&a=two+%26+%E4%B8%89"));
        assert_eq!(parsed.body, b"x=%2f", "unchanged form preserves original encoding");
        assert_eq!(parsed.header("cookie"), Some("sid=new; token=abc=="));
        let round = params(&output);
        assert_eq!(round[1].value, "two & 三");
        edited.retain(|p| p.kind != Kind::Query);
        assert_eq!(Msg::parse(rewrite(request, &edited, None).unwrap().as_bytes()).first, "POST /login HTTP/1.1");
    }

    #[test]
    fn method_conversion_moves_parameters_without_losing_duplicates() {
        let raw = "GET /search?a=one&a=two%20words HTTP/1.1\r\nHost: example.com\r\nCookie: sid=1\r\n\r\n";
        let post = change_method(raw).unwrap();
        let parsed = Msg::parse(post.as_bytes());
        assert_eq!(parsed.first, "POST /search HTTP/1.1");
        assert_eq!(parsed.body, b"a=one&a=two%20words");
        assert_eq!(parsed.header("cookie"), Some("sid=1"));
        let get = Msg::parse(change_method(&post).unwrap().as_bytes());
        assert_eq!(get.first, "GET /search?a=one&a=two+words HTTP/1.1");
        assert!(get.header("content-length").is_none());
        assert!(get.body.is_empty());
        assert!(change_method("GET / HTTP/1.1\r\n\r\nbody").is_err());
    }

    #[test]
    fn body_conversion_preserves_repeated_fields_and_rejects_nested_objects() {
        let raw = "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&a=2&text=hello+world";
        let json = change_body_encoding(raw).unwrap();
        let parsed = Msg::parse(json.as_bytes());
        let value: serde_json::Value = serde_json::from_slice(&parsed.body).unwrap();
        assert_eq!(value["a"], serde_json::json!(["1", "2"]));
        assert_eq!(value["text"], "hello world");
        let form = Msg::parse(change_body_encoding(&json).unwrap().as_bytes());
        assert_eq!(form.body, b"a=1&a=2&text=hello+world");
        assert_eq!(form.header("content-length"), Some(form.body.len().to_string().as_str()));
        assert!(change_body_encoding("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"nested\":{\"x\":1}}").is_err());
    }

    #[test]
    fn body_edits_update_framing_and_reject_invalid_json() {
        let request = "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let output = rewrite(request, &[], Some("{\"ok\": true}")).unwrap();
        let msg = Msg::parse(output.as_bytes());
        assert_eq!(msg.header("content-length"), Some("12"));
        assert!(rewrite(request, &[], Some("{")).is_err());
        let cookie = Param { kind: Kind::Cookie, name: "sid".into(), value: "x\r\nInjected: bad".into() };
        assert!(rewrite(request, &[cookie], None).is_err());
    }
}
