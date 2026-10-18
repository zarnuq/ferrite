//! Explicit, scoped request chains. Templates reference values extracted from earlier steps.
use crate::{
    http::{self, Msg, Target, Upstream},
    session,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Extract {
    pub name: String,
    #[serde(default)]
    pub regex: String,
    #[serde(default)]
    pub json_pointer: String,
    #[serde(default)]
    pub url_encode: bool,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub url: String,
    pub request: String,
    #[serde(default)]
    pub extract: Vec<Extract>,
    #[serde(default)]
    pub expect_status: u16,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Validity {
    #[serde(flatten)]
    pub step: Step,
    #[serde(default)]
    pub expect_body_regex: String,
}
impl Validity {
    fn matches(&self, reply: &http::Reply) -> Result<bool, String> {
        let status = if self.step.expect_status == 0 {
            200
        } else {
            self.step.expect_status
        };
        if reply.status != status {
            return Ok(false);
        }
        if self.expect_body_regex.is_empty() {
            return Ok(true);
        }
        Ok(regex::Regex::new(&self.expect_body_regex)
            .map_err(|e| e.to_string())?
            .is_match(&String::from_utf8_lossy(
                &Msg::parse(&reply.raw).decoded_body(),
            )))
    }
}
impl std::ops::Deref for Validity {
    type Target = Step;
    fn deref(&self) -> &Step {
        &self.step
    }
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Macro {
    /// A successful check skips the login chain, while still extracting fresh tokens.
    #[serde(default)]
    pub validity: Option<Validity>,
    pub name: String,
    pub enabled: bool,
    /// Exact origin prevents credentials or extracted values crossing origins.
    pub origin: String,
    pub path_regex: String,
    pub steps: Vec<Step>,
}

pub(crate) static GATE: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::default());

fn substitute(template: &str, values: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{") {
        out.push_str(before);
        let (name, tail) = after.split_once("}}").ok_or("Unclosed macro variable")?;
        if let Some(value) = values.get(name) {
            out.push_str(value);
        } else if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(format!("Macro variable {name} has no value"));
        } else {
            out.push_str("{{");
            out.push_str(name);
            out.push_str("}}");
        }
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

pub async fn prepare(
    macros: &[Macro],
    client: &session::Client,
    target: &Target,
    raw: &[u8],
    upstream: &Upstream,
) -> Result<Vec<u8>, String> {
    let msg = Msg::parse(raw);
    let path = msg.first.split_whitespace().nth(1).unwrap_or("/");
    let rules: Vec<_> = macros
        .iter()
        .filter(|m| m.enabled && m.origin.trim_end_matches('/') == target.url())
        .collect();
    if rules.is_empty() {
        return Ok(client.prepare(target, raw));
    }
    // Keep token refresh / login chains from interleaving between concurrent workers.

    let mut values = BTreeMap::new();
    let mut matched = false;
    for rule in rules {
        let re =
            regex::Regex::new(&rule.path_regex).map_err(|e| format!("Macro {}: {e}", rule.name))?;
        if !re.is_match(path) {
            continue;
        }
        matched = true;
        if rule.steps.len() > 32 {
            return Err("A macro supports at most 32 steps".into());
        }
        let mut steps: Vec<&Step> = Vec::new();
        if let Some(check) = &rule.validity {
            let check_target = Target::from_url(&check.url).ok_or("Invalid session check URL")?;
            if check_target.url() != target.url() {
                return Err("Session checks must stay on the rule's origin".into());
            }
            let wire = client.prepare(
                &check_target,
                &http::to_wire(&substitute(&check.request, &values)?, true),
            );
            let result = http::send(&check_target, &wire, upstream).await;
            client.capture(&check_target, &wire, &result);
            let reply = result.map_err(|e| format!("Session check {}: {e}", rule.name))?;
            if check.matches(&reply)? {
                extract_values(check, &reply, &mut values)?;
                continue;
            }
        }
        steps.extend(rule.steps.iter());
        for step in steps {
            let url = substitute(&step.url, &values)?;
            let step_target = Target::from_url(&url).ok_or("Invalid macro URL")?;
            if step_target.url() != target.url() {
                return Err("Macro steps must stay on the rule's origin".into());
            }
            let request = substitute(&step.request, &values)?;
            let wire = client.prepare(&step_target, &http::to_wire(&request, true));
            let result = http::send(&step_target, &wire, upstream).await;
            client.capture(&step_target, &wire, &result);
            let reply = result.map_err(|e| format!("Macro {}: {e}", rule.name))?;
            if step.expect_status != 0 && reply.status != step.expect_status {
                return Err(format!(
                    "Macro {} expected {}, received {}",
                    rule.name, step.expect_status, reply.status
                ));
            }
            extract_values(step, &reply, &mut values)?;
        }
        if let Some(check) = &rule.validity {
            let check_target = Target::from_url(&check.url).ok_or("Invalid session check URL")?;
            let wire = client.prepare(
                &check_target,
                &http::to_wire(&substitute(&check.request, &values)?, true),
            );
            let result = http::send(&check_target, &wire, upstream).await;
            client.capture(&check_target, &wire, &result);
            let reply = result.map_err(|e| format!("Session check {}: {e}", rule.name))?;
            if !check.matches(&reply)? {
                return Err(format!(
                    "Session {} is still invalid after its login chain",
                    rule.name
                ));
            }
            extract_values(check, &reply, &mut values)?;
        }
    }
    if !matched {
        return Ok(client.prepare(target, raw));
    }
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(index) = rest.windows(2).position(|w| w == b"{{") {
        out.extend_from_slice(&rest[..index]);
        rest = &rest[index + 2..];
        let close = rest
            .windows(2)
            .position(|w| w == b"}}")
            .ok_or("Unclosed macro variable")?;
        let name = std::str::from_utf8(&rest[..close]).ok();
        if let Some(value) = name.and_then(|name| values.get(name)) {
            out.extend_from_slice(value.as_bytes());
        } else if name.is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) {
            return Err(format!("Macro variable {} has no value", name.unwrap()));
        } else {
            out.extend_from_slice(b"{{");
            out.extend_from_slice(&rest[..close]);
            out.extend_from_slice(b"}}");
        }
        rest = &rest[close + 2..];
    }
    out.extend_from_slice(rest);
    let mut message = Msg::parse(&out);
    message.fix_content_length();
    Ok(client.prepare(target, &message.render()))
}

fn extract_values(
    step: &Step,
    reply: &http::Reply,
    values: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let response = Msg::parse(&reply.raw);
    let decoded = response.decoded_body();
    let text = String::from_utf8_lossy(&decoded);
    let whole = format!(
        "{}\n{}",
        String::from_utf8_lossy(&reply.raw[..reply.raw.len().saturating_sub(response.body.len())]),
        text
    );
    for extract in &step.extract {
        let mut value = if !extract.json_pointer.is_empty() {
            let json: serde_json::Value =
                serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
            let value = json
                .pointer(&extract.json_pointer)
                .ok_or_else(|| format!("Missing JSON value {}", extract.json_pointer))?;
            value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string())
        } else {
            regex::Regex::new(&extract.regex)
                .map_err(|e| e.to_string())?
                .captures(&whole)
                .and_then(|c| c.get(1))
                .ok_or_else(|| {
                    format!(
                        "Macro extraction {} did not match capture group 1",
                        extract.name
                    )
                })?
                .as_str()
                .to_string()
        };
        if extract.url_encode {
            value =
                percent_encoding::utf8_percent_encode(&value, percent_encoding::NON_ALPHANUMERIC)
                    .to_string();
        }
        values.insert(extract.name.clone(), value);
    }
    Ok(())
}

#[derive(Default)]
pub struct Editor {
    text: String,
    error: String,
}
impl Editor {
    pub fn ui(&mut self, ui: &mut eframe::egui::Ui, rules: &mut Vec<Macro>) {
        ui.collapsing("Session macros", |ui| {
            ui.label("Scoped login/token chains run before matching tool requests. An optional validity step skips login when its expected status matches and can extract fresh CSRF tokens. Values use {{name}}. Cookie reuse is controlled by each tool.");
            if self.text.is_empty() { self.text = serde_json::to_string_pretty(rules).unwrap_or_default(); }
            ui.horizontal(|ui| {
                if ui.button("Example").clicked() {
                    self.text = r#"[{"name":"Refresh CSRF","enabled":false,"origin":"https://example.com","path_regex":"^/submit","steps":[{"url":"https://example.com/token","request":"GET /token HTTP/1.1\r\nHost: example.com\r\n\r\n","expect_status":200,"extract":[{"name":"csrf","json_pointer":"/token","url_encode":true}]}]}]"#.into();
                }
                if ui.button("Apply macros").clicked() {
                    match serde_json::from_str::<Vec<Macro>>(&self.text).and_then(|r| {
                        for m in &r { regex::Regex::new(&m.path_regex).map_err(serde::de::Error::custom)?; }
                        Ok(r)
                    }) { Ok(r) => { *rules = r; self.error = "Saved".into(); }, Err(e) => self.error = e.to_string() }
                }
                ui.label(&self.error);
            });
            ui.add(eframe::egui::TextEdit::multiline(&mut self.text).font(eframe::egui::TextStyle::Monospace).desired_rows(12).desired_width(f32::INFINITY));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates_require_values_and_preserve_literals() {
        let vars = BTreeMap::from([("token".into(), "hello%20world".into())]);
        assert_eq!(
            substitute("csrf={{token}}&a=1", &vars).unwrap(),
            "csrf=hello%20world&a=1"
        );
        assert!(substitute("{{missing}}", &vars).is_err());
        assert_eq!(substitute("{{1337*1337}}", &vars).unwrap(), "{{1337*1337}}");
        assert!(substitute("{{token", &vars).is_err());
    }
}
