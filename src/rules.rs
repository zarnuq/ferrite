//! User settings the proxy reads on every request: scope, match & replace,
//! intercept switches and the upstream proxy.

use crate::http::{Msg, Upstream};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum Part {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    ResponseFirstLine,
    ResponseHeader,
    ResponseBody,
}

impl Part {
    pub const ALL: [Part; 6] = [
        Part::RequestFirstLine,
        Part::RequestHeader,
        Part::RequestBody,
        Part::ResponseFirstLine,
        Part::ResponseHeader,
        Part::ResponseBody,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Part::RequestFirstLine => "Request first line",
            Part::RequestHeader => "Request header",
            Part::RequestBody => "Request body",
            Part::ResponseFirstLine => "Response first line",
            Part::ResponseHeader => "Response header",
            Part::ResponseBody => "Response body",
        }
    }

    fn is_request(self) -> bool {
        matches!(self, Part::RequestFirstLine | Part::RequestHeader | Part::RequestBody)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub enabled: bool,
    pub part: Part,
    /// Empty `find` on a header part adds `replace` as a new header line.
    pub find: String,
    pub replace: String,
    pub regex: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Intercept {
    pub on: bool,
    pub requests: bool,
    pub responses: bool,
    pub websockets: bool,
    pub scope_only: bool,
    /// Let images, CSS, fonts and similar through without stopping.
    pub skip_static: bool,
}

impl Default for Intercept {
    fn default() -> Self {
        Intercept { on: false, requests: true, responses: false, websockets: false, scope_only: false, skip_static: true }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub rules: Vec<Rule>,
    pub intercept: Intercept,
    pub upstream: Upstream,
    /// Hosts (regex) tunnelled without TLS interception.
    pub passthrough: Vec<String>,
    pub mods: Mods,
    pub theme: Theme,
    /// Record only in-scope traffic in history (still proxies everything).
    pub record_scope_only: bool,
    pub capture_cookies: bool,
}

#[derive(Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    System,
    Dark,
    Light,
}

/// Burp-style response modifications applied to proxied HTML.
#[derive(Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Mods {
    pub unhide_hidden: bool,
    pub enable_disabled: bool,
    pub remove_maxlength: bool,
    pub remove_js_validation: bool,
    pub strip_secure: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            include: Vec::new(),
            exclude: Vec::new(),
            rules: Vec::new(),
            intercept: Intercept::default(),
            upstream: Upstream::None,
            passthrough: Vec::new(),
            mods: Mods::default(),
            theme: Theme::System,
            record_scope_only: false,
            capture_cookies: true,
        }
    }
}

fn settings_path() -> std::path::PathBuf {
    crate::proxy::config_dir().join("settings.json")
}

/// Loads saved settings. Intercept always starts off.
pub fn load() -> Config {
    let mut cfg: Config = std::fs::read(settings_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    cfg.intercept.on = false;
    cfg
}

pub fn save(cfg: &Config) {
    let path = settings_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    if let Ok(json) = serde_json::to_vec_pretty(cfg) {
        let _ = std::fs::write(path, json);
    }
}

pub fn compile(pattern: &str, regex: bool) -> Option<Regex> {
    Regex::new(&if regex { pattern.to_string() } else { regex::escape(pattern) }).ok()
}

/// A `Config` with its regexes compiled once.
pub struct Compiled {
    pub cfg: Config,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    passthrough: Vec<Regex>,
    rules: Vec<(Part, Option<Regex>, Vec<u8>)>,
}

impl Compiled {
    pub fn new(cfg: Config) -> Compiled {
        let list = |v: &[String]| v.iter().filter(|s| !s.is_empty()).filter_map(|s| compile(s, true)).collect();
        let mut rules: Vec<_> = cfg
            .rules
            .iter()
            .filter(|r| r.enabled)
            .filter_map(|r| {
                let re = if r.find.is_empty() { None } else { Some(compile(&r.find, r.regex)?) };
                Some((r.part, re, r.replace.clone().into_bytes()))
            })
            .collect();
        let m = &cfg.mods;
        let mods = [
            (m.unhide_hidden, Part::ResponseBody, r#"(?i)(<input\b[^>]*?\btype\s*=\s*["']?)hidden"#, "${1}text"),
            (
                m.enable_disabled,
                Part::ResponseBody,
                r#"(?i)(<(?:input|select|textarea|button|option)\b[^>]*?)\s+disabled(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?"#,
                "$1",
            ),
            (m.remove_maxlength, Part::ResponseBody, r#"(?i)(<(?:input|textarea)\b[^>]*?)\s+maxlength\s*=\s*["']?\d+["']?"#, "$1"),
            (m.remove_js_validation, Part::ResponseBody, r#"(?i)(<form\b[^>]*?)\s+onsubmit\s*=\s*(?:"[^"]*"|'[^']*')"#, "$1"),
            (
                m.remove_js_validation,
                Part::ResponseBody,
                r#"(?i)(<(?:input|select|textarea)\b[^>]*?)\s+(?:required|pattern\s*=\s*(?:"[^"]*"|'[^']*'))"#,
                "$1",
            ),
            (m.strip_secure, Part::ResponseHeader, r"(?i)^(set-cookie:.*?);\s*secure\b", "$1"),
        ];
        for (on, part, find, rep) in mods {
            if on {
                rules.push((part, Regex::new(find).ok(), rep.as_bytes().to_vec()));
            }
        }
        Compiled {
            include: list(&cfg.include),
            exclude: list(&cfg.exclude),
            passthrough: list(&cfg.passthrough),
            rules,
            cfg,
        }
    }

    /// Empty include list means everything is in scope.
    pub fn in_scope(&self, url: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|r| r.is_match(url.as_bytes())))
            && !self.exclude.iter().any(|r| r.is_match(url.as_bytes()))
    }

    /// Hosts whose TLS is tunnelled untouched.
    pub fn passthrough(&self, host: &str) -> bool {
        self.passthrough.iter().any(|r| r.is_match(host.as_bytes()))
    }

    pub fn intercepts(&self, enabled: bool, url: &str) -> bool {
        let i = &self.cfg.intercept;
        i.on && enabled && (!i.scope_only || self.in_scope(url))
    }

    /// Applies match & replace rules. Returns the new message only if something changed.
    pub fn apply(&self, raw: &[u8], request: bool) -> Option<Vec<u8>> {
        let rules: Vec<_> = self.rules.iter().filter(|(p, ..)| p.is_request() == request).collect();
        if rules.is_empty() {
            return None;
        }
        let mut m = Msg::parse(raw);
        for (part, re, rep) in rules {
            match (part, re) {
                (Part::RequestBody | Part::ResponseBody, Some(re)) => {
                    m.body = re.replace_all(&m.body, rep.as_slice()).into_owned();
                }
                (Part::RequestHeader | Part::ResponseHeader, Some(re)) => {
                    let mut lines = Vec::new();
                    for (k, v) in &m.headers {
                        let line = re.replace_all(format!("{k}: {v}").as_bytes(), rep.as_slice()).into_owned();
                        let line = String::from_utf8_lossy(&line).into_owned();
                        // A rule that empties a header line removes it.
                        if let Some((k, v)) = line.split_once(':') {
                            lines.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                    m.headers = lines;
                }
                (Part::RequestHeader | Part::ResponseHeader, None) => {
                    if let Some((k, v)) = String::from_utf8_lossy(rep).split_once(':') {
                        m.headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }
                (Part::RequestFirstLine | Part::ResponseFirstLine, Some(re)) => {
                    m.first = String::from_utf8_lossy(&re.replace_all(m.first.as_bytes(), rep.as_slice())).into_owned();
                }
                _ => {}
            }
        }
        m.fix_content_length();
        let out = m.render();
        (out != raw).then_some(out)
    }
}

pub type Shared = Arc<RwLock<Arc<Compiled>>>;

pub fn current(shared: &Shared) -> Arc<Compiled> {
    shared.read().unwrap().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(part: Part, find: &str, replace: &str) -> Rule {
        Rule { enabled: true, part, find: find.into(), replace: replace.into(), regex: true }
    }

    #[test]
    fn scope_and_rules() {
        let c = Compiled::new(Config {
            include: vec![r"example\.com".into()],
            exclude: vec![r"\.png$".into()],
            rules: vec![
                rule(Part::RequestHeader, "^User-Agent: .*$", "User-Agent: ferrite"),
                rule(Part::RequestHeader, "", "X-Test: 1"),
                rule(Part::RequestBody, "a", "bb"),
                rule(Part::RequestFirstLine, r"^POST ", "PUT "),
                rule(Part::ResponseBody, "zzz", "y"),
            ],
            ..Config::default()
        });
        assert!(c.in_scope("https://example.com/"));
        assert!(!c.in_scope("https://example.com/a.png"));
        assert!(!c.in_scope("https://other.org/"));
        let out = c.apply(b"POST / HTTP/1.1\r\nUser-Agent: curl\r\nContent-Length: 1\r\n\r\na", true).unwrap();
        assert_eq!(
            out,
            b"PUT / HTTP/1.1\r\nUser-Agent: ferrite\r\nContent-Length: 2\r\nX-Test: 1\r\n\r\nbb".to_vec()
        );
        assert!(c.apply(b"HTTP/1.1 200 OK\r\n\r\nabc", false).is_none());

        let mods = Mods { unhide_hidden: true, enable_disabled: true, remove_maxlength: true, remove_js_validation: true, strip_secure: true };
        let c = Compiled::new(Config { mods, passthrough: vec!["google".into()], ..Config::default() });
        let html = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Secure; HttpOnly\r\n\r\n<form onsubmit=\"return v()\"><input type=hidden name=a><input name=b disabled maxlength=3 required></form>";
        let out = String::from_utf8(c.apply(html, false).unwrap()).unwrap();
        assert!(out.contains("Set-Cookie: s=1; HttpOnly"), "{out}");
        assert!(out.ends_with("<form><input type=text name=a><input name=b></form>"), "{out}");
        assert!(c.passthrough("www.google.com") && !c.passthrough("example.com"));
    }
}
