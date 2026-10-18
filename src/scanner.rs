//! Passive scanner: checks each proxied response for common issues, Burp-style.

use crate::{
    Event,
    http::{Msg, Target, Upstream},
};
#[cfg(test)]
use crate::http;
use eframe::egui;
use hudsucker::futures::{StreamExt, stream};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use std::sync::{LazyLock, mpsc::Sender};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
        }
    }
}

pub struct Issue {
    pub url: String,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: String,
    pub req: Vec<u8>,
    pub res: Vec<u8>,
}

pub fn identity(issue:&Issue)->String {
    let mut url=url::Url::parse(&issue.url).ok();
    if let Some(url)=&mut url{url.set_query(None);url.set_fragment(None);}
    let location=url.map_or_else(||issue.url.clone(),|u|u.to_string());
    let method=Msg::parse(&issue.req).first.split_whitespace().next().unwrap_or("GET").to_string();
    let point=issue.detail.split_once("Parameter '").or_else(||issue.detail.split_once("parameter '")).and_then(|(_,tail)|tail.split_once("'")).map(|(p,_)|p).unwrap_or(&issue.detail);
    format!("{} {location} {method} {point}",issue.title)
}

pub struct Finding {
    /// Issues with the same key are reported once.
    pub key: String,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: String,
}

static ERRORS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(Traceback \(most recent call last\)|at java\.[a-z]+\.|You have an error in your SQL syntax|ORA-\d{5}|Warning: (mysql|pg)_|Unclosed quotation mark|SQLSTATE\[|PHP (Fatal|Parse) error|System\.NullReferenceException|Microsoft OLE DB Provider)",
    )
    .unwrap()
});
static PRIVATE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b").unwrap()
});
static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*").unwrap());

fn query_params(path: &str) -> Vec<(String, String)> {
    let Some((_, q)) = path.split_once('?') else { return Vec::new() };
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            let dec = |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned();
            (dec(k), dec(v))
        })
        .collect()
}

pub fn passive(url: &str, req_raw: &[u8], res_raw: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(t) = Target::from_url(url) else { return out };
    let host = t.host_header();
    let req = Msg::parse(req_raw);
    let res = Msg::parse(res_raw);
    let path = req.first.split_whitespace().nth(1).unwrap_or("/");
    let page = format!("{}{}", t.url(), path.split('?').next().unwrap_or("/"));
    let ctype = res.header("content-type").unwrap_or("").to_ascii_lowercase();
    let html = ctype.contains("text/html");
    let body = String::from_utf8_lossy(&res.decoded_body()).into_owned();
    let mut add = |key: String, severity, title, detail: String| out.push(Finding { key, severity, title, detail });

    if t.tls && res.header("strict-transport-security").is_none() {
        add(format!("hsts {host}"), Severity::Low, "Strict transport security not enforced",
            format!("{host} served HTTPS without a Strict-Transport-Security header."));
    }
    if html && res.status() == 200 {
        let csp = res.header("content-security-policy").unwrap_or("");
        if res.header("x-frame-options").is_none() && !csp.contains("frame-ancestors") {
            add(format!("frame {host}"), Severity::Info, "Frameable response (potential clickjacking)",
                format!("{page} sets neither X-Frame-Options nor CSP frame-ancestors."));
        }
        if csp.is_empty() {
            add(format!("csp {host}"), Severity::Info, "Content security policy not set",
                format!("{page} returned HTML without a Content-Security-Policy header."));
        }
    }
    if res.header("x-content-type-options").is_none() && !body.is_empty() {
        add(format!("nosniff {host}"), Severity::Info, "X-Content-Type-Options missing",
            format!("{host} does not send X-Content-Type-Options: nosniff."));
    }
    for (k, v) in &res.headers {
        let name = k.to_ascii_lowercase();
        if name == "set-cookie" {
            let cookie = v.split('=').next().unwrap_or("").trim();
            let attrs = v.to_ascii_lowercase();
            let mut missing = Vec::new();
            if t.tls && !attrs.contains("; secure") && !attrs.contains(";secure") {
                missing.push("Secure");
            }
            if !attrs.contains("httponly") {
                missing.push("HttpOnly");
            }
            if !attrs.contains("samesite") {
                missing.push("SameSite");
            }
            if !missing.is_empty() {
                add(format!("cookie {host} {cookie}"), Severity::Low, "Cookie without security flags",
                    format!("Cookie '{cookie}' on {host} is missing: {}.", missing.join(", ")));
            }
        }
        if (name == "server" || name == "x-powered-by" || name == "x-aspnet-version") && v.chars().any(|c| c.is_ascii_digit()) {
            add(format!("version {host} {name}"), Severity::Info, "Software version disclosed",
                format!("{host} discloses '{k}: {v}'."));
        }
    }
    let acao = res.header("access-control-allow-origin").unwrap_or("");
    let creds = res.header("access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !acao.is_empty() && req.header("origin").is_some_and(|o| o == acao) && acao != "null" && creds {
        add(format!("cors {page}"), Severity::Medium, "Cross-origin resource sharing: arbitrary origin trusted",
            format!("{page} reflects the request Origin ({acao}) and allows credentials."));
    } else if acao == "null" && creds {
        add(format!("cors-null {page}"), Severity::Medium, "Cross-origin resource sharing: null origin trusted",
            format!("{page} allows the null origin with credentials."));
    }
    if html || ctype.contains("javascript") || ctype.contains("json") {
        for (k, v) in query_params(path) {
            if v.len() >= 4 && v.chars().all(|c| c.is_ascii_alphanumeric() || "<>\"'-_".contains(c)) && body.contains(&v) {
                add(format!("reflect {page} {k}"), Severity::Info, "Input returned in response (reflected)",
                    format!("The value of parameter '{k}' ({v}) appears unencoded in the response from {page}. Test for XSS."));
            }
        }
    }
    if let Some(m) = ERRORS.find(&body) {
        add(format!("error {page}"), Severity::Low, "Error message or stack trace disclosed",
            format!("{page} contains '{}'.", m.as_str()));
    }
    if let Some(m) = PRIVATE_IP.find(&body) {
        add(format!("ip {host}"), Severity::Info, "Private IP address disclosed", format!("{page} contains {}.", m.as_str()));
    }
    if html && body.contains("<title>Index of /") {
        add(format!("listing {page}"), Severity::Low, "Directory listing", format!("{page} is a directory listing."));
    }
    if !t.tls {
        let req_text = String::from_utf8_lossy(&req.body).to_ascii_lowercase();
        if req_text.contains("password=") || req_text.contains("\"password\"") || req_text.contains("passwd=") {
            add(format!("cleartext {page}"), Severity::High, "Cleartext submission of password",
                format!("A password was submitted to {page} over unencrypted HTTP."));
        }
        if req.header("authorization").is_some_and(|a| a.to_ascii_lowercase().starts_with("basic ")) {
            add(format!("basic {host}"), Severity::Medium, "Basic authentication over HTTP",
                format!("Credentials are sent to {host} with Basic auth over unencrypted HTTP."));
        }
    }
    if let Some(m) = req.headers.iter().find_map(|(_, v)| JWT.find(v)) {
        add(format!("jwt {host}"), Severity::Info, "JSON Web Token in use",
            format!("Requests to {host} carry a JWT, e.g. {}…. Check alg, signature and expiry in Decoder.", &m.as_str()[..m.as_str().len().min(40)]));
    }
    out
}

/// Every issue title the scanner can emit, so loaded projects re-intern them as `&'static str`.
pub const ALL_TITLES: &[&str] = &[
    "Strict transport security not enforced",
    "Frameable response (potential clickjacking)",
    "Content security policy not set",
    "X-Content-Type-Options missing",
    "Cookie without security flags",
    "Software version disclosed",
    "Cross-origin resource sharing: arbitrary origin trusted",
    "Cross-origin resource sharing: null origin trusted",
    "Input returned in response (reflected)",
    "Error message or stack trace disclosed",
    "Private IP address disclosed",
    "Directory listing",
    "Cleartext submission of password",
    "Basic authentication over HTTP",
    "JSON Web Token in use",
    "SQL injection",
    "Cross-site scripting (reflected)",
    "File path traversal",
    "Server-side template injection",
    "Open redirection",
    "SQL injection (time-based blind)",
    "OS command injection (time-based blind)",
    "Hidden parameter reflected",
    "Custom scan check",
    "Out-of-band interaction observed",
];

// ---------- active scanning ----------

static SQL_ERRORS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(You have an error in your SQL syntax|ORA-\d{5}|Unclosed quotation mark|SQLSTATE\[|pg_query\(\)|syntax error at or near|SQLite.{0,20}error|sqlite3\.OperationalError|Microsoft OLE DB Provider|ODBC SQL Server Driver|quoted string not properly terminated|unterminated quoted string|mysql_fetch|Warning: mysql_)",
    )
    .unwrap()
});
static PASSWD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"root:[^:\n]*:0:0:").unwrap());

const ENCODE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
const REDIRECT_HOST: &str = "ferrite-redirect.example";

/// A parameter we can rewrite: index into the query or form-encoded body pairs.
#[derive(Clone)]
pub(crate) enum Point {
    Query(usize),
    Body(usize),
    Cookie(usize),
    Json(String),
    Header(String),
    Multipart(usize,usize),
}

fn cookie_pairs(m: &Msg) -> Vec<String> {
    m.header("cookie").unwrap_or("").split(';').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect()
}

fn split_pairs(s: &str) -> Vec<&str> {
    s.split('&').filter(|p| !p.is_empty()).collect()
}

fn multipart_points(m:&Msg)->Vec<(Point,String)> {
    let mut out=Vec::new();let content_type=m.header("content-type").unwrap_or("");
    if !content_type.to_ascii_lowercase().starts_with("multipart/form-data"){return out;}
    let boundary=content_type.split(';').filter_map(|p|p.trim().split_once('=')).find(|(k,_)|k.eq_ignore_ascii_case("boundary")).map(|(_,v)|v.trim_matches('"'));
    let Some(boundary)=boundary.filter(|b|!b.is_empty()&&b.len()<=70&&!b.contains(['\r','\n']))else{return out;};
    let delimiter=format!("--{boundary}");let delimiter=delimiter.as_bytes();
    let starts:Vec<_>=m.body.windows(delimiter.len()).enumerate().filter(|(i,w)|*w==delimiter&&(*i==0||(*i>=2&&m.body.get(i-2..*i)==Some(b"\r\n")))&&matches!(m.body.get(i+delimiter.len()..i+delimiter.len()+2),Some(b"\r\n"|b"--"))).map(|(i,_)|i).collect();
    for pair in starts.windows(2).take(200){
        let start=pair[0]+delimiter.len()+2;let end=pair[1].saturating_sub(2);
        let Some(part)=m.body.get(start..end)else{continue;};
        let Some(split)=part.windows(4).position(|w|w==b"\r\n\r\n")else{continue;};
        let head=String::from_utf8_lossy(&part[..split]);
        let disposition=head.lines().find_map(|l|l.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("content-disposition")).map(|(_,v)|v));
        let Some(disposition)=disposition else{continue;};
        if disposition.to_ascii_lowercase().contains("filename="){continue;}
        let name=disposition.split(';').filter_map(|p|p.trim().split_once('=')).find(|(k,_)|k.eq_ignore_ascii_case("name")).map(|(_,v)|v.trim_matches('"'));
        if let Some(name)=name{out.push((Point::Multipart(start+split+4,end),format!("multipart {name}")));}
    }
    out
}

pub(crate) fn points(m: &Msg) -> Vec<(Point, String)> {
    let mut out = Vec::new();
    let target = m.first.split_whitespace().nth(1).unwrap_or("");
    if let Some((_, q)) = target.split_once('?') {
        for (i, p) in split_pairs(q).iter().enumerate() {
            out.push((Point::Query(i), p.split('=').next().unwrap_or("").to_string()));
        }
    }
    if m.header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("x-www-form-urlencoded")) {
        for (i, p) in split_pairs(&String::from_utf8_lossy(&m.body)).iter().enumerate() {
            out.push((Point::Body(i), p.split('=').next().unwrap_or("").to_string()));
        }
    }
    fn json_points(value: &serde_json::Value, pointer: String, out: &mut Vec<(Point, String)>, depth: usize) {
        if depth > 16 || out.len() >= 200 { return; }
        match value {
            serde_json::Value::Object(map) => for (key,value) in map { json_points(value, format!("{pointer}/{}",key.replace('~',"~0").replace('/',"~1")),out,depth+1); },
            serde_json::Value::Array(array) => for (i,value) in array.iter().enumerate() { json_points(value,format!("{pointer}/{i}"),out,depth+1); },
            serde_json::Value::String(_) | serde_json::Value::Number(_) => out.push((Point::Json(pointer.clone()),pointer)),
            _ => {},
        }
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&m.body) { json_points(&value,String::new(),&mut out,0); }
    for (i, c) in cookie_pairs(m).iter().enumerate() {
        out.push((Point::Cookie(i), format!("cookie {}", c.split('=').next().unwrap_or(""))));
    }
    out.extend(multipart_points(m));
    for name in ["User-Agent","Referer","X-Forwarded-For"] {if m.header(name).is_some(){out.push((Point::Header(name.into()),format!("header {name}")));}}
    out.truncate(200);
    out
}

/// Replaces one parameter's value (appending to it when `append`) and returns wire bytes.
pub(crate) fn inject(m: &Msg, point: &Point, payload: &str, append: bool) -> Vec<u8> {
    let enc = utf8_percent_encode(payload, ENCODE).to_string();
    let set = |old: &str, new: &str| if append { format!("{old}{new}") } else { new.to_string() };
    let rewrite = |pairs: &str, idx: usize| -> String {
        split_pairs(pairs)
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if i != idx {
                    return p.to_string();
                }
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                format!("{k}={}", set(v, &enc))
            })
            .collect::<Vec<_>>()
            .join("&")
    };
    let mut m = Msg { first: m.first.clone(), headers: m.headers.clone(), body: m.body.clone() };
    match point {
        Point::Header(name)=>{let prev=m.header(name).unwrap_or("");let value=set(prev,payload);if !value.contains(['\r','\n']){m.set_header(name,value);}},
        Point::Multipart(start,end)=>{if *start<=*end&&*end<=m.body.len(){let prev=String::from_utf8_lossy(&m.body[*start..*end]);let value=set(&prev,payload);m.body.splice(*start..*end,value.bytes());}},
        Point::Query(i) => {
            let mut words: Vec<String> = m.first.split(' ').map(str::to_string).collect();
            if let Some((path, q)) = words.get(1).and_then(|t| t.split_once('?')).map(|(a, b)| (a.to_string(), b.to_string())) {
                words[1] = format!("{path}?{}", rewrite(&q, *i));
            }
            m.first = words.join(" ");
        }
        Point::Body(i) => m.body = rewrite(&String::from_utf8_lossy(&m.body), *i).into_bytes(),
        Point::Cookie(i) => {
            let cookies: Vec<String> = cookie_pairs(&m)
                .iter()
                .enumerate()
                .map(|(j, c)| {
                    if j != *i {
                        return c.clone();
                    }
                    let (k, v) = c.split_once('=').unwrap_or((c, ""));
                    format!("{k}={}", set(v, &enc))
                })
                .collect();
            m.set_header("Cookie", cookies.join("; "));
        }
        Point::Json(key) => {
            if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&m.body) {
                if let Some(old) = value.pointer_mut(key) {
                    let prev = old.as_str().map(str::to_string).unwrap_or_else(|| old.to_string());
                    *old = serde_json::Value::String(set(&prev,payload));
                }
                m.body = serde_json::to_vec(&value).unwrap_or_default();
            }
        }
    }
    m.fix_content_length();
    m.render()
}

#[derive(Clone, Copy, PartialEq)]
enum Check {
    Sql,
    Xss,
    Traversal,
    Ssti,
    Redirect,
    /// Time-based blind: payload template holds `{T}` for the delay in seconds.
    SqlTime,
    CmdTime,
}

#[cfg(not(test))]
const DELAY: u64 = 5;
#[cfg(test)]
const DELAY: u64 = 1;

fn payloads(token: &str) -> Vec<(Check, String, bool)> {
    let mut v: Vec<(Check, String, bool)> = vec![
        (Check::Sql, "'".into(), true),
        (Check::Sql, "\"".into(), true),
        (Check::Xss, format!("{token}<\"'>"), false),
        (Check::Traversal, "../../../../../../../../etc/passwd".into(), false),
        (Check::Traversal, "....//....//....//....//....//etc/passwd".into(), false),
        (Check::Ssti, "{{1337*1337}}".into(), false),
        (Check::Ssti, "${1337*1337}".into(), false),
        (Check::Ssti, "<%= 1337*1337 %>".into(), false),
        (Check::Redirect, format!("https://{REDIRECT_HOST}/"), false),
    ];
    for tmpl in sql_time_templates() {
        v.push((Check::SqlTime, tmpl, true));
    }
    for tmpl in cmd_time_templates() {
        v.push((Check::CmdTime, tmpl, true));
    }
    v
}

/// Delay payloads for the major SQL dialects; `{T}` is the delay in seconds.
fn sql_time_templates() -> Vec<String> {
    ["' AND SLEEP({T})-- -", "' OR SLEEP({T})-- -", "'||pg_sleep({T})--", "'; WAITFOR DELAY '0:0:{T}'--"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Delay payloads that run only if the value reaches an OS shell; `{T}` is seconds.
fn cmd_time_templates() -> Vec<String> {
    [";sleep {T};", "|sleep {T}", "$(sleep {T})", "`sleep {T}`"].iter().map(|s| s.to_string()).collect()
}

/// Inspects one probe's response; returns (severity, title, detail) if it looks vulnerable.
fn analyse(check: Check, token: &str, baseline: &str, res: &Msg, param: &str) -> Option<(Severity, &'static str, String)> {
    let body = String::from_utf8_lossy(&res.decoded_body()).into_owned();
    match check {
        Check::Sql => SQL_ERRORS.find(&body).filter(|_| !SQL_ERRORS.is_match(baseline)).map(|m| {
            (Severity::High, "SQL injection", format!("A quote in parameter '{param}' produced a database error: '{}'.", m.as_str()))
        }),
        Check::Xss => {
            let html = res.header("content-type").unwrap_or("text/html").to_ascii_lowercase().contains("html");
            (html && body.contains(&format!("{token}<\"'>"))).then(|| {
                (Severity::High, "Cross-site scripting (reflected)",
                    format!("Parameter '{param}' is echoed into an HTML response with <\"'> unencoded."))
            })
        }
        Check::Traversal => (PASSWD.is_match(&body) && !PASSWD.is_match(baseline)).then(|| {
            (Severity::High, "File path traversal", format!("Parameter '{param}' returned the contents of /etc/passwd."))
        }),
        Check::Ssti => (body.contains("1787569") && !baseline.contains("1787569")).then(|| {
            (Severity::High, "Server-side template injection", format!("Parameter '{param}' evaluated 1337*1337 = 1787569."))
        }),
        Check::Redirect => {
            let loc = res.header("location").unwrap_or("");
            ((300..400).contains(&res.status()) && loc.contains(REDIRECT_HOST)).then(|| {
                (Severity::Medium, "Open redirection", format!("Parameter '{param}' controls the redirect target: {loc}"))
            })
        }
        Check::SqlTime | Check::CmdTime => None,
    }
}

/// Common parameter names to try when mining for hidden/unlinked parameters.
const PARAM_NAMES: &[&str] = &[
    "id", "page", "q", "query", "search", "debug", "test", "admin", "user", "file", "path", "dir",
    "url", "uri", "redirect", "next", "return", "callback", "lang", "locale", "format", "view",
    "action", "cmd", "mode", "type", "key", "token", "api_key", "access", "include", "template",
    "sort", "order", "filter", "limit", "offset", "preview", "show", "hidden", "enable",
];

/// Adds a query parameter to a request, returning wire bytes.
fn add_query(m: &Msg, name: &str, value: &str) -> Vec<u8> {
    let mut words: Vec<String> = m.first.split(' ').map(str::to_string).collect();
    if let Some(target) = words.get(1).cloned() {
        let sep = if target.contains('?') { '&' } else { '?' };
        words[1] = format!("{target}{sep}{name}={value}");
    }
    let mut out = Msg { first: words.join(" "), headers: m.headers.clone(), body: m.body.clone() };
    out.fix_content_length();
    out.render()
}

/// Probes every query and form parameter of one request, reporting issues as they are found.
#[cfg(test)]
pub async fn active(target: Target, raw: Vec<u8>, upstream: Upstream, tx: Sender<Event>, ui: egui::Context) {
    active_controlled(target,raw,upstream,tx,ui,crate::session::Client::new(std::sync::Arc::default(),false,false),true,true).await
}

pub async fn active_controlled(target:Target,raw:Vec<u8>,upstream:Upstream,tx:Sender<Event>,ui:egui::Context,client:crate::session::Client,timing:bool,mining:bool) {
    let notify = |ev: Event| {
        let _ = tx.send(ev);
        ui.request_repaint();
    };
    let m = Msg::parse(&raw);
    let path = m.first.split_whitespace().nth(1).unwrap_or("/").to_string();
    let url = format!("{}{path}", target.url());
    let page = url.split('?').next().unwrap_or(&url).to_string();
    let pts:Vec<_> = points(&m).into_iter().take(200).collect();
    if pts.is_empty() {
        notify(Event::Status(format!("Active scan: no supported insertion points in {url}")));
        return;
    }
    let (baseline, base_time) = match client.send(&target,&raw,&upstream).await.1 {
        Ok(r) => (String::from_utf8_lossy(&Msg::parse(&r.raw).decoded_body()).into_owned(), r.elapsed),
        Err(e) => {
            notify(Event::Status(format!("Active scan failed: {e}")));
            return;
        }
    };
    let token = format!("fr{}",crate::callbacks::token().unwrap_or_else(|_|crate::history::next_id().to_string()));
    let delay = std::time::Duration::from_secs(DELAY);
    // Each probe carries the request plus, for timing checks, a zero-delay control to confirm with.
    let mut probes: Vec<(String, Check, Vec<u8>, Option<Vec<u8>>,Option<usize>)> = Vec::new();
    for (point, name) in &pts {
        for (check, payload, append) in payloads(&token) {
            let is_timing = matches!(check, Check::SqlTime | Check::CmdTime);
            if is_timing && !timing {continue;}
            let req = inject(&m, point, &payload.replace("{T}", &DELAY.to_string()), append);
            let control = Some(if is_timing { inject(&m, point, &payload.replace("{T}", "0"), append) } else { inject(&m, point, "ferritecontrol", false) });
            probes.push((name.clone(), check, req, control,match point{Point::Cookie(index)=>Some(*index),_=>None}));
        }
    }
    let total = probes.len();
    let mut done = 0;
    let mut found = 0;
    let mut results = stream::iter(probes)
        .map(|(name, check, req, control,cookie)| {
            let (target, upstream, client) = (target.clone(), upstream.clone(),client.clone());
            async move {
                let (sent,res) = client.send_probe(&target,&req,&upstream,cookie).await;
                (name, check, req, control,cookie,sent,res)
            }
        })
        .buffer_unordered(5);
    while let Some((name, check, req, control,cookie,sent,res)) = results.next().await {
        done += 1;
        notify(Event::Status(format!("Active scan {url}: {done}/{total} probes, {found} issues")));
        notify(Event::Log(crate::logger::entry("Scanner", &target, &sent, &res)));
        let Ok(r) = res else { continue };
        let hit = match control {
            Some(control) if matches!(check,Check::SqlTime|Check::CmdTime) => confirm_timing(check, &target, &upstream, &client, &control,cookie, r.elapsed, base_time, delay, &name).await,
            Some(control) => {
                if let Some(mut hit)=analyse(check,&token,&baseline,&Msg::parse(&r.raw),&name){
                    let neutral=client.send_probe(&target,&control,&upstream,cookie).await.1;
                    let repeated=client.send_probe(&target,&req,&upstream,cookie).await.1;
                    match (neutral,repeated){
                        (Ok(neutral),Ok(repeated)) if analyse(check,&token,&baseline,&Msg::parse(&neutral.raw),&name).is_none() && analyse(check,&token,&baseline,&Msg::parse(&repeated.raw),&name).is_some()=>{hit.2.push_str(" Reproduced on a second probe; a neutral control did not match. Browser validation is required for reflected XSS.");Some(hit)},
                        _=>None,
                    }
                }else{None}
            },
            None => None,
        };
        if let Some((severity, title, detail)) = hit {
            found += 1;
            let issue = Issue { url: url.clone(), severity, title, detail, req:sent, res: r.raw };
            notify(Event::Issue(format!("active {title} {page} {name}"), issue));
        }
    }

    if !mining {return;}
    // Param mining: try common parameter names not already present and see if any reflects.
    let existing: std::collections::HashSet<String> = pts.iter().map(|(_, n)| n.clone()).collect();
    let candidates: Vec<String> = PARAM_NAMES.iter().filter(|n| !existing.contains(**n)).map(|n| n.to_string()).collect();
    let requests: Vec<(String, String, Vec<u8>)> = candidates
        .into_iter()
        .map(|name| {
            let tok = format!("{token}{name}");
            let req = add_query(&m, &name, &tok);
            (name, tok, req)
        })
        .collect();
    let mut mine = stream::iter(requests)
        .map(|(name, tok, req)| {
            let (target, upstream, client) = (target.clone(), upstream.clone(),client.clone());
            async move {
                let res = client.send(&target,&req,&upstream).await.1;
                (name, tok, req, res)
            }
        })
        .buffer_unordered(5);
    while let Some((name, tok, req, res)) = mine.next().await {
        let Ok(r) = res else { continue };
        let body = String::from_utf8_lossy(&Msg::parse(&r.raw).decoded_body()).into_owned();
        if body.contains(&tok) && !baseline.contains(&tok) {
            found += 1;
            let detail = format!(
                "The server reflected an unlinked parameter '{name}' not present in the original request. Hidden parameters often expose debug features or extra injection points."
            );
            let issue = Issue {
                url: url.clone(),
                severity: Severity::Low,
                title: "Hidden parameter reflected",
                detail,
                req,
                res: r.raw,
            };
            notify(Event::Issue(format!("mine {name} {page}"), issue));
        }
    }
    notify(Event::Status(format!("Active scan {url}: complete, {found} issues")));
}

/// Confirms a time-based blind finding: the probe was slow, and a zero-delay control is fast.
/// This two-step check rejects responses that are simply slow by nature.
async fn confirm_timing(
    check: Check,
    target: &Target,
    upstream: &Upstream,
    client: &crate::session::Client,
    control: &[u8],
    cookie:Option<usize>,
    probe_time: std::time::Duration,
    base_time: std::time::Duration,
    delay: std::time::Duration,
    param: &str,
) -> Option<(Severity, &'static str, String)> {
    if probe_time < base_time + delay.mul_f32(0.9) {
        return None;
    }
    let control_fast = client.send_probe(target, control, upstream,cookie).await.1.is_ok_and(|c| c.elapsed < base_time + delay / 2);
    if !control_fast {
        return None;
    }
    let (title, what) = if check == Check::SqlTime {
        ("SQL injection (time-based blind)", "database")
    } else {
        ("OS command injection (time-based blind)", "server")
    };
    let detail = format!(
        "Parameter '{param}' delayed the response by {:.1}s (baseline {:.1}s) when asked to wait,          and a zero-delay control returned quickly. The {what} is executing the injected delay.",
        probe_time.as_secs_f32(),
        base_time.as_secs_f32()
    );
    Some((Severity::High, title, detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_issues() {
        let req = b"GET /s?q=hello123 HTTP/1.1\r\nHost: a\r\nOrigin: https://evil.com\r\n\r\n";
        let res = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=1; Path=/\r\nServer: nginx/1.2.3\r\nAccess-Control-Allow-Origin: https://evil.com\r\nAccess-Control-Allow-Credentials: true\r\n\r\n<p>hello123</p> 10.0.0.5";
        let f = passive("https://a/s?q=hello123", req, res);
        let titles: Vec<_> = f.iter().map(|f| f.title).collect();
        for t in [
            "Strict transport security not enforced",
            "Frameable response (potential clickjacking)",
            "Cookie without security flags",
            "Software version disclosed",
            "Cross-origin resource sharing: arbitrary origin trusted",
            "Input returned in response (reflected)",
            "Private IP address disclosed",
        ] {
            assert!(titles.contains(&t), "missing {t}: {titles:?}");
        }
        let m = Msg::parse(b"POST /p?a=1&b=2 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nc=3");
        assert_eq!(points(&m).len(), 3);
        // JSON body fields and cookie values are injectable points too.
        let j = Msg::parse(b"POST /p HTTP/1.1\r\nContent-Type: application/json\r\nCookie: sid=1; csrf=x\r\nContent-Length: 17\r\n\r\n{\"u\":\"a\",\"n\":2}");
        let names: Vec<String> = points(&j).into_iter().map(|(_, n)| n).collect();
        assert!(names.contains(&"/u".to_string()) && names.contains(&"/n".to_string()));
        assert!(names.iter().any(|n| n.contains("sid")) && names.iter().any(|n| n.contains("csrf")));
        let got = inject(&j, &Point::Json("/u".into()), "X", true);
        assert!(got.windows(8).any(|w| w == b"\"u\":\"aX\""), "{}", String::from_utf8_lossy(&got));
        assert_eq!(
            inject(&m, &Point::Query(1), "'", true),
            b"POST /p?a=1&b=2%27 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\nc=3"
        );
        assert!(inject(&m, &Point::Body(0), "<x>", false).ends_with(b"Content-Length: 9\r\n\r\nc=%3Cx%3E"));
        let res = Msg::parse(b"HTTP/1.1 500 Error\r\n\r\nYou have an error in your SQL syntax near");
        assert!(analyse(Check::Sql, "t", "", &res, "a").is_some());
        let clean = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nStrict-Transport-Security: max-age=1\r\n\r\n{}";
        assert!(passive("https://a/", b"GET / HTTP/1.1\r\n\r\n", clean).is_empty());
    }
}

#[cfg(test)]
mod active_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A local server with one deliberately vulnerable endpoint per check.
    async fn vulnerable_server() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let target = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let q = http::form_pairs(query);
                    let v = q.first().map(|p| p.1.clone()).unwrap_or_default();
                    let (status, extra, body) = match path {
                        "/sql" if v.contains('\'') => ("500 Error", "", "You have an error in your SQL syntax".to_string()),
                        "/xss" => ("200 OK", "Content-Type: text/html\r\n", format!("<p>{v}</p>")),
                        "/hidden" => {
                            let d = q.iter().find(|(k, _)| k == "debug").map(|(_, val)| val.clone()).unwrap_or_default();
                            ("200 OK", "", format!("home {d}"))
                        }
                        "/file" if v.contains("etc/passwd") => ("200 OK", "", "root:x:0:0:root:/root:/bin/sh".into()),
                        "/tpl" if v.contains("1337*1337") => ("200 OK", "", "1787569".into()),
                        // Sleeps only when the injected delay is non-zero: a real time-based sink.
                        "/slow" => {
                            if v.contains("SLEEP(1)") || v.contains("sleep 1") {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                            ("200 OK", "", "done".to_string())
                        }
                        "/go" => ("302 Found", "", String::new()),
                        _ => ("200 OK", "", "ok".into()),
                    };
                    let location = if path == "/go" { format!("Location: {v}\r\n") } else { String::new() };
                    let res = format!("HTTP/1.1 {status}\r\n{extra}{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = s.write_all(res.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn finds_each_class() {
        let port = vulnerable_server().await;
        let (tx, rx) = std::sync::mpsc::channel();
        let t = Target { host: "127.0.0.1".into(), port, tls: false };
        for path in ["/sql?id=1", "/xss?q=hi", "/file?name=a.txt", "/tpl?n=x", "/go?to=/home", "/slow?id=1", "/hidden?a=1", "/safe?a=1"] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").into_bytes();
            active(t.clone(), req, Upstream::None, tx.clone(), egui::Context::default()).await;
        }
        let issues: Vec<(String, &str)> = rx
            .try_iter()
            .filter_map(|e| if let Event::Issue(_, i) = e { Some((i.url, i.title)) } else { None })
            .collect();
        for (path, title) in [
            ("/sql", "SQL injection"),
            ("/xss", "Cross-site scripting (reflected)"),
            ("/file", "File path traversal"),
            ("/tpl", "Server-side template injection"),
            ("/go", "Open redirection"),
            ("/slow", "SQL injection (time-based blind)"),
            ("/hidden", "Hidden parameter reflected"),
        ] {
            assert!(issues.iter().any(|(u, t)| u.contains(path) && *t == title), "{title} not found: {issues:?}");
        }
        assert!(!issues.iter().any(|(u, _)| u.contains("/safe")), "false positive: {issues:?}");
    }
}


/// Opt-in blind SSRF/XXE probes using the user's reachable callback endpoint.
pub async fn oast(target: Target, raw: Vec<u8>, base: String, client: crate::session::Client, upstream: Upstream, tx: Sender<Event>, ui: egui::Context) {
    let Ok(callback) = url::Url::parse(&base.replace("{{token}}","probe")) else {let _=tx.send(Event::Status("Scanner callback base must be an HTTP(S) URL".into()));return;};
    if !matches!(callback.scheme(),"http"|"https") || callback.host_str().is_none() {return;}
    let msg = Msg::parse(&raw);
    let path=msg.first.split_whitespace().nth(1).unwrap_or("/");
    let url=format!("{}{path}",target.url());
    let mut probes=Vec::new();
    for(point,_)in points(&msg).into_iter().take(20) {
        let Ok(token)=crate::callbacks::token()else{return;};
        let payload=crate::callbacks::payload(&base,&token);
        probes.push((token,"SSRF",inject(&msg,&point,&payload,false)));
    }
    if msg.header("content-type").is_some_and(|t|t.contains("xml")) {
        if let Ok(token)=crate::callbacks::token(){
            let mut xml=Msg::parse(&raw);
            let callback=crate::callbacks::payload(&base,&token).replace('&',"&amp;").replace('"',"&quot;");
            xml.body=format!("<!DOCTYPE ferrite [<!ENTITY probe SYSTEM \"{callback}\">]><ferrite>&probe;</ferrite>").into_bytes();xml.set_header("Content-Length",xml.body.len().to_string());
            probes.push((token,"XXE",xml.render()));
        }
    }
    for(token,kind,request)in probes {
        let _=tx.send(Event::OastProbe(crate::callbacks::Probe{token,url:url.clone(),request:crate::retention::clip(request.clone()),kind:kind.into()}));
        let(sent,result)=client.send(&target,&request,&upstream).await;
        let _=tx.send(Event::Log(crate::logger::entry("Scanner",&target,&sent,&result)));ui.request_repaint();
    }
}

#[cfg(test)]
#[path = "tests/scanner_regression.rs"]
mod robust_scanner_tests;
