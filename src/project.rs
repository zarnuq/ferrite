//! Save and load a session to a `.ferrite` file: gzipped JSON of history, WebSocket
//! messages and scanner issues. Not a live Burp project (no incremental autosave).

use crate::{
    history::{Flow, History, WsMsg},
    http::Msg,
    scanner::{Issue, Severity},
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use base64::Engine;

const MAGIC: &str = "ferrite-project-v1";

#[derive(Serialize, Deserialize)]
struct SavedFlow {
    id: u64,
    url: String,
    host: String,
    method: String,
    path: String,
    req: Vec<u8>,
    res: Option<Vec<u8>>,
    status: u16,
    mime: String,
    ms: Option<u128>,
    highlight: Option<u32>,
    #[serde(default)]
    note: String,
    #[serde(default)]
    created_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct SavedWs {
    url: String,
    outgoing: bool,
    text: bool,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SavedIssue {
    url: String,
    severity: Severity,
    title: String,
    detail: String,
    req: Vec<u8>,
    res: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Project {
    magic: String,
    flows: Vec<SavedFlow>,
    ws: Vec<SavedWs>,
    issues: Vec<SavedIssue>,
    #[serde(default)]
    repeater: crate::repeater::SavedState,
    #[serde(default)]
    organizer: crate::organizer::SavedState,
    #[serde(default)]
    intruder: crate::intruder::SavedState,
}

/// Known issue titles, so a loaded title becomes `&'static str` without leaking per load.
fn intern(title: &str) -> &'static str {
    for known in crate::scanner::ALL_TITLES {
        if *known == title {
            return known;
        }
    }
    // Unknown title (version drift): leak once. Projects load rarely, so this is bounded.
    Box::leak(title.to_string().into_boxed_str())
}

pub fn save(history: &History, repeater: &crate::repeater::Repeater, organizer: &crate::organizer::Organizer, intruder: &crate::intruder::Intruder, path: &str) -> Result<(), String> {
    let project = Project {
        magic: MAGIC.to_string(),
        repeater: repeater.save_state(),
        organizer: organizer.saved().clone(),
        intruder: intruder.save_state(),
        flows: history
            .flows
            .iter()
            .map(|f| SavedFlow {
                id: f.id,
                url: f.url.clone(),
                host: f.host.clone(),
                method: f.method.clone(),
                path: f.path.clone(),
                req: f.req.clone(),
                res: f.res.clone(),
                status: f.status,
                mime: f.mime.clone(),
                ms: f.ms,
                highlight: f.highlight.map(|c| u32::from_le_bytes(c.to_array())),
                note: f.note.clone(),
                created_ms: f.created_ms,
            })
            .collect(),
        ws: history.ws.iter().map(|m| SavedWs { url: m.url.clone(), outgoing: m.outgoing, text: m.text, data: m.data.clone() }).collect(),
        issues: history
            .issues
            .iter()
            .map(|i| SavedIssue {
                url: i.url.clone(),
                severity: i.severity,
                title: i.title.to_string(),
                detail: i.detail.clone(),
                req: i.req.clone(),
                res: i.res.clone(),
            })
            .collect(),
    };
    let json = serde_json::to_vec(&project).map_err(|e| e.to_string())?;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&json).map_err(|e| e.to_string())?;
    let bytes = gz.finish().map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}"))
}

pub fn load(history: &mut History, repeater: &mut crate::repeater::Repeater, organizer: &mut crate::organizer::Organizer, intruder: &mut crate::intruder::Intruder, path: &str) -> Result<usize, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let mut json = Vec::new();
    GzDecoder::new(&bytes[..]).read_to_end(&mut json).map_err(|_| "not a gzipped ferrite project".to_string())?;
    let project: Project = serde_json::from_slice(&json).map_err(|e| e.to_string())?;
    if project.magic != MAGIC {
        return Err(format!("unrecognised project format: {}", project.magic));
    }
    let flows = project
        .flows
        .into_iter()
        .map(|f| Flow {
            id: f.id,
            url: f.url,
            host: f.host,
            method: f.method,
            path: f.path,
            req: f.req,
            res: f.res,
            status: f.status,
            mime: f.mime,
            ms: f.ms,
            highlight: f.highlight.map(|v| { let [r,g,b,a]=v.to_le_bytes(); eframe::egui::Color32::from_rgba_premultiplied(r,g,b,a) }),
            note: f.note,
            created_ms: f.created_ms,
        })
        .collect();
    let ws = project.ws.into_iter().map(|m| WsMsg { url: m.url, outgoing: m.outgoing, text: m.text, data: m.data }).collect();
    let issues = project
        .issues
        .into_iter()
        .map(|i| Issue { url: i.url, severity: i.severity, title: intern(&i.title), detail: i.detail, req: i.req, res: i.res })
        .collect();
    let count = history.replace_all(flows, ws, issues);
    repeater.restore(project.repeater);
    intruder.restore(project.intruder);
    organizer.restore(project.organizer);
    Ok(count)
}


/// Exports history to HAR 1.2 (gzipped JSON interchange used by browsers and other tools).
pub fn export_har(history: &History, path: &str) -> Result<usize, String> {
    use serde_json::{Value, json};

    fn headers(m: &Msg) -> Vec<Value> {
        m.headers.iter().map(|(k, v)| json!({"name": k, "value": v})).collect()
    }
    fn query(url: &str) -> Vec<Value> {
        let Some((_, q)) = url.split_once('?') else { return Vec::new() };
        crate::http::form_pairs(q).into_iter().map(|(k, v)| json!({"name": k, "value": v})).collect()
    }

    let entries: Vec<Value> = history
        .flows
        .iter()
        .map(|f| {
            let req = Msg::parse(&f.req);
            let res = f.res.as_ref().map(|r| Msg::parse(r));
            let post = (!req.body.is_empty()).then(|| {
                let decoded = req.decoded_body();
                let (text, encoding) = match String::from_utf8(decoded.clone()) {
                    Ok(text) => (text, None),
                    Err(_) => (base64::engine::general_purpose::STANDARD.encode(&decoded), Some("base64")),
                };
                json!({"mimeType": req.header("content-type").unwrap_or("application/octet-stream"), "text": text, "_encoding": encoding})
            });
            let (status, status_text, res_headers, mime, body, redirect, http_version) = match &res {
                Some(r) => {
                    let line: Vec<&str> = r.first.splitn(3, ' ').collect();
                    let decoded = r.decoded_body();
                    let (body, encoding) = match String::from_utf8(decoded.clone()) {
                        Ok(text) => (text, None),
                        Err(_) => (base64::engine::general_purpose::STANDARD.encode(&decoded), Some("base64")),
                    };
                    (
                        r.status() as i64,
                        line.get(2).copied().unwrap_or("").to_string(),
                        headers(r),
                        r.header("content-type").unwrap_or("").to_string(),
                        (body, encoding, decoded.len()),
                        r.header("location").unwrap_or("").to_string(),
                        line.first().copied().unwrap_or("HTTP/1.1").to_string(),
                    )
                }
                None => (0, String::new(), Vec::new(), String::new(), (String::new(), None, 0), String::new(), "HTTP/1.1".into()),
            };
            json!({
                "startedDateTime": time::OffsetDateTime::from_unix_timestamp_nanos(f.created_ms as i128 * 1_000_000)
                    .ok().and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".into()),
                "time": f.ms.unwrap_or(0),
                "request": {
                    "method": f.method,
                    "url": f.url,
                    "httpVersion": req.first.rsplit(' ').next().unwrap_or("HTTP/1.1"),
                    "headers": headers(&req),
                    "queryString": query(&f.url),
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": req.body.len(),
                    "postData": post,
                },
                "response": {
                    "status": status,
                    "statusText": status_text,
                    "httpVersion": http_version,
                    "headers": res_headers,
                    "cookies": [],
                    "content": {"size": body.2, "mimeType": mime, "text": body.0, "encoding": body.1},
                    "redirectURL": redirect,
                    "headersSize": -1,
                    "bodySize": res.as_ref().map_or(0, |r| r.body.len()),
                },
                "cache": {},
                "timings": {"send": 0, "wait": f.ms.unwrap_or(0), "receive": 0},
            })
        })
        .collect();

    let count = entries.len();
    let har = json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "ferrite", "version": env!("CARGO_PKG_VERSION")},
            "entries": entries,
        }
    });
    let json = serde_json::to_vec(&har).map_err(|e| e.to_string())?;
    // .har.gz keeps large exports small; plain .har stays uncompressed.
    if path.ends_with(".gz") {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&json).map_err(|e| e.to_string())?;
        std::fs::write(path, gz.finish().map_err(|e| e.to_string())?).map_err(|e| format!("{path}: {e}"))?;
    } else {
        std::fs::write(path, &json).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_legacy_projects_without_repeater_state() {
        let project: Project = serde_json::from_value(serde_json::json!({
            "magic": MAGIC, "flows": [], "ws": [], "issues": []
        })).unwrap();
        let mut repeater = crate::repeater::Repeater::default();
        repeater.restore(project.repeater);
        assert!(repeater.is_empty());
        let mut intruder = crate::intruder::Intruder::default();
        intruder.restore(project.intruder);
        assert!(intruder.is_empty());
    }

    #[test]
    fn har_round_trip_preserves_binary_bodies_and_timestamps() {
        let mut history = History::default();
        let original_id = crate::history::next_id();
        let mut req = b"POST /upload?q=1 HTTP/1.1\r\nHost: a.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\n".to_vec();
        req.extend([0, 255, 128]);
        history.on_request(original_id, "https://a.com/upload?q=1".into(), req);
        history.flows[0].created_ms = 1_792_200_000_123;
        let mut res = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        res.extend([255, 0, 254]);
        history.on_response(original_id, res, 42);
        let path = format!("/tmp/ferrite-har-roundtrip-{}.har.gz", std::process::id());
        export_har(&history, &path).unwrap();
        let mut imported = History::default();
        assert_eq!(import_har(&mut imported, &path).unwrap(), 1);
        let flow = &imported.flows[0];
        assert_eq!(flow.created_ms, history.flows[0].created_ms);
        assert_eq!(Msg::parse(&flow.req).body, [0, 255, 128]);
        assert_eq!(Msg::parse(flow.res.as_ref().unwrap()).decoded_body(), [255, 0, 254]);
        assert_eq!(flow.ms, Some(42));
        assert_ne!(flow.id, original_id, "imported entries get fresh runtime identities");
        assert!(flow.note.contains("reconstructed"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn imports_form_fields_and_rejects_partial_imports() {
        let entry = serde_json::json!({
            "startedDateTime": "2026-10-17T10:20:30.456-04:00", "time": 12.5,
            "request": {"url": "http://[::1]:8080?x=1", "method": "POST", "cookies": [{"name":"sid","value":"123"}],
                "postData": {"mimeType":"application/x-www-form-urlencoded", "params":[{"name":"q","value":"a b"}]}},
            "response": {"status":200, "statusText":"OK", "headers":[{"name":"Content-Encoding","value":"gzip"}],
                "content":{"mimeType":"text/plain","text":"decoded response"}}
        });
        let imported = har_entry(&entry).unwrap();
        let req = Msg::parse(&imported.req);
        assert_eq!(req.first, "POST /?x=1 HTTP/1.1");
        assert_eq!(req.header("host"), Some("[::1]:8080"));
        assert_eq!(req.header("cookie"), Some("sid=123"));
        assert_eq!(req.body, b"q=a+b");
        let res = Msg::parse(imported.res.as_ref().unwrap());
        assert!(res.header("content-encoding").is_none());
        assert_eq!(res.decoded_body(), b"decoded response");
        let path = format!("/tmp/ferrite-har-invalid-{}.har", std::process::id());
        let har = serde_json::json!({"log":{"entries":[entry, {"request":{"url":"broken"}}]}});
        std::fs::write(&path, serde_json::to_vec(&har).unwrap()).unwrap();
        let mut history = History::default();
        assert!(import_har(&mut history, &path).unwrap_err().contains("entry 2"));
        assert!(history.flows.is_empty(), "failed imports must be atomic");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn round_trip() {
        let mut repeater = crate::repeater::Repeater::default();
        let mut organizer = crate::organizer::Organizer::default();
        let mut intruder = crate::intruder::Intruder::default();
        intruder.load(crate::http::Target::from_url("https://a.com/").unwrap(), b"GET /intruder?q=1 HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
        let mut h = History::default();
        let original_id = crate::history::next_id();
        h.on_request(original_id, "https://a.com/x".into(), b"GET /x HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
        h.on_response(original_id, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hi</p>".to_vec(), 12);
        h.on_ws("wss://a.com/s".into(), true, true, b"ping".to_vec());
        let path = format!("{}/ferrite-test.ferrite", std::env::temp_dir().display());
        organizer.add("https://a.com/x".into(), h.flows[0].req.clone(), h.flows[0].res.clone());
        repeater.add(crate::http::Target::from_url("https://a.com/").unwrap(), b"GET /saved-tab HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
        save(&h, &repeater, &organizer, &intruder, &path).unwrap();
        let mut h2 = History::default();
        let n = load(&mut h2, &mut repeater, &mut organizer, &mut intruder, &path).unwrap();
        assert_eq!(n, 1);
        assert!(!repeater.is_empty(), "Repeater tabs should survive project load");
        assert!(!organizer.is_empty(), "Organizer snapshots should survive project load");
        assert!(!intruder.is_empty(), "Intruder draft should survive project load");
        assert_eq!(h2.flows.len(), 1);
        assert_eq!(h2.flows[0].url, "https://a.com/x");
        assert_eq!(h2.flows[0].status, 200);
        assert_ne!(h2.flows[0].id, original_id);
        h2.on_response(original_id, b"HTTP/1.1 500 Stale response\r\n\r\n".to_vec(), 1);
        assert_eq!(h2.flows[0].status, 200, "old in-flight responses cannot overwrite loaded flows");
        assert_eq!(h2.ws.len(), 1);
        assert!(!h2.issues.is_empty(), "passive scan should have run on load's source");

        // Notes survive a round trip.
        h2.flows[0].note = "interesting".into();
        save(&h2, &repeater, &organizer, &intruder, &path).unwrap();
        let mut h3 = History::default();
        load(&mut h3, &mut repeater, &mut organizer, &mut intruder, &path).unwrap();
        assert_eq!(h3.flows[0].note, "interesting");

        // HAR export produces valid JSON with one entry per flow.
        let har_path = format!("{}/ferrite-test.har", std::env::temp_dir().display());
        let n = export_har(&h3, &har_path).unwrap();
        assert_eq!(n, 1);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&har_path).unwrap()).unwrap();
        assert_eq!(v["log"]["entries"][0]["request"]["method"], "GET");
        assert_eq!(v["log"]["entries"][0]["response"]["status"], 200);
        std::fs::remove_file(&har_path).ok();
        std::fs::remove_file(&path).ok();
    }
}

/// Imports HAR traffic as reconstructed HTTP messages. Parse every entry before changing
/// history, so a malformed entry cannot leave a partially imported session.
pub fn import_har(history: &mut History, path: &str) -> Result<usize, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let json = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        GzDecoder::new(&bytes[..]).read_to_end(&mut out).map_err(|e| format!("Invalid gzip HAR: {e}"))?;
        out
    } else { bytes };
    let har: serde_json::Value = serde_json::from_slice(&json).map_err(|e| format!("Invalid HAR JSON: {e}"))?;
    let entries = har.pointer("/log/entries").and_then(|v| v.as_array()).ok_or("HAR must contain log.entries")?;
    let imported = entries.iter().enumerate().map(|(i, e)| har_entry(e).map_err(|e| format!("HAR entry {}: {e}", i + 1))).collect::<Result<Vec<_>, _>>()?;
    let count = imported.len();
    for entry in imported {
        let id = crate::history::next_id();
        history.on_request(id, entry.url, entry.req);
        if let Some(res) = entry.res { history.on_response(id, res, entry.ms); }
        if let Some(&index) = history.index.get(&id) {
            history.flows[index].created_ms = entry.created_ms;
            history.flows[index].note = "Imported HAR (reconstructed HTTP)".into();
        }
    }
    Ok(count)
}

struct HarEntry { url: String, req: Vec<u8>, res: Option<Vec<u8>>, ms: u128, created_ms: u64 }

fn har_entry(entry: &serde_json::Value) -> Result<HarEntry, String> {
    use serde_json::Value;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    fn headers(value: &Value) -> Vec<(String, String)> {
        value.get("headers").and_then(Value::as_array).into_iter().flatten().filter_map(|h| {
            Some((h.get("name")?.as_str()?.to_string(), h.get("value")?.as_str()?.to_string()))
        }).collect()
    }
    fn body(value: &Value) -> Result<Vec<u8>, String> {
        let text = value.get("text").and_then(Value::as_str).unwrap_or("");
        match value.get("encoding").or_else(|| value.get("_encoding")).and_then(Value::as_str) {
            None | Some("") => Ok(text.as_bytes().to_vec()),
            Some("base64") => base64::engine::general_purpose::STANDARD.decode(text).map_err(|e| format!("Invalid base64 body: {e}")),
            Some(other) => Err(format!("Unsupported body encoding: {other}")),
        }
    }
    let request = &entry["request"];
    let mut url = url::Url::parse(&text(request, "url")).map_err(|e| format!("Invalid request URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") { return Err("Request URL must use HTTP(S)".into()); }
    url.set_fragment(None);
    let target = crate::http::Target::from_url(url.as_str()).ok_or("Invalid request target")?;
    let method = text(request, "method");
    if method.is_empty() || method.bytes().any(|b| !b.is_ascii_graphic()) { return Err("Invalid request method".into()); }
    // HAR contains structured headers and bodies, not original wire bytes.
    let mut req = Msg { first: format!("{method} {} HTTP/1.1", crate::http::url_path(url.as_str())), headers: headers(request), body: Vec::new() };
    if req.header("host").is_none() { req.set_header("Host", target.host_header()); }
    if req.header("cookie").is_none() {
        let cookies = request["cookies"].as_array().into_iter().flatten().map(|c| format!("{}={}", text(c, "name"), text(c, "value"))).collect::<Vec<_>>().join("; ");
        if !cookies.is_empty() { req.set_header("Cookie", cookies); }
    }
    if let Some(post) = request.get("postData").filter(|p| !p.is_null()) {
        req.body = body(post)?;
        if post.get("text").is_none() {
            if let Some(params) = post["params"].as_array().filter(|p| !p.is_empty()) {
                if !text(post, "mimeType").starts_with("application/x-www-form-urlencoded") {
                    return Err("Multipart/file body is unavailable in this HAR; raw postData.text is required".into());
                }
                req.body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params.iter().map(|p| (text(p, "name"), text(p, "value")))).finish().into_bytes();
            }
        }
        if req.header("content-type").is_none() && !text(post, "mimeType").is_empty() { req.set_header("Content-Type", text(post, "mimeType")); }
        req.set_header("Content-Length", req.body.len().to_string());
    }
    let framed = req.header("content-length").is_some() || req.header("transfer-encoding").is_some();
    req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding") && !k.eq_ignore_ascii_case("transfer-encoding"));
    if framed { req.set_header("Content-Length", req.body.len().to_string()); }
    let response = &entry["response"];
    let status = response["status"].as_u64().unwrap_or(0);
    let res = if status == 0 { None } else {
        if !(100..=599).contains(&status) { return Err("Invalid response status".into()); }
        let content = &response["content"];
        let mut res = Msg { first: format!("HTTP/1.1 {status} {}", text(response, "statusText")), headers: headers(response), body: body(content)? };
        // HAR content.text is decoded, so wire compression/chunk framing no longer applies.
        res.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding") && !k.eq_ignore_ascii_case("transfer-encoding"));
        res.set_header("Content-Length", res.body.len().to_string());
        if res.header("content-type").is_none() && !text(content, "mimeType").is_empty() { res.set_header("Content-Type", text(content, "mimeType")); }
        Some(res.render())
    };
    let created_ms = time::OffsetDateTime::parse(&text(entry, "startedDateTime"), &time::format_description::well_known::Rfc3339)
        .ok().map(|t| (t.unix_timestamp_nanos() / 1_000_000).max(0) as u64).unwrap_or(0);
    let ms = entry["time"].as_f64().unwrap_or(0.0).max(0.0) as u128;
    Ok(HarEntry { url: url.into(), req: req.render(), res, ms, created_ms })
}
