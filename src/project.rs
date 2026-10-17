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

pub fn save(history: &History, path: &str) -> Result<(), String> {
    let project = Project {
        magic: MAGIC.to_string(),
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

pub fn load(history: &mut History, path: &str) -> Result<usize, String> {
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
            let req_body = String::from_utf8_lossy(&req.body).into_owned();
            let post = (!req.body.is_empty()).then(|| {
                json!({"mimeType": req.header("content-type").unwrap_or("application/octet-stream"), "text": req_body})
            });
            let (status, status_text, res_headers, mime, body, redirect, http_version) = match &res {
                Some(r) => {
                    let line: Vec<&str> = r.first.splitn(3, ' ').collect();
                    let body = String::from_utf8_lossy(&r.decoded_body()).into_owned();
                    (
                        r.status() as i64,
                        line.get(2).copied().unwrap_or("").to_string(),
                        headers(r),
                        r.header("content-type").unwrap_or("").to_string(),
                        body,
                        r.header("location").unwrap_or("").to_string(),
                        line.first().copied().unwrap_or("HTTP/1.1").to_string(),
                    )
                }
                None => (0, String::new(), Vec::new(), String::new(), String::new(), String::new(), "HTTP/1.1".into()),
            };
            json!({
                "startedDateTime": "1970-01-01T00:00:00.000Z",
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
                    "content": {"size": body.len(), "mimeType": mime, "text": body},
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
    fn round_trip() {
        let mut h = History::default();
        h.on_request(1, "https://a.com/x".into(), b"GET /x HTTP/1.1\r\nHost: a.com\r\n\r\n".to_vec());
        h.on_response(1, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hi</p>".to_vec(), 12);
        h.on_ws("wss://a.com/s".into(), true, true, b"ping".to_vec());
        let path = format!("{}/ferrite-test.ferrite", std::env::temp_dir().display());
        save(&h, &path).unwrap();
        let mut h2 = History::default();
        let n = load(&mut h2, &path).unwrap();
        assert_eq!(n, 1);
        assert_eq!(h2.flows.len(), 1);
        assert_eq!(h2.flows[0].url, "https://a.com/x");
        assert_eq!(h2.flows[0].status, 200);
        assert_eq!(h2.ws.len(), 1);
        assert!(!h2.issues.is_empty(), "passive scan should have run on load's source");

        // Notes survive a round trip.
        h2.flows[0].note = "interesting".into();
        save(&h2, &path).unwrap();
        let mut h3 = History::default();
        load(&mut h3, &path).unwrap();
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
