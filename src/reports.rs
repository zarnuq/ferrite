//! Reviewable findings and self-contained HTML/JSON reports.
use crate::{history::History,scanner::Issue};
use serde::{Serialize,Deserialize};
use std::collections::BTreeMap;
use eframe::egui;
use sha2::{Digest,Sha256};
use base64::Engine;

#[derive(Clone,Default,Serialize,Deserialize)]
#[serde(default)]
pub struct Review {pub status:String,pub confidence:String,pub remediation:String,pub notes:String}
pub type Saved=BTreeMap<String,Review>;
#[derive(Default)]pub struct Reports{pub saved:Saved,selected:usize,path:String,message:String}
pub fn key(issue:&Issue)->String{let mut h=Sha256::new();h.update(issue.title);h.update([0]);h.update(&issue.url);h.update([0]);h.update(&issue.req);h.finalize().iter().map(|b|format!("{b:02x}")).collect()}
fn escaped(s:&str)->String{s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;").replace('\'',"&#39;")}
fn remediation(title:&str)->String {
    let title=title.to_lowercase();
    if title.contains("sql"){ "Use parameterized queries; avoid SQL string concatenation." }
    else if title.contains("scripting")||title.contains("reflected"){ "Apply context-specific output encoding and validate input. Confirm execution before classifying reflected input as XSS." }
    else if title.contains("cookie"){ "Apply Secure, HttpOnly and an appropriate SameSite policy to sensitive cookies." }
    else if title.contains("transport"){ "Use HTTPS and configure Strict-Transport-Security after validating deployment requirements." }
    else if title.contains("traversal"){ "Resolve paths against an allowed base directory and reject escapes. Avoid using user input as a filesystem path." }
    else { "Validate the finding, identify its root cause, apply a targeted fix, and retest the original evidence." }.into()
}
impl Reports {
    pub fn export(&self,history:&History,path:&str)->Result<(),String>{
        let mut findings=Vec::new();
        for issue in &history.issues {
            let review=self.saved.get(&key(issue)).cloned().unwrap_or_default();
            findings.push(serde_json::json!({"id":key(issue),"url":issue.url,"title":issue.title,"severity":issue.severity.label(),"confidence":if review.confidence.is_empty(){"Tentative"}else{&review.confidence},"status":if review.status.is_empty(){"Open"}else{&review.status},"detail":issue.detail,"notes":review.notes,"remediation":if review.remediation.is_empty(){remediation(issue.title)}else{review.remediation},"request_base64":base64::engine::general_purpose::STANDARD.encode(&issue.req),"response_base64":base64::engine::general_purpose::STANDARD.encode(&issue.res)}));
        }
        let bytes=if path.ends_with(".json"){serde_json::to_vec_pretty(&serde_json::json!({"generator":"Ferrite","findings":findings})).map_err(|e|e.to_string())?}else{
            let mut html=String::from("<!doctype html><meta charset=utf-8><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Ferrite findings</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:16px}article{border-top:1px solid #aaa;margin-top:28px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eee;padding:12px}small{color:#555}</style><h1>Ferrite findings</h1><p>Scanner observations require validation. Review status and confidence before distribution.</p>");
            for (f,issue) in findings.iter().zip(&history.issues){html+=&format!("<article><h2>{}</h2><p>{} · {} · {}</p><p>{}</p><h3>Observation</h3><pre>{}</pre><h3>Remediation</h3><pre>{}</pre><h3>Review notes</h3><pre>{}</pre>",escaped(issue.title),escaped(f["severity"].as_str().unwrap()),escaped(f["confidence"].as_str().unwrap()),escaped(f["status"].as_str().unwrap()),escaped(&issue.url),escaped(&issue.detail),escaped(f["remediation"].as_str().unwrap()),escaped(f["notes"].as_str().unwrap()));
                for(label,raw)in [("Request",&issue.req),("Response",&issue.res)]{html+=&format!("<details><summary>{label} evidence</summary><pre>{}</pre></details>",escaped(&String::from_utf8_lossy(&raw[..raw.len().min(65536)])));if raw.len()>65536{html+="<small>HTML preview limited to 64 KiB. JSON export contains all retained evidence.</small>";}}html+="</article>";
            }html.into_bytes()
        };
        crate::project::atomic_write(std::path::Path::new(path),&bytes).map_err(|e|e.to_string())
    }
    pub fn ui(&mut self,ui:&mut egui::Ui,history:&History){
        ui.horizontal(|ui|{ui.label("Report file");ui.add(egui::TextEdit::singleline(&mut self.path).hint_text("/path/report.html or report.json").desired_width(400.0));if ui.button("Export report").clicked(){self.message=match self.export(history,&self.path){Ok(())=>format!("Exported {} findings",history.issues.len()),Err(e)=>e};}ui.label(&self.message);});
        egui::ScrollArea::vertical().max_height(200.0).show(ui,|ui|{for(i,issue)in history.issues.iter().enumerate(){ui.selectable_value(&mut self.selected,i,format!("{} · {} · {}",issue.severity.label(),issue.title,issue.url));}});
        if let Some(issue)=history.issues.get(self.selected){let review=self.saved.entry(key(issue)).or_insert_with(||Review{status:"Open".into(),confidence:"Tentative".into(),remediation:remediation(issue.title),notes:String::new()});ui.heading(issue.title);ui.label(&issue.url);ui.horizontal(|ui|{egui::ComboBox::from_id_salt("review_status").selected_text(&review.status).show_ui(ui,|ui|{for s in ["Open","Confirmed","False positive","Fixed","Needs retest"]{ui.selectable_value(&mut review.status,s.into(),s);}});egui::ComboBox::from_id_salt("review_confidence").selected_text(&review.confidence).show_ui(ui,|ui|{for s in ["Tentative","Firm","Certain"]{ui.selectable_value(&mut review.confidence,s.into(),s);}});});ui.label(&issue.detail);ui.label("Remediation");ui.add(egui::TextEdit::multiline(&mut review.remediation).desired_rows(3).desired_width(f32::INFINITY));ui.label("Retest / review notes");ui.add(egui::TextEdit::multiline(&mut review.notes).desired_rows(4).desired_width(f32::INFINITY));}
    }
}
#[cfg(test)]mod tests {use super::*;#[test]fn evidence_and_notes_are_html_escaped(){let mut h=History::default();h.add_issue("test".into(),Issue{url:"http://example.test/<script>".into(),title:"Custom scan check",severity:crate::scanner::Severity::Low,detail:"<img src=x onerror=alert(1)>".into(),req:b"<script>bad</script>".to_vec(),res:vec![0,255]});let path=std::env::temp_dir().join(format!("ferrite-report-{}.html",crate::history::next_id()));Reports::default().export(&h,path.to_str().unwrap()).unwrap();let html=std::fs::read_to_string(&path).unwrap();assert!(!html.contains("<script>"));assert!(html.contains("&lt;script&gt;"));std::fs::remove_file(path).unwrap();}}
