//! Ferrite's JSON check format and stdin/stdout script protocol; no Burp compatibility.
use crate::{Env,Event,http::{self,Msg,Target},scanner::{Issue,Severity}};
use base64::{Engine,engine::general_purpose::STANDARD};
use eframe::egui;
use serde::{Deserialize,Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt,AsyncWriteExt};

#[derive(Clone,PartialEq,Serialize,Deserialize,Default)]
#[serde(default)]
pub struct Check {
    pub name:String,pub enabled:bool,pub url_regex:String,
    /// Empty request means a passive check. Active templates support {{host}}, {{path}}, {{origin}}.
    pub request:String,pub response_regex:String,pub status:u16,pub severity:Option<Severity>,
    /// Suppress matches already present in the unmodified baseline.
    pub differential:bool,
}
#[derive(Clone,PartialEq,Serialize,Deserialize,Default)]
#[serde(default)]
pub struct Script {pub name:String,pub enabled:bool,pub origin:String,pub phase:String,pub command:Vec<String>}
fn sdk_version()->u32{1}
#[derive(Clone,PartialEq,Serialize,Deserialize,Default)]#[serde(default)]
pub struct Tool{pub name:String,pub enabled:bool,pub origin:String,pub request:String}
#[derive(Clone,PartialEq,Serialize,Deserialize,Default)]#[serde(default)]
pub struct Panel{pub name:String,pub enabled:bool,pub url_regex:String,pub response_regex:String}
#[derive(Clone,PartialEq,Serialize,Deserialize)]
#[serde(default)]
pub struct Package {#[serde(default="sdk_version")]pub version:u32,pub name:String,pub checks:Vec<Check>,pub scripts:Vec<Script>,pub tools:Vec<Tool>,pub panels:Vec<Panel>}
impl Default for Package{fn default()->Self{Self{version:1,name:String::new(),checks:vec![],scripts:vec![],tools:vec![],panels:vec![]}}}
impl Package {
    pub fn validate(&self)->Result<(),String>{
        if self.version!=1{return Err("Unsupported extension API version; expected 1".into());}
        if self.tools.len()>20||self.panels.len()>20{return Err("Package exceeds 20 tools / 20 panels".into());}
        for tool in &self.tools{if crate::browser_auth::origin(&tool.origin).is_none()||tool.name.is_empty()||tool.request.len()>1024*1024{return Err("Tools need a name, exact origin and at most 1 MiB of request template".into());}}
        for panel in &self.panels{regex::Regex::new(&panel.url_regex).map_err(|e|e.to_string())?;regex::Regex::new(&panel.response_regex).map_err(|e|e.to_string())?;if panel.name.is_empty()||panel.response_regex.is_empty(){return Err("Panels need a name and response regex".into());}}

        if self.checks.len()>200||self.scripts.len()>20{return Err("Package exceeds 200 checks / 20 scripts".into());}
        for c in &self.checks {regex::Regex::new(&c.url_regex).map_err(|e|e.to_string())?;regex::Regex::new(&c.response_regex).map_err(|e|e.to_string())?;if c.response_regex.is_empty()&&c.status==0{return Err(format!("{} needs a response regex or expected status",c.name));}}
        for s in &self.scripts {if s.command.is_empty()||!matches!(s.phase.as_str(),"request"|"response"){return Err("Script needs a command and request/response phase".into());}if Target::from_url(&s.origin).is_none(){return Err("Script needs an explicit HTTP(S) origin".into());}}
        Ok(())
    }
}
fn matches(check:&Check,url:&str,raw:&[u8])->bool{
    if !check.enabled||!regex::Regex::new(&check.url_regex).is_ok_and(|r|r.is_match(url)){return false;}
    let msg=Msg::parse(raw);let text=format!("{}\n{}",String::from_utf8_lossy(raw),String::from_utf8_lossy(&msg.decoded_body()));
    (check.status==0||check.status==msg.status())&&regex::Regex::new(&check.response_regex).is_ok_and(|r|r.is_match(&text))
}
pub fn passive(package:&Package,url:&str,req:&[u8],res:&[u8])->Vec<Issue>{
    if package.version!=1{return Vec::new();}
    package.checks.iter().filter(|c|c.request.is_empty()&&matches(c,url,res)).map(|c|Issue{url:url.into(),severity:c.severity.unwrap_or(Severity::Info),title:"Custom scan check",detail:format!("{} matched its configured response condition. Validate the evidence before treating this as a vulnerability.",c.name),req:crate::retention::clip(req.to_vec()),res:crate::retention::clip(res.to_vec())}).collect()
}
pub async fn active(package:Package,target:Target,raw:Vec<u8>,client:crate::session::Client,upstream:http::Upstream,tx:std::sync::mpsc::Sender<Event>,ctx:egui::Context){
    if package.version!=1{return;}
    let path=Msg::parse(&raw).first.split_whitespace().nth(1).unwrap_or("/").to_string();let url=format!("{}{path}",target.url());
    let(_,baseline)=client.send(&target,&raw,&upstream).await;
    for check in package.checks.iter().filter(|c|c.enabled&&!c.request.is_empty()){
        if !regex::Regex::new(&check.url_regex).is_ok_and(|r|r.is_match(&url)){continue;}
        let text=check.request.replace("{{host}}",&target.host_header()).replace("{{origin}}",&target.url()).replace("{{path}}",&path);
        let(request,result)=client.send(&target,&http::to_wire(&text,true),&upstream).await;
        let _=tx.send(Event::Log(crate::logger::entry("Scanner",&target,&request,&result)));
        if let Ok(response)=result{
            if matches(check,&url,&response.raw)&&(!check.differential||baseline.as_ref().is_ok_and(|r|!matches(check,&url,&r.raw))){
                let _=tx.send(Event::Issue(format!("custom {} {url}",check.name),Issue{url:url.clone(),severity:check.severity.unwrap_or(Severity::Info),title:"Custom scan check",detail:format!("{} matched the configured active check; validate manually.",check.name),req:crate::retention::clip(request),res:crate::retention::clip(response.raw)}));
            }
        }
        ctx.request_repaint();
    }
}

pub async fn hooks(package:&Package,phase:&str,url:&str,mut raw:Vec<u8>)->Result<Vec<u8>,String>{
    if package.version!=1{return Err("Unsupported extension API version".into());}
    let origin=Target::from_url(url).ok_or("Invalid hook URL")?.url();
    for script in package.scripts.iter().filter(|s|s.enabled&&s.phase==phase&&s.origin.trim_end_matches('/')==origin){
        let run=async{
            let(executable,args)=script.command.split_first().ok_or("Empty script command")?;
            let mut child=tokio::process::Command::new(executable).args(args).kill_on_drop(true).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().map_err(|e|e.to_string())?;
            let input=serde_json::to_vec(&json!({"version":1,"phase":phase,"url":url,"raw_base64":STANDARD.encode(&raw)})).map_err(|e|e.to_string())?;
            let mut stdin=child.stdin.take().unwrap();let mut stdout=child.stdout.take().unwrap().take(2*1024*1024);let mut output=Vec::new();
            let(write,read)=tokio::join!(async move { let result=stdin.write_all(&input).await; drop(stdin); result },stdout.read_to_end(&mut output));
            write.map_err(|e|e.to_string())?;read.map_err(|e|e.to_string())?;
            if output.len()>=2*1024*1024{return Err("Script output exceeds 2 MiB".into());}
            if !child.wait().await.map_err(|e|e.to_string())?.success(){return Err("Script exited unsuccessfully".into());}
            let value:serde_json::Value=serde_json::from_slice(&output).map_err(|e|e.to_string())?;
            if value.get("version").is_some_and(|v|v.as_u64()!=Some(1)){return Err("Unsupported script protocol version".into());}
            let encoded=value["raw_base64"].as_str().ok_or("Script output needs raw_base64")?;
            STANDARD.decode(encoded).map_err(|e|e.to_string())
        };
        raw=tokio::time::timeout(std::time::Duration::from_secs(3),run).await.map_err(|_|format!("Script {} timed out",script.name))?.map_err(|e|format!("Script {}: {e}",script.name))?;
    }
    Ok(raw)
}
#[derive(Default)]pub struct Extensions {text:String,path:String,message:String,observations:Vec<(String,String,String)>}
pub fn menu(ui:&mut egui::Ui,env:&mut Env,url:&str){
    let Some(target)=Target::from_url(url)else{return;};let package=crate::rules::current(env.shared).cfg.extensions.clone();if package.version!=1{return;}
    for tool in package.tools.iter().filter(|t|t.enabled&&crate::browser_auth::origin(&t.origin).is_some_and(|o|o==target.url())){if ui.button(format!("Extension: {}",tool.name)).clicked(){let text=tool.request.replace("{{host}}",&target.host_header()).replace("{{origin}}",&target.url()).replace("{{path}}",&http::url_path(url));env.actions.push(crate::Action::Repeater(target.clone(),http::to_wire(&text,true)));ui.close();}}
}
impl Extensions {
    pub fn observe(&mut self,package:&Package,url:&str,raw:&[u8]){
        if package.version!=1{return;}let decoded=Msg::parse(raw).decoded_body();let text=String::from_utf8_lossy(&decoded);
        for panel in package.panels.iter().filter(|p|p.enabled&&regex::Regex::new(&p.url_regex).is_ok_and(|r|r.is_match(url))){if let Ok(regex)=regex::Regex::new(&panel.response_regex){if let Some(c)=regex.captures(&text){let value=c.get(1).or_else(||c.get(0)).unwrap().as_str();self.observations.push((panel.name.clone(),url.into(),value[..value.floor_char_boundary(4096)].into()));}}}
        if self.observations.len()>1000{self.observations.drain(..self.observations.len()-1000);}
    }

    pub fn ui(&mut self,ui:&mut egui::Ui,package:&mut Package,_env:&mut Env){
        ui.collapsing("Extension panels",|ui|{for panel in &package.panels{if panel.enabled{ui.collapsing(&panel.name,|ui|{for(_,url,value)in self.observations.iter().filter(|(name,_,_)|name==&panel.name).rev().take(100){ui.label(url);ui.monospace(value);if ui.small_button("Copy").clicked(){ui.ctx().copy_text(value.clone());}}});}}});
        ui.label("Ferrite checks and scripts. JSON packages support passive/active checks and scoped proxy hooks. Burp JARs and BChecks are not compatible.");
        ui.label("Enabled scripts execute local commands. stdin: {version,phase,url,raw_base64}; stdout: {raw_base64}. Timeout: 3 seconds; output limit: 2 MiB.");
        if self.text.is_empty(){self.text=serde_json::to_string_pretty(package).unwrap_or_default();}
        ui.horizontal(|ui|{ui.add(egui::TextEdit::singleline(&mut self.path).hint_text("Package JSON path").desired_width(350.0));if ui.button("Read package").clicked(){match std::fs::read_to_string(&self.path){Ok(t)=>self.text=t,Err(e)=>self.message=e.to_string()}}if ui.button("Save package").clicked(){self.message=match crate::project::atomic_write(std::path::Path::new(&self.path),self.text.as_bytes()){Ok(())=>"Saved".into(),Err(e)=>e.to_string()};}});
        ui.horizontal(|ui|{if ui.button("Example").clicked(){self.text=r#"{"checks":[{"name":"Debug response","enabled":false,"url_regex":"^https://example\\.com/","response_regex":"(?i)debug enabled","severity":"Low"},{"name":"Exposed environment","enabled":false,"url_regex":"^https://example\\.com/","request":"GET /.env HTTP/1.1\r\nHost: {{host}}\r\nConnection: close\r\n\r\n","response_regex":"(?m)^(APP_KEY|DB_PASSWORD)=","status":200,"severity":"High","differential":true}],"scripts":[]}"#.into();}if ui.button("Apply package").clicked(){match serde_json::from_str::<Package>(&self.text).map_err(|e|e.to_string()).and_then(|p|{p.validate()?;Ok(p)}){Ok(p)=>{*package=p;self.message="Applied and saved in settings".into();},Err(e)=>self.message=e}}ui.label(&self.message);});
        egui::ScrollArea::vertical().show(ui,|ui|{ui.add(egui::TextEdit::multiline(&mut self.text).font(egui::TextStyle::Monospace).desired_rows(24).desired_width(f32::INFINITY));});
    }
}
#[cfg(test)]mod tests{use super::*;#[test]fn passive_checks_honor_enable_scope_status_and_body(){let p=Package{version:1,name:String::new(),tools:vec![],panels:vec![],checks:vec![Check{name:"secret".into(),enabled:true,url_regex:"^https://example\\.com/".into(),response_regex:"secret".into(),status:200,..Default::default()}],scripts:vec![]};p.validate().unwrap();assert_eq!(passive(&p,"https://example.com/",b"GET / HTTP/1.1\r\n\r\n",b"HTTP/1.1 200 OK\r\n\r\nsecret").len(),1);assert!(passive(&p,"https://other.com/",b"",b"HTTP/1.1 200 OK\r\n\r\nsecret").is_empty());}}
