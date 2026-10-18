//! Isolated Chromium/CDP runner for JavaScript discovery and DOM canary evidence.
use crate::{
    Env, Event,
    http::{self, Target, Upstream},
};
use eframe::egui;
use hudsucker::{
    futures::{SinkExt, StreamExt},
    tokio_tungstenite::{connect_async, tungstenite::Message},
};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Step {
    Navigate { url: String },
    Fill { selector: String, value: String },
    Click { selector: String },
    Wait { ms: u64 },
    AssertText { selector: String, text: String },
    PostMessage { data: Value },
}
async fn replay(
    cdp: &mut Cdp,
    steps: &[Step],
    scope: &crate::rules::Compiled,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if steps.len() > 100 {
        return Err("Browser workflows support at most 100 steps".into());
    }
    for (index, step) in steps.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("Browser replay stopped".into());
        }
        let result=match step {
            Step::Navigate{url}=>{
                let url=url::Url::parse(url).map_err(|e|e.to_string())?;
                if (url.origin()!=cdp.origin&&!cdp.allowed.contains(&url.origin()))||(url.origin()==cdp.origin&&!scope.in_scope(url.as_str()))||!url.username().is_empty()||url.password().is_some(){return Err("Workflow navigation must remain on the starting origin and in scope".into());}
                let nav=cdp.command("Page.navigate",json!({"url":url.as_str()})).await?;
                if let Some(e)=nav["errorText"].as_str(){return Err(e.into());}
                cdp.settle(300).await.map(|_|Value::Null)
            },
            Step::Wait{ms}=>cdp.eval(&format!("new Promise(resolve=>setTimeout(()=>resolve(true),{}))",ms.min(&10000))).await,
            Step::Fill{selector,value}=>cdp.eval(&format!(r#"(() => {{const e=document.querySelector({});if(!e)throw Error('Fill selector did not match');const p=e instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;const d=Object.getOwnPropertyDescriptor(p,'value');if(!d?.set)throw Error('Element cannot be filled');d.set.call(e,{});e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));return true;}})()"#,json!(selector),json!(value))).await,
            Step::Click{selector}=>{let r=cdp.eval(&format!("(() => {{const e=document.querySelector({});if(!e)throw Error('Click selector did not match');e.click();return true;}})()",json!(selector))).await;r?;cdp.settle(300).await.map(|_|Value::Null)},
            Step::AssertText{selector,text}=>cdp.eval(&format!("(() => {{const e=document.querySelector({});if(!e||!e.textContent.includes({}))throw Error('Text assertion failed');return true;}})()",json!(selector),json!(text))).await,
            Step::PostMessage{data}=>cdp.eval(&format!("window.postMessage({},location.origin);true",data)).await,
        };
        result.map_err(|e| format!("Workflow step {}: {e}", index + 1))?;
    }
    Ok(())
}
type Socket = hudsucker::tokio_tungstenite::WebSocketStream<
    hudsucker::tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;
struct Cdp {
    socket: Socket,
    id: u64,
    origin: url::Origin,
    headers: Vec<(String, String)>,
    recorded: Vec<Step>,
    allowed:HashSet<url::Origin>,
}
impl Cdp {
    async fn command(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.id += 1;
        let id = self.id;
        self.socket
            .send(Message::Text(
                json!({"id":id,"method":method,"params":params})
                    .to_string()
                    .into(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(20),async{
            loop {
                let message=self.socket.next().await.ok_or("Browser disconnected")?.map_err(|e|e.to_string())?;
                let Message::Text(text)=message else{continue};let v:Value=serde_json::from_str(&text).map_err(|e|e.to_string())?;
                if v["method"]=="Runtime.bindingCalled" && v["params"]["name"]=="__ferriteRecord" && self.recorded.len()<99 {
                    if let Some(step)=v["params"]["payload"].as_str().and_then(|text|serde_json::from_str::<Step>(text).ok()){self.recorded.push(step);}
                }
                if v["method"]=="Fetch.requestPaused"{
                    let request=&v["params"]["request"];let request_origin=url::Url::parse(request["url"].as_str().unwrap_or("")).ok().map(|u|u.origin());let allowed=request_origin.as_ref().is_some_and(|o|o==&self.origin||self.allowed.contains(o));
                    self.id+=1;
                    let (method,params)=if allowed{
                        let mut headers:Vec<Value>=request["headers"].as_object().into_iter().flatten().map(|(k,v)|json!({"name":k,"value":v.as_str().unwrap_or("")})).collect();
                        for(k,value)in self.headers.iter().filter(|_|request_origin.as_ref()==Some(&self.origin)){headers.retain(|h|!h["name"].as_str().unwrap_or("").eq_ignore_ascii_case(k));headers.push(json!({"name":k,"value":value}));}
                        ("Fetch.continueRequest",json!({"requestId":v["params"]["requestId"],"headers":headers}))
                    }else{("Fetch.failRequest",json!({"requestId":v["params"]["requestId"],"errorReason":"BlockedByClient"}))};
                    self.socket.send(Message::Text(json!({"id":self.id,"method":method,"params":params}).to_string().into())).await.map_err(|e|e.to_string())?;
                }
                if v["id"]==id {if v.get("error").is_some(){return Err(v["error"].to_string());}return Ok(v["result"].clone());}
            }
        }).await.map_err(|_|"Browser command timed out (check Proxy Intercept)".to_string())?
    }
    async fn settle(&mut self, ms: u64) -> Result<(), String> {
        let mut last = String::new();
        for _ in 0..5 {
            match self
                .eval(&format!(
                    "new Promise(resolve => setTimeout(() => resolve(location.href), {ms}))"
                ))
                .await
            {
                Ok(value) if value.as_str().is_some_and(|u| u != "about:blank") => return Ok(()),
                Ok(_) => {}
                Err(error) => last = error,
            }
        }
        Err(format!("Page did not settle: {last}"))
    }
    async fn eval(&mut self, expression: &str) -> Result<Value, String> {
        let r = self
            .command(
                "Runtime.evaluate",
                json!({"expression":expression,"returnByValue":true,"awaitPromise":true}),
            )
            .await?;
        if r.get("exceptionDetails").is_some() {
            return Err(r["exceptionDetails"].to_string());
        }
        Ok(r["result"]["value"].clone())
    }
}
struct Process {
    child: tokio::process::Child,
    profile: PathBuf,
}
impl Process {
    async fn start(addr: SocketAddr, visible: bool) -> Result<(Self, Socket), String> {
        let pem = std::fs::read_to_string(crate::proxy::config_dir().join("ca.key"))
            .map_err(|e| e.to_string())?;
        let fingerprint = crate::browser::ca_fingerprint(&pem).map_err(|e| e.to_string())?;
        Self::start_mode(addr, &fingerprint, visible).await
    }
    #[cfg(test)]
    async fn start_with_pin(addr: SocketAddr, fingerprint: &str) -> Result<(Self, Socket), String> {
        Self::start_mode(addr, fingerprint, false).await
    }
    async fn start_mode(
        addr: SocketAddr,
        fingerprint: &str,
        visible: bool,
    ) -> Result<(Self, Socket), String> {
        let profile = std::env::temp_dir().join(format!(
            "ferrite-browser-{}-{}",
            std::process::id(),
            crate::history::next_id()
        ));
        std::fs::create_dir(&profile).map_err(|e| e.to_string())?;
        let mut command = crate::browser::command(&profile, addr, &fingerprint);
        if !visible {
            command.arg("--headless");
        }
        command.args([
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-quic",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            "about:blank",
        ]);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let child = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut process = Self { child, profile };
        let result = async {
            let mut port = None;
            for _ in 0..100 {
                if let Ok(text) =
                    std::fs::read_to_string(process.profile.join("DevToolsActivePort"))
                {
                    port = text.lines().next().and_then(|p| p.parse::<u16>().ok());
                    if port.is_some() {
                        break;
                    }
                }
                if process
                    .child
                    .try_wait()
                    .map_err(|e| e.to_string())?
                    .is_some()
                {
                    return Err("Chromium exited before debugging became available".into());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let port = port.ok_or("Chromium debugging port did not become available")?;
            let target = Target::from_url(&format!("http://127.0.0.1:{port}")).unwrap();
            let reply = http::send(
                &target,
                format!(
                    "GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
                &Upstream::None,
            )
            .await?;
            let targets: Value =
                serde_json::from_slice(&http::Msg::parse(&reply.raw).decoded_body())
                    .map_err(|e| e.to_string())?;
            let ws = targets
                .as_array()
                .and_then(|t| t.iter().find(|t| t["type"] == "page"))
                .and_then(|t| t["webSocketDebuggerUrl"].as_str())
                .ok_or("No browser page")?;
            let (socket, _) = connect_async(ws).await.map_err(|e| e.to_string())?;
            Ok(socket)
        }
        .await;
        match result {
            Ok(socket) => Ok((process, socket)),
            Err(e) => {
                process.close().await;
                Err(e)
            }
        }
    }
    async fn close(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}
#[derive(Clone)]
pub struct Page {
    pub url: String,
    pub links: Vec<String>,
    pub evidence: Value,
}
pub enum Note {
    Page(Page),
    Status(String),
    Done,
}
#[derive(Default)]
pub struct BrowserLab {
    url: String,
    max_pages: usize,
    wait_ms: u64,
    submit: bool,
    probe: bool,
    headers: String,
    run: u64,
    cancel: Option<Arc<AtomicBool>>,
    pages: Vec<Page>,
    selected: usize,
    status: String,
    steps_text: String,
    steps_error: String,
    auth_text:String,export_session:bool,
}
impl BrowserLab {
    pub fn accepts(&self,run:u64)->bool{run==self.run}
    pub fn reset_project(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        let run = self.run + 1;
        *self = Self::default();
        self.run = run;
    }

    pub fn on_note(&mut self, run: u64, note: Note) {
        if run != self.run {
            return;
        }
        match note {
            Note::Page(p) => self.pages.push(p),
            Note::Status(s) => self.status = s,
            Note::Done => self.cancel = None,
        }
    }
    fn start(&mut self, env: &Env, record: bool) {
        let Ok(start) = url::Url::parse(&self.url) else {
            self.status = "Invalid HTTP(S) URL".into();
            return;
        };
        if !matches!(start.scheme(), "http" | "https")
            || Target::from_url(start.as_str()).is_none()
            || !start.username().is_empty()
            || start.password().is_some()
        {
            self.status = "Use an HTTP(S) URL without embedded credentials".into();
            return;
        }
        let scope = crate::rules::current(env.shared);
        if !scope.in_scope(start.as_str()) {
            self.status = "Start URL is outside scope".into();
            return;
        }
        let mut headers = Vec::new();
        for line in self.headers.lines().filter(|l| !l.trim().is_empty()) {
            let Some((k, v)) = line.split_once(':') else {
                self.status = "Headers need Name: value".into();
                return;
            };
            if ["host", "content-length", "connection", "transfer-encoding"]
                .contains(&k.to_ascii_lowercase().as_str())
                || v.contains('\r')
            {
                self.status = "Invalid custom header".into();
                return;
            }
            headers.push((k.to_string(), v.trim().to_string()));
        }
        let steps = scope.cfg.browser_steps.clone();
        let auth=scope.cfg.browser_auth.clone();if let Err(e)=auth.validate(){self.status=e;return;}
        let export_session=self.export_session;
        let mut origins=auth.origins.clone();origins.push(start.origin().ascii_serialization());
        let cookies:Vec<_>=origins.iter().flat_map(|o|env.jar.lock().unwrap().browser_cookies(o)).collect();
        let (run, max_pages, wait_ms, submit, probe) = (
            self.run + 1,
            self.max_pages.clamp(1, 200),
            self.wait_ms.clamp(100, 10000),
            self.submit,
            self.probe,
        );
        self.run = run;
        self.pages.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (addr, tx, ctx) = (env.listen_addr, env.tx.clone(), env.egui.clone());
        env.rt.spawn(async move{
            let notify=|note|{let _=tx.send(Event::BrowserLab{run,note});ctx.request_repaint();};
            let(mut process,socket)=match Process::start(addr,record).await{Ok(p)=>p,Err(e)=>{notify(Note::Status(e));notify(Note::Done);return;}};
            let result=async{
                let origin=start.origin();let mut cdp=Cdp{socket,id:0,origin:origin.clone(),headers,recorded:Vec::new(),allowed:origins.iter().filter_map(|o|url::Url::parse(o).ok().map(|u|u.origin())).collect()};
                cdp.command("Page.enable",json!({})).await?;
                cdp.command("Runtime.enable",json!({})).await?;
                cdp.command("Runtime.addBinding",json!({"name":"__ferriteRecord"})).await?;
                cdp.command("Network.enable",json!({})).await?;
                cdp.command("Fetch.enable",json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]})).await?;
                cdp.command("Network.setCookies",json!({"cookies":cookies})).await?;
                cdp.command("DOMStorage.enable",json!({})).await?;
                cdp.command("Page.addScriptToEvaluateOnNewDocument",json!({"source":auth.bootstrap()})).await?;
                cdp.command("Page.addScriptToEvaluateOnNewDocument",json!({"source":include_str!("../assets/dom-probe.js")})).await?;
                let mut queue=VecDeque::from([start.to_string()]);let mut seen=HashSet::new();
                while let Some(mut url)=queue.pop_front(){
                    if cancel.load(Ordering::Relaxed)||seen.len()>=max_pages{break;}
                    if !seen.insert(url.clone()){continue;}
                    if probe&&!record{let mut u=url::Url::parse(&url).map_err(|e|e.to_string())?;u.query_pairs_mut().append_pair("__proto__[ferrite_canary]","ferrite_canary").append_pair("constructor[prototype][ferrite_canary]","ferrite_canary");u.set_fragment(Some("ferrite_canary"));url=u.to_string();}
                    notify(Note::Status(format!("Rendering {url}")));
                    let nav=cdp.command("Page.navigate",json!({"url":url})).await?;
                    if let Some(error)=nav["errorText"].as_str(){return Err(error.to_string());}
                    // Runtime promise keeps servicing Fetch events while scripts and resources load.
                    cdp.settle(wait_ms).await?;
                    if record {
                        notify(Note::Status("Recording in Chromium. Use the page, then press Stop in Ferrite to save the workflow.".into()));
                        while !cancel.load(Ordering::Relaxed){if cdp.eval("new Promise(resolve=>setTimeout(()=>resolve(true),200))").await.is_err(){break;}}
                    }else if seen.len()==1{replay(&mut cdp,&steps,&scope,&cancel).await?;}
                    if submit&&!record{cdp.eval(r#"(() => { const f=[...document.forms].find(f=>new URL(f.action,location.href).origin===location.origin); if(!f)return false;for(const e of f.elements){if(e.name&&!e.value&&!['hidden','submit','button','checkbox','radio'].includes(e.type)){e.value=e.type==='email'?'ferrite@example.invalid':'ferrite_canary';}}f.requestSubmit();return true;})()"#).await?;cdp.settle(wait_ms).await?;}
                    let evidence_result=cdp.eval(r#"(() => ({url:location.href, links:[...document.querySelectorAll('a[href],iframe[src]')].map(e=>e.href||e.src),forms:[...document.forms].filter(f=>f.method.toLowerCase()==='get').map(f=>{let u=new URL(f.action||location.href);u.search=new URLSearchParams(new FormData(f)).toString();return u.href;}),events:window.__ferriteDOM||[],actions:window.__ferriteActions||[],prototype:({}).ferrite_canary||null}))()"#).await;
                    let mut evidence=match evidence_result{Ok(e)=>e,Err(_)if record=>json!({"url":start.as_str(),"links":[],"forms":[],"events":[],"recording":"Browser disconnected; recorded actions retained"}),Err(e)=>return Err(e)};
                    if record {let mut actions=vec![Step::Navigate{url:start.to_string()}];actions.extend(cdp.recorded.clone());evidence["actions"]=serde_json::to_value(actions).map_err(|e|e.to_string())?;}
                    let rendered=evidence["url"].as_str().unwrap_or(&url).to_string();
                    let links:Vec<_>=evidence["links"].as_array().into_iter().flatten().chain(evidence["forms"].as_array().into_iter().flatten()).filter_map(Value::as_str).filter_map(|u|crate::crawler::resolve(&rendered,u)).filter(|u|url::Url::parse(u).is_ok_and(|u|u.origin()==origin)&&scope.in_scope(u)).take(2000).collect();
                    for link in &links{if !seen.contains(link)&&queue.len()<2000{queue.push_back(link.clone());}}
                    notify(Note::Page(Page{url:rendered,links,evidence}));
                    if export_session{
                        let mut saved=auth.clone();
                        for origin in &origins{
                            let mut state=crate::browser_auth::Storage::default();for local in [true,false]{
                                if let Ok(items)=cdp.command("DOMStorage.getDOMStorageItems",json!({"storageId":{"securityOrigin":origin,"isLocalStorage":local}})).await{
                                    for pair in items["entries"].as_array().into_iter().flatten().take(500){if let(Some(k),Some(v))=(pair[0].as_str(),pair[1].as_str()){if k!="__ferrite_bootstrap"&&k.len()<=4096&&v.len()<=65536{if local{state.local.insert(k.into(),v.into());}else{state.session.insert(k.into(),v.into());}}}}
                                }
                            }
                            saved.storage.insert(origin.clone(),state);
                        }
                        let cookies=cdp.command("Network.getAllCookies",json!({})).await?["cookies"].clone();
                        saved.validate()?;let _=tx.send(Event::BrowserSession{run,auth:saved,cookies});ctx.request_repaint();
                    }
                }
                Ok::<_,String>(())
            }.await;
            process.close().await;
            notify(Note::Status(match result{Ok(())=>"Browser run finished; traffic is in Proxy history".into(),Err(e)=>e}));notify(Note::Done);
        });
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if self.url.is_empty() {
            self.url = "https://example.com/#ferrite_canary".into();
            self.max_pages = 1;
            self.wait_ms = 1000;
        }
        ui.label("JavaScript discovery and DOM traces in isolated Chromium. Requests stay on the starting origin and pass through Ferrite. Use ferrite_canary in input URLs to trace dangerous DOM sinks.");
        ui.horizontal(|ui| {
            ui.label("URL");
            ui.add(egui::TextEdit::singleline(&mut self.url).desired_width(500.0));
            ui.label("Pages");
            ui.add(egui::DragValue::new(&mut self.max_pages).range(1..=200));
            ui.label("Wait ms");
            ui.add(egui::DragValue::new(&mut self.wait_ms).range(100..=10000));
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.submit, "Submit first same-origin form per page");
            ui.checkbox(&mut self.probe, "Probe prototype pollution");
        });
        ui.collapsing("Authentication headers",|ui|{ui.label("Session jar cookies are copied into this isolated browser. Headers are restricted to the starting origin.");ui.add(egui::TextEdit::multiline(&mut self.headers).desired_rows(3).desired_width(f32::INFINITY));});
        ui.collapsing("SSO and browser session",|ui|{
            ui.checkbox(&mut self.export_session,"Export cookies and browser storage to this project after the run");
            ui.label("Explicit SSO origins permit cross-origin login. Custom authentication headers remain on the starting origin. Saved token mappings can feed manual tools using session cookies.");
            if self.auth_text.is_empty(){self.auth_text=serde_json::to_string_pretty(&crate::rules::current(env.shared).cfg.browser_auth).unwrap_or_default();}
            ui.add(egui::TextEdit::multiline(&mut self.auth_text).desired_rows(6));
            if ui.button("Apply browser authentication").clicked(){match serde_json::from_str::<crate::browser_auth::Auth>(&self.auth_text).map_err(|e|e.to_string()).and_then(|a|{a.validate()?;Ok(a)}){Ok(a)=>{env.actions.push(crate::Action::BrowserAuth(a));self.steps_error="Browser authentication saved".into();},Err(e)=>self.steps_error=e}}
        });
        ui.collapsing("Workflow replay",|ui|{
            ui.label("JSON steps: navigate, fill, click, wait, assert_text, post_message. Replayed once on the first page. Saved with the project. Recordings can contain credentials.");
            if self.steps_text.is_empty(){self.steps_text=serde_json::to_string_pretty(&crate::rules::current(env.shared).cfg.browser_steps).unwrap_or_default();}
            ui.add(egui::TextEdit::multiline(&mut self.steps_text).desired_rows(6).desired_width(f32::INFINITY));
            if ui.button("Apply workflow").clicked(){match serde_json::from_str::<Vec<Step>>(&self.steps_text){Ok(steps) if steps.len()<=100=>{env.actions.push(crate::Action::BrowserSteps(steps));self.steps_error="Workflow saved".into();},Ok(_)=>self.steps_error="At most 100 steps".into(),Err(e)=>self.steps_error=e.to_string()}}
            ui.label(&self.steps_error);
        });
        ui.horizontal(|ui| {
            if let Some(cancel) = &self.cancel {
                if ui.button("Stop").clicked() {
                    cancel.store(true, Ordering::Relaxed);
                }
            } else if ui.button("Render / inspect").clicked() {
                self.start(env, false);
            }
            if self.cancel.is_none() && ui.button("Record in Chromium").clicked() {
                self.start(env, true);
            }
            ui.label(&self.status);
        });
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                for (i, p) in self.pages.iter().enumerate() {
                    let count = p.evidence["events"].as_array().map_or(0, Vec::len);
                    ui.selectable_value(
                        &mut self.selected,
                        i,
                        format!("{} · {} links · {count} observations", p.url, p.links.len()),
                    );
                }
            });
        if let Some(page) = self.pages.get(self.selected) {
            ui.horizontal(|ui| {
                if ui.button("Copy recorded actions as workflow").clicked() {
                    ui.ctx().copy_text(
                        serde_json::to_string_pretty(&page.evidence["actions"]).unwrap_or_default(),
                    );
                }
                if ui.button("Copy observations").clicked() {
                    ui.ctx().copy_text(
                        serde_json::to_string_pretty(&page.evidence).unwrap_or_default(),
                    );
                }
                if ui.button("Add observations to Organizer").clicked() {
                    env.actions.push(crate::Action::Organize(
                        page.url.clone(),
                        format!(
                            "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            http::url_path(&page.url),
                            Target::from_url(&page.url).map_or(String::new(), |t| t.host_header())
                        )
                        .into_bytes(),
                        Some(serde_json::to_vec_pretty(&page.evidence).unwrap_or_default()),
                    ));
                }
            });
            ui.weak("Observations need manual validation. A canary reaching a sink or a duplicate element name alone is not proof of an exploitable vulnerability.");
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(serde_json::to_string_pretty(&page.evidence).unwrap_or_default());
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires installed Chromium and local socket access"]
    async fn chromium_executes_javascript_and_records_dom_canary_through_proxy() {
        let (target, _seen, server) = crate::features_tests::fixture().await;
        let (proxy, proxy_task) = crate::features_tests::start_proxy(Default::default()).await;
        let (mut process, socket) = Process::start_with_pin(proxy, "test").await.unwrap();
        let origin = url::Url::parse(&target.url()).unwrap().origin();
        let mut cdp = Cdp {
            socket,
            id: 0,
            origin,
            headers: vec![],
            recorded: vec![],allowed:Default::default(),
        };
        let result=async {
            cdp.command("Page.enable",json!({})).await?;
            cdp.command("Fetch.enable",json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]})).await?;
            cdp.command("Page.addScriptToEvaluateOnNewDocument",json!({"source":include_str!("../assets/dom-probe.js")})).await?;
            cdp.command("Page.navigate",json!({"url":format!("{}/dom#ferrite_canary",target.url())})).await?;
            cdp.settle(500).await?;
            cdp.eval("({events:window.__ferriteDOM,links:[...document.querySelectorAll('a')].map(a=>a.href)})").await
        }.await;
        process.close().await;
        proxy_task.abort();
        server.abort();
        let data = result.unwrap();
        assert!(
            data["links"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().ends_with("/dynamic"))
        );
        assert!(
            data["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["sink"] == "innerHTML")
        );
    }
}

#[cfg(test)]
#[path = "tests/browser_lab_regression.rs"]
mod robust_browser_tests;
