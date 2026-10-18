//! Explicit identity replay. Every variant has an independent cookie jar and no login macros.
use crate::{
    Env,
    http::{self, Msg, Target},
    session,
};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::sync::mpsc;

#[derive(Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Identity {
    pub name: String,
    pub origin: String,
    pub headers: String,
    pub cookies: session::Jar,
}

pub fn identity_editor(ui: &mut egui::Ui, identities: &mut Vec<Identity>, jar: &session::Shared) {
    ui.collapsing("User identities", |ui| {
        ui.label("Set an exact origin, enter authentication headers, and snapshot the current cookie jar for each user. Saved with this project.");
        let mut remove = None;
        for (i, identity) in identities.iter_mut().enumerate() {
            ui.push_id(i, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut identity.name).hint_text("User / role").desired_width(140.0));
                    ui.add(egui::TextEdit::singleline(&mut identity.origin).hint_text("https://app.example.com").desired_width(250.0));
                    if ui.button("Snapshot cookies").clicked() { identity.cookies = jar.lock().unwrap().clone(); }
                    if ui.button("Delete").clicked() { remove = Some(i); }
                });
                ui.add(egui::TextEdit::multiline(&mut identity.headers).hint_text("Authorization: Bearer ...\nX-CSRF-Token: ...").desired_rows(2));
            });
        }
        if let Some(i) = remove { identities.remove(i); }
        if identities.len() < 20 && ui.button("Add identity").clicked() {
            identities.push(Identity { name: format!("User {}", identities.len()+1), ..Default::default() });
        }
    });
}

fn variant(
    target: &Target,
    raw: &[u8],
    identity: Option<&Identity>,
    extra: &[String],
) -> Result<Vec<u8>, String> {
    let mut msg = Msg::parse(raw);
    // Strip every configured identity header from the source so variants cannot inherit another user's credentials.
    msg.headers.retain(|(key, _)| {
        ![
            "cookie",
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-csrf-token",
        ]
        .iter()
        .any(|x| key.eq_ignore_ascii_case(x))
            && !extra.iter().any(|x| key.eq_ignore_ascii_case(x))
    });
    let Some(identity) = identity else {
        return Ok(msg.render());
    };
    let origin =
        url::Url::parse(&identity.origin).map_err(|_| "Identity needs a valid exact origin")?;
    if origin.origin().ascii_serialization() != target.url()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err("Identity origin must exactly match the request origin".into());
    }
    for line in identity.headers.lines().filter(|l| !l.trim().is_empty()) {
        let (key, value) = line
            .split_once(':')
            .ok_or("Use Name: value for identity headers")?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || key.bytes().any(|c| !c.is_ascii_alphanumeric() && c != b'-')
            || value.contains(['\r', '\n'])
            || [
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "proxy-authorization",
            ]
            .iter()
            .any(|x| key.eq_ignore_ascii_case(x))
        {
            return Err("Invalid identity header".into());
        }
        msg.set_header(key, value.to_string());
    }
    let mut jar = session::Jar::default();
    jar.restore(identity.cookies.clone());
    Ok(jar.apply(target, &msg.render()))
}

#[derive(Clone)]
struct Case { target:Target, raw:Vec<u8>, label:String }
#[derive(Default)]
struct Objects {location:String,name:String,values:String}
fn mutate(raw:&[u8],objects:&Objects,value:&str)->Result<Vec<u8>,String>{
    let mut m=Msg::parse(raw);
    let encode=|v:&str|percent_encoding::utf8_percent_encode(v,percent_encoding::NON_ALPHANUMERIC).to_string();
    let replace=|pairs:&str|->Result<String,String>{let mut found=false;let out=pairs.split('&').map(|p|{let(k,_)=p.split_once('=').unwrap_or((p,""));if percent_encoding::percent_decode_str(k).decode_utf8_lossy()==objects.name{found=true;format!("{k}={}",encode(value))}else{p.into()}}).collect::<Vec<_>>().join("&");if found{Ok(out)}else{Err("Object parameter was not found".into())}};
    match objects.location.as_str(){
        "JSON"=>{let mut json:serde_json::Value=serde_json::from_slice(&m.body).map_err(|e|e.to_string())?;let slot=json.pointer_mut(&objects.name).ok_or("JSON pointer was not found")?;*slot=if slot.is_number(){let value=serde_json::from_str::<serde_json::Value>(value).map_err(|_|"Object ID must be a JSON number")?;if !value.is_number(){return Err("Object ID must be a JSON number".into());}value}else{serde_json::Value::String(value.into())};m.body=serde_json::to_vec(&json).map_err(|e|e.to_string())?;},
        "Form"=>{if !m.header("content-type").is_some_and(|c|c.starts_with("application/x-www-form-urlencoded")){return Err("Use a URL-encoded form request".into());}m.body=replace(&String::from_utf8_lossy(&m.body))?.into_bytes();},
        mode=>{let mut words:Vec<_>=m.first.split_whitespace().map(str::to_string).collect();let path=words.get_mut(1).ok_or("Invalid request line")?;
            if mode=="Path"{let index=objects.name.parse::<usize>().map_err(|_|"Path uses a zero-based nonempty segment index")?;let(p,q)=path.split_once('?').unwrap_or((path,""));let mut parts:Vec<_>=p.split('/').map(str::to_string).collect();let slot=parts.iter_mut().filter(|s|!s.is_empty()).nth(index).ok_or("Path segment was not found")?;*slot=encode(value);*path=format!("{}{}",parts.join("/"),if q.is_empty(){String::new()}else{format!("?{q}")});}
            else{let(p,q)=path.split_once('?').ok_or("No query parameters")?;*path=format!("{p}?{}",replace(q)?);}
            m.first=words.join(" ");
        },
    }
    m.fix_content_length();Ok(m.render())
}
struct ResultRow {
    case:usize, url:String, similarity:Option<f32>, body_len:usize,

    name: String,
    request: Vec<u8>,
    reply: Result<http::Reply, String>,
}
#[derive(Default)]
pub struct Authorization {
    target: Option<Target>,
    request: String,
    rows: Vec<ResultRow>,
    selected: usize,
    task: Option<tokio::task::JoinHandle<()>>,
    rx: Option<mpsc::Receiver<ResultRow>>,
    allow_writes: bool,
    status: String,
    cases:Vec<Case>, objects:Objects, use_batch:bool,
}
impl Drop for Authorization {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Authorization {
    pub fn load(&mut self, target: Target, raw: Vec<u8>) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.rx = None;
        self.rows.clear();
        self.selected = 0;
        self.request = crate::repeater::as_http1(&target, &raw);
        self.target = Some(target);
    }
    pub fn queue(&mut self,requests:Vec<(Target,Vec<u8>)>){
        let mut bytes:usize=self.cases.iter().map(|c|c.raw.len()).sum();
        for(target,raw)in requests{
            if self.cases.len()>=100||bytes+raw.len()>crate::retention::BYTES{break;}
            if self.cases.iter().any(|c|c.target.url()==target.url()&&c.raw==raw){continue;}
            let label=Msg::parse(&raw).first;bytes+=raw.len();self.cases.push(Case{target,raw,label});
        }
        self.use_batch=true;self.status=format!("{} requests queued; nothing sent yet",self.cases.len());
    }
    fn start(&mut self, env: &Env) {
        let mut cases=if self.use_batch{self.cases.clone()}else{let Some(target)=self.target.clone()else{return;};vec![Case{target,raw:http::to_wire(&self.request,true),label:"Current request".into()}]};
        if cases.is_empty(){self.status="Queue requests first".into();return;}
        if !self.objects.values.trim().is_empty(){
            let mut generated=Vec::new();for case in &cases{for value in self.objects.values.lines().filter(|s|!s.is_empty()).take(20){match mutate(&case.raw,&self.objects,value){Ok(raw)=>generated.push(Case{target:case.target.clone(),raw,label:format!("{} [object {value}]",case.label)}),Err(e)=>{self.status=format!("{}: {e}",case.label);return;}}}}
            cases.extend(generated);
        }
        if !self.allow_writes&&cases.iter().any(|c|!matches!(Msg::parse(&c.raw).first.split_whitespace().next(),Some("GET"|"HEAD"|"OPTIONS"))){self.status="Enable replay of state-changing methods to run this batch".into();return;}
        let identities = crate::rules::current(env.shared).cfg.identities.clone();
        let extra: Vec<String> = identities
            .iter()
            .flat_map(|i| i.headers.lines())
            .filter_map(|l| l.split_once(':').map(|(k, _)| k.trim().to_string()))
            .filter(|k| {
                !["host", "content-length", "transfer-encoding", "connection"]
                    .iter()
                    .any(|name| k.eq_ignore_ascii_case(name))
            })
            .collect();
        let count:usize=cases.iter().map(|c|2+identities.iter().filter(|i|url::Url::parse(&i.origin).is_ok_and(|u|u.origin().ascii_serialization()==c.target.url())).take(20).count()).sum();
        if count>2000{self.status="Batch exceeds 2,000 requests; reduce endpoints, identities or object IDs".into();return;}
        // Validate all variants before starting a batch, so malformed credentials never cause a partial replay.
        for case in &cases{for identity in identities.iter().filter(|i|url::Url::parse(&i.origin).is_ok_and(|u|u.origin().ascii_serialization()==case.target.url())).take(20){if let Err(e)=variant(&case.target,&case.raw,Some(identity),&extra){self.status=e;return;}}}
        self.rows.clear();
        self.selected = 0;
        self.status = "Replaying identities…".into();
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        let upstream = env.upstream();
        let ctx = env.egui.clone();
        self.task = Some(env.rt.spawn(async move {
            for (case_id,case) in cases.into_iter().enumerate(){
                let mut jobs=vec![("Original".into(),case.raw.clone()),("Anonymous".into(),variant(&case.target,&case.raw,None,&extra).unwrap())];
                for identity in identities.iter().filter(|i|url::Url::parse(&i.origin).is_ok_and(|u|u.origin().ascii_serialization()==case.target.url())).take(20){jobs.push((identity.name.clone(),variant(&case.target,&case.raw,Some(identity),&extra).unwrap()));}
                let mut baseline=None;
                for(name,request)in jobs{
                    let reply=http::send(&case.target,&request,&upstream).await;
                    let(body_len,score)=reply.as_ref().map(|r|{let body=Msg::parse(&r.raw).decoded_body();let score=baseline.as_ref().map(|base:&Vec<u8>|similarity(base,&body));if baseline.is_none(){baseline=Some(body.clone());}(body.len(),score)}).unwrap_or((0,None));
                    let reply=reply.map(|mut reply|{reply.raw=crate::retention::clip(reply.raw);reply});
                    if tx.send(ResultRow{case:case_id,url:format!("{} · {}",case.target.url(),case.label),similarity:score,body_len,name,request:crate::retention::clip(request),reply}).is_err(){return;}ctx.request_repaint();
                }
            }
        }));
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env) {
        if let Some(rx) = &self.rx {
            self.rows.extend(rx.try_iter());
            let mut bytes=0;for row in self.rows.iter_mut().rev(){bytes+=row.request.len()+row.reply.as_ref().map_or(0,|r|r.raw.len());if bytes>crate::retention::BYTES{row.request.clear();if let Ok(r)=&mut row.reply{r.raw.clear();}}}
        }
        if self.task.as_ref().is_some_and(|t| t.is_finished()) {
            self.task = None;
            self.status =
                "Replay finished. Similar responses need manual authorization review.".into();
        }
        ui.label("Compare the original request with anonymous and saved user identities. Configure identities in Sessions. Cookies and authentication headers are isolated for each replay.");
        ui.horizontal(|ui|{
            ui.checkbox(&mut self.use_batch,format!("Batch ({} endpoints)",self.cases.len()));
            if ui.button("Queue in-scope history").clicked(){env.actions.push(crate::Action::AuthHistory(None));}
            if ui.button("Queue current").clicked(){if let Some(target)=&self.target{self.queue(vec![(target.clone(),http::to_wire(&self.request,true))]);}}
            if self.task.is_none()&&ui.button("Clear queue").clicked(){self.cases.clear();}
        });
        ui.collapsing("Object-ID variants",|ui|{
            ui.label("Adds variants of every endpoint before comparing identities. Query/form parameter name, zero-based path segment index, or JSON pointer. At most 20 values.");
            egui::ComboBox::from_id_salt("object_location").selected_text(if self.objects.location.is_empty(){"Query"}else{&self.objects.location}).show_ui(ui,|ui|{for location in ["Query","Form","Path","JSON"]{ui.selectable_value(&mut self.objects.location,location.into(),location);}});
            ui.text_edit_singleline(&mut self.objects.name);ui.add(egui::TextEdit::multiline(&mut self.objects.values).desired_rows(3).hint_text("One object ID per line; empty disables variants"));
        });
        if self.target.is_none() && self.cases.is_empty() {
            ui.weak("Right-click a request → Test authorization.");
            return;
        }
        ui.horizontal(|ui| {
            if self.task.is_none() {
                if ui.button("Compare identities").clicked() {
                    self.start(env);
                }
            } else if ui.button("Stop").clicked() {
                if let Some(t) = self.task.take() {
                    t.abort();
                }
                self.status = "Stopped; active requests may have reached the server".into();
            }
            ui.checkbox(&mut self.allow_writes, "Replay state-changing methods");
            ui.label(&self.status);
        });
        ui.collapsing("Request", |ui| {
            crate::editor(ui, "authorization_request", &mut self.request);
        });
        for (i, row) in self.rows.iter().enumerate() {
            let label = match &row.reply {
                Ok(r) => {
                    let review=row.name!="Original"&&(200..300).contains(&r.status)&&row.body_len>0&&row.similarity.is_some_and(|score|score>=0.95);
                    format!("{} · {} · {} · {} bytes · {:.0}% similarity{}",row.url,row.name,r.status,row.body_len,row.similarity.unwrap_or(1.0)*100.0,if review{" · REVIEW similar successful response"}else{""})
                }
                Err(e) => format!("{} · {e}", row.name),
            };
            ui.selectable_value(&mut self.selected, i, label);
        }
        if let Some(row) = self.rows.get(self.selected) {
            if let Ok(reply) = &row.reply {
                if ui.button("Save comparison evidence to Organizer").clicked() {
                    env.actions.push(crate::Action::Organize(
                        format!(
                            "{}{}",
                            Target::from_url(&row.url.split(" · ").next().unwrap_or("")).map_or(String::new(),|t|t.url()),
                            http::Msg::parse(&row.request)
                                .first
                                .split_whitespace()
                                .nth(1)
                                .filter(|p| p.starts_with('/'))
                                .unwrap_or("/")
                        ),
                        row.request.clone(),
                        Some(reply.raw.clone()),
                    ));
                }
                if let Some(base) = self.rows.iter().find(|r|r.case==row.case&&r.name=="Original").and_then(|r|r.reply.as_ref().ok()) {
                    let a = Msg::parse(&base.raw).decoded_body();
                    let b = Msg::parse(&reply.raw).decoded_body();
                    let a = String::from_utf8_lossy(&a[..a.len().min(64 * 1024)]);
                    let b = String::from_utf8_lossy(&b[..b.len().min(64 * 1024)]);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.monospace(
                            similar::TextDiff::configure()
                                .timeout(std::time::Duration::from_millis(100))
                                .diff_lines(&a, &b)
                                .unified_diff()
                                .header("original", "selected")
                                .to_string(),
                        );
                    });
                }
            }
        }
    }
}
fn similarity(a: &[u8], b: &[u8]) -> f32 {
    if a == b {
        return 1.0;
    }
    let n = a.len().max(b.len());
    if n == 0 {
        return 1.0;
    }
    a.iter().zip(b).filter(|(x, y)| x == y).count() as f32 / n as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identities_strip_inherited_credentials_and_enforce_origin() {
        let t = Target::from_url("https://example.com/").unwrap();
        let raw=b"GET / HTTP/1.1\r\nAuthorization: Bearer admin\r\nCookie: sid=admin\r\nX-Token: old\r\nHost: example.com\r\n\r\n";
        let anon = Msg::parse(&variant(&t, raw, None, &["X-Token".into()]).unwrap());
        assert!(anon.header("cookie").is_none());
        assert!(anon.header("authorization").is_none());
        assert!(anon.header("x-token").is_none());
        let mut id = Identity {
            origin: t.url(),
            headers: "Authorization: Bearer user".into(),
            ..Default::default()
        };
        id.cookies
            .set_cookie("https://example.com/", "sid=user; Secure; Path=/")
            .unwrap();
        let r = Msg::parse(&variant(&t, raw, Some(&id), &["X-Token".into()]).unwrap());
        assert_eq!(r.header("authorization"), Some("Bearer user"));
        assert_eq!(r.header("cookie"), Some("sid=user"));
        id.origin = "https://elsewhere.example".into();
        assert!(variant(&t, raw, Some(&id), &[]).is_err());
    }
    #[test]
    fn similarity_handles_binary_and_empty() {
        assert_eq!(similarity(b"", b""), 1.0);
        assert_eq!(similarity(&[0, 255], &[0, 1]), 0.5);
    }
}

#[cfg(test)]
mod wire_regressions {
    use super::*;
    use std::sync::{Arc, RwLock};
    #[tokio::test]
    async fn comparison_keeps_original_anonymous_and_user_credentials_separate() {
        let server = crate::robust_tests::fixture(|raw| {
            let msg = Msg::parse(raw);
            let body = match msg.header("authorization") {
                Some("Bearer admin") => b"admin data".as_slice(),
                Some("Bearer user") => b"user data",
                _ => b"denied",
            };
            crate::robust_tests::Reply::body(
                if body == b"denied" { 403 } else { 200 },
                &[("Set-Cookie", "sid=response; Path=/")],
                body,
            )
        })
        .await;
        let identity = Identity {
            name: "User".into(),
            origin: server.target.url(),
            headers: "Authorization: Bearer user".into(),
            ..Default::default()
        };
        let cfg = crate::rules::Config {
            identities: vec![identity],
            ..Default::default()
        };
        let shared = Arc::new(RwLock::new(Arc::new(crate::rules::Compiled::new(cfg))));
        let jar: session::Shared = Arc::default();
        jar.lock()
            .unwrap()
            .set_cookie(&server.target.url(), "sid=global; Path=/")
            .unwrap();
        let (tx, _rx) = mpsc::channel();
        let ctx = egui::Context::default();
        let mut actions = vec![];
        let env = Env {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            rt: &tokio::runtime::Handle::current(),
            tx: &tx,
            egui: &ctx,
            shared: &shared,
            jar: &jar,
            actions: &mut actions,
        };
        let mut tool = Authorization::default();
        tool.load(server.target.clone(),format!("GET /private HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer admin\r\nCookie: sid=admin\r\nX-Api-Key: admin\r\n\r\n",server.target.host_header()).into_bytes());
        tool.start(&env);
        tokio::time::timeout(crate::robust_tests::DEADLINE, async {
            while !tool.task.as_ref().unwrap().is_finished() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let rows: Vec<_> = tool.rx.as_ref().unwrap().try_iter().collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].reply.as_ref().unwrap().status, 200);
        assert_eq!(rows[1].reply.as_ref().unwrap().status, 403);
        assert_eq!(rows[2].reply.as_ref().unwrap().status, 200);
        for row in &rows[1..] {
            let m = Msg::parse(&row.request);
            assert!(m.header("cookie").is_none());
            assert!(m.header("x-api-key").is_none());
        }
        assert_eq!(
            Msg::parse(
                &jar.lock()
                    .unwrap()
                    .apply(&server.target, b"GET / HTTP/1.1\r\n\r\n")
            )
            .header("cookie"),
            Some("sid=global")
        );
        tool.load(
            server.target.clone(),
            b"POST /delete HTTP/1.1\r\n\r\n".to_vec(),
        );
        tool.start(&env);
        assert!(tool.task.is_none());
        assert!(tool.status.contains("state-changing"));
        assert_eq!(server.seen.lock().unwrap().len(), 3);
    }
}

#[cfg(test)]mod batch_tests{
    use super::*;
    #[test]fn object_variants_preserve_siblings_encoding_and_json_types(){
        let mut objects=Objects{location:"Query".into(),name:"id".into(),values:String::new()};let raw=b"GET /users/1?id=1&other=keep HTTP/1.1\r\nHost: app.test\r\n\r\n";assert!(Msg::parse(&mutate(raw,&objects,"a/b").unwrap()).first.contains("id=a%2Fb&other=keep"));
        objects.location="Path".into();objects.name="1".into();assert!(Msg::parse(&mutate(raw,&objects,"2/3").unwrap()).first.starts_with("GET /users/2%2F3?id=1"));
        objects.location="JSON".into();objects.name="/user/id".into();let raw=b"POST / HTTP/1.1\r\nContent-Length: 31\r\n\r\n{\"user\":{\"id\":1},\"other\":true}";let m=Msg::parse(&mutate(raw,&objects,"23").unwrap());let value:serde_json::Value=serde_json::from_slice(&m.body).unwrap();assert_eq!(value["user"]["id"],23);assert_eq!(value["other"],true);assert!(mutate(raw,&objects,"not-a-number").is_err());
    }
    #[tokio::test]async fn batch_matrix_has_independent_baselines_per_endpoint_and_object(){
        use std::sync::{Arc,RwLock};
        let server=crate::robust_tests::fixture(|raw|{let m=Msg::parse(raw);crate::robust_tests::Reply::body(200,&[],m.first.as_bytes())}).await;
        let shared=Arc::new(RwLock::new(Arc::new(crate::rules::Compiled::new(Default::default()))));let jar=Arc::default();let(tx,_)=mpsc::channel();let ctx=egui::Context::default();let mut actions=vec![];
        let env=Env{listen_addr:"127.0.0.1:8080".parse().unwrap(),rt:&tokio::runtime::Handle::current(),tx:&tx,egui:&ctx,shared:&shared,jar:&jar,actions:&mut actions};
        let mut tool=Authorization::default();tool.queue(["/a?id=1","/b?id=1"].iter().map(|p|(server.target.clone(),crate::robust_tests::request(&server.target,"GET",p,b""))).collect());tool.objects=Objects{location:"Query".into(),name:"id".into(),values:"2\n3".into()};tool.start(&env);
        tokio::time::timeout(crate::robust_tests::DEADLINE,async{while !tool.task.as_ref().unwrap().is_finished(){tokio::time::sleep(std::time::Duration::from_millis(5)).await;}}).await.unwrap();let rows:Vec<_>=tool.rx.as_ref().unwrap().try_iter().collect();assert_eq!(rows.len(),12);assert_eq!(rows.iter().filter(|r|r.name=="Original").count(),6);assert!(rows.iter().filter(|r|r.name=="Anonymous").all(|r|r.similarity==Some(1.0)));assert_eq!(server.seen.lock().unwrap().len(),12);
    }
}
