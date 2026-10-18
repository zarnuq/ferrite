//! Local HTTP/DNS callback collector. Public reachability/delegation is user configured.
use crate::{Env, Event};
use eframe::egui;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone,serde::Serialize,serde::Deserialize)]
pub struct Interaction {
    pub time: u64,
    pub protocol: String,
    pub peer: String,
    pub payload: String,
}
pub enum Note {
    Endpoint(String),
    Session(Vec<u8>),
    Interaction(Interaction),
    Status(String),
    Done,
}
#[derive(Default)]
pub struct Callbacks {
    http: String,
    dns: String,
    base: String,
    poll: String,
    auth: String,
    tokens: Vec<String>,
    probes: Vec<Probe>,
    interactions: Vec<Interaction>,
    status: String,
    run: u64,
    cancel: Option<Arc<AtomicBool>>,
    selected: usize,
    binary: String,
    server: String,
    session:Vec<u8>,
}
#[derive(Clone,Default,serde::Serialize,serde::Deserialize)]#[serde(default)]
pub struct Saved{pub binary:String,pub server:String,pub session:Vec<u8>,pub base:String,pub probes:Vec<Probe>,pub tokens:Vec<String>,pub interactions:Vec<Interaction>}
pub(crate) fn payload(base: &str, token: &str) -> String {
    if base.contains("{{token}}") {
        base.replace("{{token}}", token)
    } else {
        format!("{}/{token}", base.trim_end_matches('/'))
    }
}
pub(crate) fn token() -> Result<String, String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| e.to_string())?;
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
pub struct Probe {
    pub token: String,
    pub url: String,
    pub request: Vec<u8>,
    pub kind: String,
}
fn dns_question(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 12 || u16::from_be_bytes([data[4], data[5]]) != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let n = *data.get(pos)? as usize;
        pos += 1;
        if n == 0 {
            break;
        }
        if n > 63 {
            return None;
        }
        let b = data.get(pos..pos + n)?;
        labels.push(String::from_utf8_lossy(b).into_owned());
        pos += n;
        if pos > 267 {
            return None;
        }
    }
    data.get(pos..pos + 4)?;
    Some((labels.join("."), pos + 4))
}
impl Callbacks {
    pub fn saved(&self)->Saved{Saved{binary:self.binary.clone(),server:self.server.clone(),session:self.session.clone(),base:self.base.clone(),probes:self.probes.clone(),tokens:self.tokens.clone(),interactions:self.interactions.clone()}}
    pub fn restore(&mut self,saved:Saved){self.reset_project();self.binary=saved.binary;self.server=saved.server;self.session=saved.session.into_iter().take(65536).collect();self.base=saved.base;self.probes=saved.probes.into_iter().take(1000).collect();self.tokens=saved.tokens.into_iter().take(1000).collect();self.interactions=saved.interactions.into_iter().take(2000).collect();self.status="Callback session restored; click Start Interactsh to resume polling".into();}

    pub fn accepts(&self, run: u64) -> bool {
        run == self.run
    }
    fn start_interactsh(&mut self, env: &Env) {
        self.run += 1;
        let run = self.run;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (binary, server,session) = (self.binary.clone(), self.server.clone(),self.session.clone());
        let (tx, ctx) = (env.tx.clone(), env.egui.clone());
        env.rt.spawn(async move {
            let notify = |note| {
                let _ = tx.send(Event::Callback { run, note });
                ctx.request_repaint();
            };
            if let Err(e) = crate::interactsh::run_saved(binary, server,session,cancel, &notify).await {
                notify(Note::Status(e));
            }
            notify(Note::Done);
        });
    }
    pub fn reset_project(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.run += 1;
        self.session.clear();
        self.auth.clear();
        self.base.clear();
        self.poll.clear();
        self.cancel = None;
        self.tokens.clear();
        self.probes.clear();
        self.interactions.clear();
    }

    pub fn register(&mut self, probe: Probe) {
        self.tokens.push(probe.token.clone());
        self.probes.push(probe);
        if self.tokens.len() > 1000 {
            self.tokens.remove(0);
        }
        if self.probes.len() > 1000 {
            self.probes.remove(0);
        }
    }
    pub fn issue(&self, interaction: &Interaction) -> Option<crate::scanner::Issue> {
        if !matches!(interaction.protocol.as_str(), "HTTP" | "DNS") {
            return None;
        }
        let probe = self
            .probes
            .iter()
            .rev()
            .find(|p| interaction.payload.contains(&p.token))?;
        Some(crate::scanner::Issue {
            url: probe.url.clone(),
            severity: crate::scanner::Severity::Medium,
            title: "Out-of-band interaction observed",
            detail: format!(
                "{} probe received a correlated {} callback from {}. Verify that the target initiated it. Callback evidence follows:\n{}",
                probe.kind, interaction.protocol, interaction.peer, interaction.payload
            ),
            req: probe.request.clone(),
            res: interaction.payload.as_bytes().to_vec(),
        })
    }
    pub fn on_note(&mut self, run: u64, note: Note) {
        if run != self.run {
            return;
        }
        match note {
            Note::Session(bytes)=>self.session=bytes,
            Note::Endpoint(base) => {
                self.base = format!(
                    "http://{{{{token}}}}.{}",
                    base.trim_start_matches("https://")
                );
                self.status =
                    "Interactsh registered and polling. Use this callback URL for scanner probes."
                        .into();
            }
            Note::Interaction(i) => {
                if self.interactions.iter().any(|old|old.protocol==i.protocol&&old.peer==i.peer&&old.payload==i.payload){return;}
                self.interactions.push(i);
                if self.interactions.len() > 2000 {
                    self.interactions.remove(0);
                }
            }
            Note::Status(s) => self.status = s,
            Note::Done => self.cancel = None,
        }
    }
    fn start(&mut self, env: &Env) {
        self.run += 1;
        let run = self.run;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (http, dns) = (self.http.clone(), self.dns.clone());
        let (tx, ctx) = (env.tx.clone(), env.egui.clone());
        env.rt.spawn(async move{
            let notify=|note|{let _=tx.send(Event::Callback{run,note});ctx.request_repaint();};
            let listener=match tokio::net::TcpListener::bind(&http).await{Ok(l)=>l,Err(e)=>{notify(Note::Status(format!("HTTP listener: {e}")));notify(Note::Done);return;}};
            let udp=if dns.is_empty(){None}else{match tokio::net::UdpSocket::bind(&dns).await{Ok(s)=>Some(s),Err(e)=>{notify(Note::Status(format!("DNS listener: {e}")));notify(Note::Done);return;}}};
            notify(Note::Status(format!("Listening on {http}; DNS {}. Targets must be able to reach these addresses.",if dns.is_empty(){"disabled"}else{&dns})));
            let mut packet=[0u8;4096];let mut tasks=tokio::task::JoinSet::new();
            while !cancel.load(Ordering::Relaxed){
                while tasks.try_join_next().is_some(){}
                tokio::select!{
                    accepted=listener.accept()=>if let Ok((mut socket,peer))=accepted{
                        if tasks.len()>=32{continue;}
                        let tx=tx.clone();let ctx=ctx.clone();
                        tasks.spawn(async move{
                            let read = async {
                                let mut data = Vec::new();
                                while !data.ends_with(b"\r\n\r\n") {
                                    if data.len() >= 8192 { return Err(std::io::Error::other("callback header limit exceeded")); }
                                    data.push(socket.read_u8().await?);
                                }
                                Ok::<_,std::io::Error>(data)
                            };
                            if let Ok(Ok(data))=tokio::time::timeout(std::time::Duration::from_secs(3),read).await {
                                let i=Interaction{time:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),protocol:"HTTP".into(),peer:peer.to_string(),payload:String::from_utf8_lossy(&data).into_owned()};
                                let _=tx.send(Event::Callback{run,note:Note::Interaction(i)});ctx.request_repaint();let _=socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                            }
                        });
                    },
                    result=async{match &udp{Some(udp)=>udp.recv_from(&mut packet).await,None=>std::future::pending().await}}=>if let Ok((n,peer))=result{
                        if let Some((name,end))=dns_question(&packet[..n]){
                            notify(Note::Interaction(Interaction{time:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),protocol:"DNS".into(),peer:peer.to_string(),payload:name}));
                            let mut reply=packet[..end].to_vec();reply[2]=0x81;reply[3]=0x83;reply[6..12].fill(0);let _=udp.as_ref().unwrap().send_to(&reply,peer).await;
                        }
                    },
                    _=tokio::time::sleep(std::time::Duration::from_millis(100))=>{}
                }
            }
            tasks.abort_all();notify(Note::Done);
        });
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, env: &mut Env, scan_base: &mut String) {
        if self.http.is_empty() {
            self.http = "127.0.0.1:8888".into();
        }
        ui.collapsing("Public Interactsh service",|ui|{
            if self.binary.is_empty(){self.binary="interactsh-client".into();}
            ui.label("Uses the installed official client for registration, decryption and automatic polling. Starting contacts the configured public service. Stops when switching projects.");
            ui.horizontal(|ui|{ui.label("Executable");ui.text_edit_singleline(&mut self.binary);ui.label("Server (optional)");ui.text_edit_singleline(&mut self.server);});
            if self.cancel.is_none()&&ui.button("Start Interactsh").clicked(){self.start_interactsh(env);}
        });
        ui.label("Collect HTTP and DNS callbacks for blind testing. Use a VPN/public address reachable by the target; DNS requires delegation or direct queries to your listener.");
        ui.horizontal(|ui| {
            ui.label("HTTP bind");
            ui.text_edit_singleline(&mut self.http);
            ui.label("DNS bind (optional)");
            ui.text_edit_singleline(&mut self.dns);
        });
        ui.horizontal(|ui| {
            if let Some(cancel) = &self.cancel {
                if ui.button("Stop listeners").clicked() {
                    cancel.store(true, Ordering::Relaxed);
                }
            } else if ui.button("Start listeners").clicked() {
                self.start(env);
            }
            ui.label(&self.status);
        });
        ui.horizontal(|ui| {
            ui.label("Callback URL or DNS suffix");
            ui.add(
                egui::TextEdit::singleline(&mut self.base)
                    .hint_text("http://VPN-IP:8888 or delegated.example.net")
                    .desired_width(400.0),
            );
            if ui.button("Generate payload").clicked() {
                match token() {
                    Ok(t) => {
                        let p = if self.base.contains("://") {
                            payload(&self.base, &t)
                        } else {
                            format!("{t}.{}", self.base.trim_matches('.'))
                        };
                        self.tokens.push(p.clone());
                        if self.tokens.len() > 1000 {
                            self.tokens.remove(0);
                        }
                        ui.ctx().copy_text(p);
                    }
                    Err(e) => self.status = e,
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Scanner callback base (empty disables blind probes)");
            ui.add(egui::TextEdit::singleline(scan_base).desired_width(360.0));
            if ui.button("Use callback URL above").clicked() {
                *scan_base = self.base.clone();
            }
        });
        for token in self.tokens.iter().rev().take(5) {
            ui.horizontal(|ui| {
                ui.monospace(token);
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(token.clone());
                }
            });
        }
        ui.collapsing("Poll an external callback service",|ui|{
            ui.label("GET a service endpoint that returns interaction text/JSON. Authentication stays in memory. This is a generic webhook adapter, not the encrypted Collaborator/Interactsh protocol.");
            ui.text_edit_singleline(&mut self.poll);ui.add(egui::TextEdit::singleline(&mut self.auth).password(true).hint_text("Authorization header, optional"));
            if ui.button("Poll now").clicked(){let url=self.poll.clone();let auth=self.auth.clone();let upstream=env.upstream();let run=self.run;
                env.spawn(async move{let result=async{let t=crate::http::Target::from_url(&url).ok_or("Invalid polling URL")?;if auth.contains(['\r','\n']){return Err("Invalid Authorization header".into());}let raw=format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: {auth}\r\n\r\n",crate::http::url_path(&url),t.host_header());let r=crate::http::send(&t,raw.as_bytes(),&upstream).await?;if r.status!=200{return Err(format!("Poll returned {}",r.status));}Ok(String::from_utf8_lossy(&crate::http::Msg::parse(&r.raw).decoded_body()).into_owned())}.await;
                    Event::Callback{run,note:match result{Ok(payload)=>Note::Interaction(Interaction{time:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),protocol:"Poll".into(),peer:url,payload}),Err(e)=>Note::Status(e)}}});}
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(format!("{} interactions", self.interactions.len()));
            if ui.button("Clear").clicked() {
                self.interactions.clear();
            }
        });
        egui::ScrollArea::vertical()
            .max_height(240.0)
            .show(ui, |ui| {
                for (i, item) in self.interactions.iter().enumerate() {
                    let matched = self.tokens.iter().any(|t| {
                        t.split('/')
                            .next_back()
                            .is_some_and(|token| item.payload.contains(token))
                    });
                    ui.selectable_value(
                        &mut self.selected,
                        i,
                        format!(
                            "{} {} {} {}",
                            item.time,
                            item.protocol,
                            item.peer,
                            if matched { "[payload matched]" } else { "" }
                        ),
                    );
                }
            });
        if let Some(i) = self.interactions.get(self.selected) {
            ui.monospace(&i.payload);
            if ui.button("Copy evidence").clicked() {
                ui.ctx().copy_text(format!(
                    "{} {} {}\n{}",
                    i.time, i.protocol, i.peer, i.payload
                ));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_parsing_rejects_compression_and_extracts_question() {
        let mut q = vec![0u8; 12];
        q[5] = 1;
        q.extend_from_slice(b"\x03abc\x07example\x03com\0\0\x01\0\x01");
        assert_eq!(dns_question(&q).unwrap().0, "abc.example.com");
        q[12] = 0xc0;
        assert!(dns_question(&q).is_none());
    }
    #[test]
    fn payload_tokens_are_distinct() {
        assert_ne!(token().unwrap(), token().unwrap());
    }
}

#[cfg(test)]
#[path = "tests/callbacks_regression.rs"]
mod robust_callback_tests;
