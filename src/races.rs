//! Repeat synchronized groups and retain per-round evidence and success counts.
use crate::{Env,http::{self,Target},groups::Mode};
use eframe::egui;
use std::sync::mpsc;
struct Row{round:usize,index:usize,request:Vec<u8>,reply:Result<http::Reply,String>,success:bool,hash:String}
pub struct Races{target:Option<Target>,requests:Vec<Vec<u8>>,copies:usize,rounds:usize,delay:u64,mode:Mode,codes:String,pattern:String,maximum:usize,check_max:bool,writes:bool,cookies:bool,rows:Vec<Row>,selected:usize,task:Option<tokio::task::JoinHandle<()>>,rx:Option<mpsc::Receiver<Row>>,message:String}
impl Default for Races{fn default()->Self{Self{target:None,requests:vec![],copies:2,rounds:10,delay:100,mode:Mode::Coalesced,codes:"200,201,204".into(),pattern:String::new(),maximum:1,check_max:false,writes:false,cookies:false,rows:vec![],selected:0,task:None,rx:None,message:String::new()}}}
impl Drop for Races{fn drop(&mut self){if let Some(task)=&self.task{task.abort();}}}
impl Races{
    pub fn load(&mut self,target:Target,requests:Vec<Vec<u8>>){*self=Self::default();self.target=Some(target);self.requests=requests.into_iter().take(100).collect();if self.requests.len()>1{self.copies=1;}}
    fn start(&mut self,env:&Env){
        let Some(target)=self.target.clone()else{return;};let cfg=crate::rules::current(env.shared);if cfg.cfg.session_macros.iter().any(|m|m.enabled){self.message="Prepare login/tokens first, then disable macros for synchronized requests".into();return;}
        if !self.writes&&self.requests.iter().any(|r|!matches!(http::Msg::parse(r).first.split_whitespace().next(),Some("GET"|"HEAD"|"OPTIONS"))){self.message="Enable state-changing requests before starting".into();return;}
        let members=self.requests.len()*self.copies.clamp(1,100);if members==0||members>100{self.message="Use 1–100 total group members".into();return;}
        let pattern=match regex::Regex::new(&self.pattern){Ok(p)=>p,Err(e)=>{self.message=e.to_string();return;}};
        let codes:Vec<u16>=match self.codes.split(',').map(|s|s.trim().parse()).collect(){Ok(c)=>c,Err(_)=>{self.message="Success statuses must be comma-separated numbers".into();return;}};
        let client=env.session(self.cookies);let requests:Vec<_>=(0..self.copies).flat_map(|_|self.requests.iter().map(|r|client.prepare(&target,r))).collect();
        let(mode,rounds,delay)=(self.mode,self.rounds.clamp(1,100),self.delay.min(60000));let(tx,rx)=mpsc::channel();self.rx=Some(rx);self.rows.clear();self.selected=0;
        let upstream=env.upstream();let ctx=env.egui.clone();self.task=Some(env.rt.spawn(async move{
            use sha2::Digest;
            for round in 0..rounds{let results=crate::groups::send(target.clone(),requests.clone(),upstream.clone(),mode).await;for(index,reply)in results{
                let(success,hash)=reply.as_ref().map(|r|{let body=http::Msg::parse(&r.raw).decoded_body();(codes.contains(&r.status)&&pattern.is_match(&String::from_utf8_lossy(&body)),sha2::Sha256::digest(&body).iter().map(|b|format!("{b:02x}")).collect())}).unwrap_or((false,String::new()));
                let reply=reply.map(|mut r|{r.raw=crate::retention::clip(r.raw);r});if tx.send(Row{round,index,request:crate::retention::clip(requests[index].clone()),reply,success,hash}).is_err(){return;}ctx.request_repaint();}
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }));
    }
    pub fn ui(&mut self,ui:&mut egui::Ui,env:&mut Env){
        if let Some(rx)=&self.rx{self.rows.extend(rx.try_iter());let mut bytes=0;for row in self.rows.iter_mut().rev(){bytes+=row.request.len()+row.reply.as_ref().map_or(0,|r|r.raw.len());if bytes>crate::retention::BYTES{row.request.clear();if let Ok(reply)=&mut row.reply{reply.raw.clear();}}}}
        if self.task.as_ref().is_some_and(|t|t.is_finished()){self.task=None;self.message="Race attempts finished; inspect application state to validate duplicate side effects".into();}
        ui.label("Send a request here from a request context menu, or a named Repeater group. HTTP/2 coalesced release stages complete frames before writing; TCP packet boundaries remain OS-controlled.");
        if self.target.is_none(){return;}
        ui.horizontal(|ui|{ui.label(format!("{} templates",self.requests.len()));ui.label("Copies");ui.add(egui::DragValue::new(&mut self.copies).range(1..=100));ui.label("Rounds");ui.add(egui::DragValue::new(&mut self.rounds).range(1..=100));ui.label("Between rounds ms");ui.add(egui::DragValue::new(&mut self.delay).range(0..=60000));});
        egui::ComboBox::from_id_salt("race_mode").selected_text(self.mode.label()).show_ui(ui,|ui|{for(mode,label)in Mode::ALL{ui.selectable_value(&mut self.mode,mode,label);}});
        ui.horizontal(|ui|{ui.label("Success statuses");ui.text_edit_singleline(&mut self.codes);ui.label("Body regex");ui.text_edit_singleline(&mut self.pattern);});
        ui.horizontal(|ui|{ui.checkbox(&mut self.check_max,"Flag rounds exceeding expected successes");ui.add(egui::DragValue::new(&mut self.maximum).range(0..=100));ui.checkbox(&mut self.writes,"Allow state-changing requests");ui.checkbox(&mut self.cookies,"Use session cookies");});
        ui.horizontal(|ui|{if self.task.is_none(){if ui.button("Run race attempts").clicked(){self.start(env);}}else if ui.button("Stop").clicked(){if let Some(task)=self.task.take(){task.abort();}self.message="Stopped; released requests may have reached the target".into();}ui.label(&self.message);});
        let mut rounds=std::collections::BTreeMap::new();for row in &self.rows{let count=rounds.entry(row.round).or_insert(0);if row.success{*count+=1;}}
        for(round,count)in rounds{ui.label(format!("Round {}: {count} successful responses{}",round+1,if self.check_max&&count>self.maximum{" — REVIEW exceeded expected maximum"}else{""}));}
        egui::ScrollArea::vertical().max_height(160.0).show(ui,|ui|{for(i,row)in self.rows.iter().enumerate(){ui.selectable_value(&mut self.selected,i,format!("Round {} member {} · {} · {}",row.round+1,row.index+1,row.reply.as_ref().map_or_else(|e|e.clone(),|r|format!("{} / {} ms",r.status,r.elapsed.as_millis())),&row.hash[..row.hash.len().min(12)]));}});
        if let Some(row)=self.rows.get(self.selected){if let Ok(reply)=&row.reply{if ui.button("Save race evidence to Organizer").clicked(){env.actions.push(crate::Action::Organize(self.target.as_ref().unwrap().url(),row.request.clone(),Some(reply.raw.clone())));}egui::ScrollArea::vertical().show(ui,|ui|{ui.monospace(String::from_utf8_lossy(&reply.raw));});}}
    }
}
