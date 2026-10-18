//! Scan queue with request-level pause/resume and named shared quotas.
use crate::{Env,http::Target,work::{Control,PoolConfig}};
use eframe::egui;
use serde::{Serialize,Deserialize};
use std::sync::{Arc,atomic::Ordering};
#[derive(Clone,Serialize,Deserialize)]#[serde(default)]pub struct Policy{pub timing:bool,pub mining:bool,pub custom:bool,pub callbacks:bool,pub pool:String}
impl Default for Policy{fn default()->Self{Self{timing:false,mining:true,custom:true,callbacks:false,pool:"Default".into()}}}
#[derive(Clone,Serialize,Deserialize)]pub struct SavedJob{target:Target,raw:Vec<u8>,policy:Policy}
struct Job{saved:SavedJob,control:Arc<Control>,task:Option<tokio::task::JoinHandle<()>>,started:bool}
impl Drop for Job{fn drop(&mut self){self.control.cancelled.store(true,Ordering::Relaxed);if let Some(task)=self.task.take(){task.abort();}}}
#[derive(Default)]pub struct Dashboard{jobs:Vec<Job>,policy:Policy}
impl Dashboard{
    pub fn is_empty(&self)->bool{self.jobs.is_empty()}
    pub fn enqueue(&mut self,target:Target,raw:Vec<u8>){if self.jobs.len()>=100{return;}self.jobs.push(Job{saved:SavedJob{target,raw,policy:self.policy.clone()},control:Arc::default(),task:None,started:false});}
    pub fn saved(&self)->Vec<SavedJob>{self.jobs.iter().map(|j|j.saved.clone()).collect()}
    pub fn restore(&mut self,jobs:Vec<SavedJob>){self.jobs.clear();for saved in jobs.into_iter().take(100){let control=Arc::new(Control::default());control.paused.store(true,Ordering::Relaxed);self.jobs.push(Job{saved,control,task:None,started:false});}}
    pub fn clear(&mut self){self.jobs.clear();}
    pub fn tick(&mut self,env:&Env){
        if self.jobs.iter().any(|j|j.task.as_ref().is_some_and(|t|!t.is_finished())){return;}
        let Some(job)=self.jobs.iter_mut().find(|j|!j.started&&!j.control.paused.load(Ordering::Relaxed)&&!j.control.cancelled.load(Ordering::Relaxed))else{return;};
        job.started=true;let saved=job.saved.clone();let control=job.control.clone();let config=crate::rules::current(env.shared).cfg.clone();let pool=config.resource_pools.iter().find(|p|p.name==saved.policy.pool).cloned().unwrap_or_default();let client=env.session(true).with_work(crate::work::Work::new(pool,control));let(tx,ctx,upstream)=(env.tx.clone(),env.egui.clone(),env.upstream());
        job.task=Some(env.rt.spawn(async move{
            crate::scanner::active_controlled(saved.target.clone(),saved.raw.clone(),upstream.clone(),tx.clone(),ctx.clone(),client.clone(),saved.policy.timing,saved.policy.mining).await;
            if saved.policy.custom{crate::extensions::active(config.extensions,saved.target.clone(),saved.raw.clone(),client.clone(),upstream.clone(),tx.clone(),ctx.clone()).await;}
            if saved.policy.callbacks&&!config.callback_base.is_empty(){crate::scanner::oast(saved.target,saved.raw,config.callback_base,client,upstream,tx,ctx.clone()).await;}
            ctx.request_repaint();
        }));
    }
    pub fn ui(&mut self,ui:&mut egui::Ui,pools:&mut Vec<PoolConfig>){
        ui.heading("Scan queue");ui.label("New scans use the policy below. Pause stops new requests; current requests may finish. Restored scans require an explicit Resume.");
        ui.horizontal(|ui|{ui.checkbox(&mut self.policy.timing,"Time-based probes");ui.checkbox(&mut self.policy.mining,"Parameter mining");ui.checkbox(&mut self.policy.custom,"Custom checks");ui.checkbox(&mut self.policy.callbacks,"Callback probes");egui::ComboBox::from_id_salt("scan_pool").selected_text(&self.policy.pool).show_ui(ui,|ui|{for pool in pools.iter(){ui.selectable_value(&mut self.policy.pool,pool.name.clone(),&pool.name);}});});
        ui.collapsing("Shared resource pools",|ui|{for(i,pool)in pools.iter_mut().enumerate(){ui.push_id(i,|ui|{ui.horizontal(|ui|{ui.text_edit_singleline(&mut pool.name);ui.label("Concurrency");ui.add(egui::DragValue::new(&mut pool.concurrency).range(1..=200));ui.label("Delay ms");ui.add(egui::DragValue::new(&mut pool.delay_ms).range(0..=60000));ui.label("429/503 backoff ms");ui.add(egui::DragValue::new(&mut pool.backoff_ms).range(0..=60000));});});}if pools.len()<20&&ui.button("Add pool").clicked(){pools.push(PoolConfig{name:format!("Pool {}",pools.len()+1),..Default::default()});}});
        egui::ScrollArea::vertical().show(ui,|ui|{for(i,job)in self.jobs.iter_mut().enumerate(){ui.push_id(i,|ui|{let finished=job.task.as_ref().is_some_and(|t|t.is_finished());let paused=job.control.paused.load(Ordering::Relaxed);let cancelled=job.control.cancelled.load(Ordering::Relaxed);ui.horizontal(|ui|{ui.label(format!("{} · {} · {}/{} completed · {} errors",job.saved.target.url(),if cancelled{"Cancelled"}else if finished{"Finished"}else if paused{"Paused"}else if job.started{"Running"}else{"Queued"},job.control.completed.load(Ordering::Relaxed),job.control.sent.load(Ordering::Relaxed),job.control.errors.load(Ordering::Relaxed)));if !finished&&!cancelled{if ui.button(if paused{"Resume"}else{"Pause"}).clicked(){job.control.paused.store(!paused,Ordering::Relaxed);}if ui.button("Cancel").clicked(){job.control.cancelled.store(true,Ordering::Relaxed);}}});});}});
    }
}
