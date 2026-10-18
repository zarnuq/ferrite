//! Explicit differential probes. Unstable and reflected-only responses are not confirmations.
use crate::{Event,http::{self,Msg,Target,Upstream},scanner::{Issue,Severity,Point,points,inject}};
use serde::{Serialize,Deserialize};
#[derive(Clone,Default,Serialize,Deserialize)]#[serde(default)]
pub struct Policy{pub boolean_sql:bool,pub host_cache:bool,pub framing:bool}
fn body(reply:&http::Reply)->Vec<u8>{Msg::parse(&reply.raw).decoded_body()}
async fn send(client:&crate::session::Client,target:&Target,raw:&[u8],upstream:&Upstream,point:Option<&Point>)->(Vec<u8>,Result<http::Reply,String>){client.send_probe(target,raw,upstream,point.and_then(|p|if let Point::Cookie(i)=p{Some(*i)}else{None})).await}
pub async fn run(policy:Policy,target:Target,raw:Vec<u8>,client:crate::session::Client,upstream:Upstream,tx:std::sync::mpsc::Sender<Event>,ctx:eframe::egui::Context){
    let m=Msg::parse(&raw);let path=m.first.split_whitespace().nth(1).unwrap_or("/");let url=format!("{}{path}",target.url());
    let notify=|title:&'static str,severity,detail:String,request:Vec<u8>,response:Vec<u8>|{let _=tx.send(Event::Issue(format!("deep {title} {url} {detail}"),Issue{url:url.clone(),severity,title,detail,req:crate::retention::clip(request),res:crate::retention::clip(response)}));ctx.request_repaint();};
    if policy.boolean_sql {
        let first=client.send(&target,&raw,&upstream).await.1;let second=client.send(&target,&raw,&upstream).await.1;
        if let(Ok(base),Ok(again))=(first,second){if base.status==again.status&&body(&base)==body(&again){
            for(point,name)in points(&m).into_iter().take(20){
                for quote in ["'",""]{
                    let mut evidence=None;let mut confirmed=true;
                    for(a,b)in [("1=1","1=2"),("4=4","4=5")]{
                        let yes=inject(&m,&point,&format!("{quote} AND {a}-- "),true);let no=inject(&m,&point,&format!("{quote} AND {b}-- "),true);
                        let(_,yes)=send(&client,&target,&yes,&upstream,Some(&point)).await;let(sent,no)=send(&client,&target,&no,&upstream,Some(&point)).await;
                        match(yes,no){(Ok(yes),Ok(no))if yes.status==base.status&&body(&yes)==body(&base)&&((no.status!=base.status)||(body(&no)!=body(&base)&&body(&no).len().abs_diff(body(&base).len())>=16))=>evidence=Some((sent,no.raw)),_=>{confirmed=false;break;}}
                    }
                    if confirmed{if let Some((request,response))=evidence{notify("SQL injection (boolean-based)",Severity::High,format!("Parameter '{name}' preserved a stable baseline for two true predicates and changed it for two false predicates. Validate the database behavior manually."),request,response);}break;}
                }
            }
        }}
    }
    if policy.host_cache {
        let token=crate::callbacks::token().unwrap_or_else(|_|crate::history::next_id().to_string());let marker=format!("ferrite-{token}.invalid");let mut isolated=Msg::parse(&raw);let mut words:Vec<_>=isolated.first.split_whitespace().map(str::to_string).collect();
        if let Some(path)=words.get_mut(1){*path=format!("{path}{}_ferrite_probe={token}",if path.contains('?'){"&"}else{"?"});}isolated.first=words.join(" ");
        let clean=isolated.render();let(_,before)=client.send(&target,&clean,&upstream).await;
        let mut poison=Msg::parse(&clean);poison.set_header("X-Forwarded-Host",marker.clone());let(sent,poisoned)=client.send(&target,&poison.render(),&upstream).await;
        let contains=|r:&http::Reply|String::from_utf8_lossy(&r.raw).contains(&marker);
        if before.as_ref().is_ok_and(|r|!contains(r))&&poisoned.as_ref().is_ok_and(contains){
            let(_,victim)=client.send(&target,&clean,&upstream).await;let(_,repeat)=client.send(&target,&clean,&upstream).await;
            if let(Ok(victim),Ok(repeat))=(victim,repeat){if contains(&victim)&&contains(&repeat){notify("Cache poisoning (forwarded host)",Severity::High,"A unique cache-busted request with X-Forwarded-Host contaminated two subsequent requests without that header. Evidence includes the poisoned and victim responses.".into(),sent,[poisoned.unwrap().raw,b"\n--- victim ---\n".to_vec(),victim.raw,repeat.raw].concat());}}
        }
        let mut host=Msg::parse(&clean);host.set_header("Host",marker.clone());let(sent,result)=client.send(&target,&host.render(),&upstream).await;
        if let Ok(reply)=result{if(300..400).contains(&reply.status)&&Msg::parse(&reply.raw).header("location").is_some_and(|l|url::Url::parse(l).is_ok_and(|u|u.host_str()==Some(&marker))){notify("Host header controls redirection",Severity::Medium,"Changing Host to a unique invalid domain changed the redirect authority. Review virtual-host routing and trusted-host validation.".into(),sent,reply.raw);}}
    }
    if policy.framing {
        let host=target.host_header();let token=crate::callbacks::token().unwrap_or_default();
        // An isolated connection, no embedded victim request, and a deliberately incomplete
        // chunk distinguish rejection from acceptance without desynchronizing a shared socket.
        let probes=[format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-Ferrite-Probe: {token}\r\n\r\n0\r\n\r\n"),format!("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\nX-Ferrite-Probe: {token}\r\n\r\nprobe!")];
        for request in probes{let result=tokio::time::timeout(std::time::Duration::from_secs(3),http::send(&target,request.as_bytes(),&upstream)).await;
            if let Ok(Ok(reply))=result{if(200..400).contains(&reply.status){notify("Ambiguous request framing accepted",Severity::Info,"An isolated request with conflicting HTTP/1 framing fields received a successful response. This is a request-smuggling review candidate, not proof of a frontend/backend discrepancy. No victim request was queued.".into(),request.into_bytes(),reply.raw);}}
        }
    }
}

#[cfg(test)]mod tests{
    use super::*;use crate::robust_tests::{fixture,Reply,request};use std::sync::{Arc,mpsc};
    #[tokio::test]async fn boolean_differentials_require_two_stable_true_and_false_pairs(){for vulnerable in [false,true]{let server=fixture(move|raw|{let raw=percent_encoding::percent_decode(raw).decode_utf8_lossy();let denied=vulnerable&&(raw.contains("1=2")||raw.contains("4=5"));Reply::body(200,&[],if denied{b"no rows"}else{b"user row: this is a sufficiently long stable authorized response"})}).await;let(tx,rx)=mpsc::channel();run(Policy{boolean_sql:true,..Default::default()},server.target.clone(),request(&server.target,"GET","/?id=1",b""),crate::session::Client::new(Arc::default(),false,false),Upstream::None,tx,eframe::egui::Context::default()).await;assert_eq!(rx.try_iter().any(|e|matches!(e,Event::Issue(_,i)if i.title=="SQL injection (boolean-based)")),vulnerable);}}
    #[tokio::test]async fn reflected_host_without_cache_replay_is_not_cache_poisoning(){let server=fixture(|raw|{let m=Msg::parse(raw);Reply::body(200,&[],m.header("x-forwarded-host").unwrap_or("normal").as_bytes())}).await;let(tx,rx)=mpsc::channel();run(Policy{host_cache:true,..Default::default()},server.target.clone(),request(&server.target,"GET","/",b""),crate::session::Client::new(Arc::default(),false,false),Upstream::None,tx,eframe::egui::Context::default()).await;assert!(!rx.try_iter().any(|e|matches!(e,Event::Issue(_,i)if i.title=="Cache poisoning (forwarded host)")));}
}
