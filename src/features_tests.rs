//! Local network regressions for advanced workflows; no external target required.
use crate::{http::{self, Msg, Target, Upstream}, groups::{self, Mode}};
use std::{sync::{Arc,Mutex},time::Duration};
use tokio::io::{AsyncReadExt,AsyncWriteExt};

pub async fn fixture() -> (Target, Arc<Mutex<Vec<Vec<u8>>>>, tokio::task::JoinHandle<()>) {
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
    let seen:Arc<Mutex<Vec<Vec<u8>>>>=Arc::default();let record=seen.clone();
    let task=tokio::spawn(async move {
        loop {let Ok((mut io,_))=listener.accept().await else{break};let seen=record.clone();tokio::spawn(async move {
            let mut pending=Vec::new();
            loop {
                let mut chunk=[0u8;4096];
                let end=loop {
                    if let Some(head)=pending.windows(4).position(|w|w==b"\r\n\r\n").map(|i|i+4){let length=Msg::parse(&pending[..head]).header("content-length").and_then(|v|v.parse::<usize>().ok()).unwrap_or(0);if pending.len()>=head+length{break head+length;}}
                    let Ok(n)=io.read(&mut chunk).await else{return};if n==0{return;}pending.extend_from_slice(&chunk[..n]);
                };
                let raw:Vec<_>=pending.drain(..end).collect();let msg=Msg::parse(&raw);let path=msg.first.split_whitespace().nth(1).unwrap_or("/");
                seen.lock().unwrap().push(raw.clone());
                let body=if path=="/token"{r#"{"token":"rotated csrf"}"#.to_string()}else if path.starts_with("/dom"){r#"<div id="sink"></div><script>document.querySelector('#sink').innerHTML=decodeURIComponent(location.hash.slice(1));let a=document.createElement('a');a.href='/dynamic';a.textContent='dynamic';document.body.append(a);</script>"#.into()}else{format!("received {path}")};
                let extra=if path=="/token"{"Set-Cookie: sid=rotated; Path=/\r\nContent-Type: application/json\r\n"}else{"Content-Type: text/html\r\n"};
                let response=format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\n\r\n{body}",body.len());
                if io.write_all(response.as_bytes()).await.is_err(){return;}
                if msg.header("connection").is_some_and(|v|v.eq_ignore_ascii_case("close")){return;}
            }
        });}
    });
    (Target::from_url(&format!("http://{addr}")).unwrap(),seen,task)
}

#[tokio::test]
async fn groups_send_sequence_reuse_and_synchronized_requests(){
    let(target,seen,server)=fixture().await;
    for mode in [Mode::Sequence,Mode::Connection,Mode::Parallel]{
        let requests=(0..3).map(|i|format!("GET /{i} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",target.host_header()).into_bytes()).collect();
        let replies=groups::send(target.clone(),requests,Upstream::None,mode).await;
        assert_eq!(replies.len(),3);for(i,r)in replies{let r=r.unwrap();assert_eq!(r.status,200);assert!(String::from_utf8_lossy(&r.raw).contains(&format!("received /{i}")));}
    }
    assert_eq!(seen.lock().unwrap().len(),9);server.abort();
}
#[tokio::test]
async fn groups_use_real_http2_streams(){
    use hudsucker::hyper::{server::conn::http2,service::service_fn,Response};
    use hyper_util::rt::{TokioExecutor,TokioIo};
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
    let server=tokio::spawn(async move{let(io,_)=listener.accept().await.unwrap();let _=http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(io),service_fn(|req:hudsucker::hyper::Request<hudsucker::hyper::body::Incoming>|async move{Ok::<_,std::convert::Infallible>(Response::new(http_body_util::Full::new(bytes::Bytes::from(format!("h2 {}",req.uri().path())))))})).await;});
    let target=Target::from_url(&format!("http://{addr}")).unwrap();let requests=(0..3).map(|i|format!("GET /{i} HTTP/1.1\r\nHost: {addr}\r\n\r\n").into_bytes()).collect();
    let results=groups::send(target,requests,Upstream::None,Mode::Http2).await;assert_eq!(results.len(),3);
    for(i,result)in results{let result=result.unwrap();assert!(String::from_utf8_lossy(&result.raw).contains(&format!("h2 /{i}")));}server.abort();
}
#[tokio::test]
async fn macros_refresh_token_and_cookie_before_actual_request(){
    use crate::macros::{Macro,Step,Extract};
    let(target,seen,server)=fixture().await;
    let rule=Macro{validity:None,name:"csrf".into(),enabled:true,origin:target.url(),path_regex:"^/submit".into(),steps:vec![Step{url:format!("{}/token",target.url()),request:format!("GET /token HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",target.host_header()),expect_status:200,extract:vec![Extract{name:"csrf".into(),regex:String::new(),json_pointer:"/token".into(),url_encode:true}]}]};
    let client=crate::session::Client::new(Arc::default(),true,true).with_macros(vec![rule.clone()]);
    let raw=format!("POST /submit HTTP/1.1\r\nHost: {}\r\nContent-Length: 1\r\nConnection: close\r\n\r\ncsrf={{{{csrf}}}}",target.host_header());
    let(sent,result)=client.send(&target,raw.as_bytes(),&Upstream::None).await;assert_eq!(result.unwrap().status,200);
    let msg=Msg::parse(&sent);assert_eq!(msg.header("cookie"),Some("sid=rotated"));assert_eq!(String::from_utf8(msg.body).unwrap(),"csrf=rotated%20csrf");assert_eq!(seen.lock().unwrap().len(),2);
    let mut bad=rule;bad.steps[0].url="http://other.invalid/token".into();let client=client.with_macros(vec![bad]);assert!(client.send(&target,raw.as_bytes(),&Upstream::None).await.1.err().unwrap().contains("origin"));server.abort();
}
#[tokio::test]
async fn scripts_transform_requests_and_reject_invalid_protocol(){
    use crate::extensions::{Package,Script};
    let mut package=Package{checks:vec![],scripts:vec![Script{name:"header".into(),enabled:true,origin:"http://example.com".into(),phase:"request".into(),command:vec!["python3".into(),"-c".into(),"import sys,json,base64;v=json.load(sys.stdin);s=base64.b64decode(v['raw_base64']).replace(b'Host: example.com',b'Host: example.com\\r\\nX-Hook: yes');print(json.dumps({'raw_base64':base64.b64encode(s).decode()}))".into()]}]};
    let raw=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();let out=crate::extensions::hooks(&package,"request","http://example.com/",raw.clone()).await.unwrap();assert_eq!(Msg::parse(&out).header("x-hook"),Some("yes"));
    assert_eq!(crate::extensions::hooks(&package,"request","http://other.com/",raw.clone()).await.unwrap(),raw);
    package.scripts[0].command=vec!["python3".into(),"-c".into(),"print('{}')".into()];assert!(crate::extensions::hooks(&package,"request","http://example.com/",raw).await.is_err());
}

pub fn issuer()->hudsucker::rcgen::Issuer<'static,hudsucker::rcgen::KeyPair>{
    use hudsucker::rcgen::*;let key=KeyPair::generate().unwrap();let mut params=CertificateParams::default();params.is_ca=IsCa::Ca(BasicConstraints::Unconstrained);let cert=params.self_signed(&key).unwrap();Issuer::from_ca_cert_pem(&cert.pem(),key).unwrap()
}
pub async fn start_proxy(cfg:crate::rules::Config)->(std::net::SocketAddr,tokio::task::JoinHandle<()>) {
    let reserved=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=reserved.local_addr().unwrap();drop(reserved);
    let shared=Arc::new(std::sync::RwLock::new(Arc::new(crate::rules::Compiled::new(cfg))));let(tx,_rx)=std::sync::mpsc::channel();
    let task=tokio::spawn(async move{let _=crate::proxy::run_with_issuer(addr,shared,tx,eframe::egui::Context::default(),issuer()).await;});
    for _ in 0..50{if tokio::net::TcpStream::connect(addr).await.is_ok(){return(addr,task);}tokio::time::sleep(Duration::from_millis(10)).await;}panic!("proxy did not bind");
}
#[tokio::test]
async fn proxy_delivers_sse_before_upstream_closes_and_retains_header_rewrites(){
    use crate::rules::{Config,Rule,Part};
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let target=listener.local_addr().unwrap();
    let origin=tokio::spawn(async move{let(mut socket,_)=listener.accept().await.unwrap();let mut b=[0u8;2048];let _=socket.read(&mut b).await;socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 12\r\n\r\ndata: hello\n").await.unwrap();tokio::time::sleep(Duration::from_secs(5)).await;socket.write_all(b"\n").await.unwrap();});
    let(proxy,task)=start_proxy(Config{rules:vec![Rule{enabled:true,part:Part::ResponseHeader,find:String::new(),replace:"X-Test: streaming".into(),regex:false}],..Default::default()}).await;
    let mut socket=tokio::net::TcpStream::connect(proxy).await.unwrap();socket.write_all(format!("GET http://{target}/sse HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
    let early=tokio::time::timeout(Duration::from_secs(2),async{let mut all=Vec::new();let mut chunk=[0u8;2048];loop{let n=socket.read(&mut chunk).await.unwrap();if n==0{break;}all.extend_from_slice(&chunk[..n]);if String::from_utf8_lossy(&all).contains("data: hello"){break;}}all}).await.unwrap();let text=String::from_utf8_lossy(&early);assert!(text.contains("data: hello"));assert!(text.to_lowercase().contains("x-test: streaming"));assert!(text.to_lowercase().contains("content-length: 12"));task.abort();origin.abort();
}
#[tokio::test]
async fn websocket_transport_honors_http_upstream(){
    use hudsucker::{futures::{SinkExt,StreamExt},tokio_tungstenite::{accept_async,tungstenite::{Message,client::IntoClientRequest}}};
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
    let server=tokio::spawn(async move{let(mut socket,_)=listener.accept().await.unwrap();let mut header=Vec::new();while !header.ends_with(b"\r\n\r\n"){header.push(socket.read_u8().await.unwrap());}assert!(String::from_utf8_lossy(&header).starts_with("CONNECT fixture.invalid:80"));socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();let mut ws=accept_async(socket).await.unwrap();let m=ws.next().await.unwrap().unwrap();ws.send(m).await.unwrap();});
    let(mut ws,_)=http::websocket("ws://fixture.invalid/".into_client_request().unwrap(),&Upstream::Http(addr.to_string())).await.unwrap();ws.send(Message::Text("hello".into())).await.unwrap();assert_eq!(ws.next().await.unwrap().unwrap(),Message::Text("hello".into()));server.await.unwrap();
}
#[test]fn history_evicts_old_evidence_and_preserves_current_flow_ids(){let mut h=crate::history::History::default();for i in 0..=crate::retention::ROWS{h.on_request(i as u64,format!("http://example.com/{i}"),b"GET / HTTP/1.1\r\n\r\n".to_vec());}h.enforce_limits();assert_eq!(h.flows.len(),crate::retention::ROWS);assert!(h.flow(0).is_none());assert!(h.flow(crate::retention::ROWS as u64).is_some());}
