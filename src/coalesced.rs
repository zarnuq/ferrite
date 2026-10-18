//! Stage complete HTTP/2 request frames, then flush their bytes together.
//! A coalesced application write cannot guarantee a single physical TCP packet.
use crate::http::{self,Msg,Reply,Target,Upstream};
use std::{collections::HashMap,io,pin::Pin,sync::{Arc,Mutex},task::{Context,Poll,Waker},time::{Duration,Instant}};
use tokio::io::{AsyncRead,AsyncWrite,ReadBuf};
#[derive(Default)]struct State{armed:bool,released:bool,bytes:Vec<u8>,offset:usize,waker:Option<Waker>,flushes:usize}
struct Gate{io:Box<dyn http::Stream>,state:Arc<Mutex<State>>}
impl Gate{
    fn drain(&mut self,cx:&mut Context<'_>)->Poll<io::Result<()>>{
        let mut s=self.state.lock().unwrap();s.waker=Some(cx.waker().clone());if !s.released{return Poll::Ready(Ok(()));}
        while s.offset<s.bytes.len(){let offset=s.offset;let n=match Pin::new(&mut *self.io).poll_write(cx,&s.bytes[offset..]){Poll::Pending=>return Poll::Pending,Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),Poll::Ready(Ok(0))=>return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),Poll::Ready(Ok(n))=>n};s.offset+=n;}
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Gate{fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{match self.drain(cx){Poll::Pending=>return Poll::Pending,Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),_=>{}}Pin::new(&mut *self.io).poll_read(cx,buf)}}
impl AsyncWrite for Gate{
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>>{
        {let mut s=self.state.lock().unwrap();s.waker=Some(cx.waker().clone());if s.armed&&!s.released{if s.bytes.len()+bytes.len()>1024*1024{return Poll::Ready(Err(io::Error::other("Coalesced frame buffer exceeded 1 MiB")));}s.bytes.extend_from_slice(bytes);return Poll::Ready(Ok(bytes.len()));}}
        match self.drain(cx){Poll::Pending=>return Poll::Pending,Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),_=>{}}Pin::new(&mut *self.io).poll_write(cx,bytes)
    }
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{
        {let mut s=self.state.lock().unwrap();s.waker=Some(cx.waker().clone());if s.armed&&!s.released{return Poll::Ready(Ok(()));}}
        match self.drain(cx){Poll::Pending=>return Poll::Pending,Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),_=>{}}
        let result=Pin::new(&mut *self.io).poll_flush(cx);if matches!(result,Poll::Ready(Ok(()))){self.state.lock().unwrap().flushes+=1;}result
    }
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{match self.drain(cx){Poll::Pending=>return Poll::Pending,Poll::Ready(Err(e))=>return Poll::Ready(Err(e)),_=>{}}Pin::new(&mut *self.io).poll_shutdown(cx)}
}
fn complete(bytes:&[u8])->usize{
    let mut streams:HashMap<u32,(bool,bool)>=HashMap::new();let mut pos=0;
    while bytes.len().saturating_sub(pos)>=9{let h=&bytes[pos..pos+9];let n=((h[0]as usize)<<16)|((h[1]as usize)<<8)|h[2]as usize;if pos+9+n>bytes.len(){break;}let id=u32::from_be_bytes([h[5]&0x7f,h[6],h[7],h[8]]);if id!=0{let state=streams.entry(id).or_default();match h[3]{1=>{state.0|=h[4]&1!=0;state.1=h[4]&4!=0;},9=>state.1=h[4]&4!=0,0=>state.0|=h[4]&1!=0,_=>{}}}pos+=9+n;}
    streams.values().filter(|(end,headers)|*end&&*headers).count()
}
struct Abort(tokio::task::AbortHandle);impl Drop for Abort{fn drop(&mut self){self.0.abort();}}
pub async fn send(target:Target,requests:Vec<Vec<u8>>,upstream:Upstream)->Result<Vec<(usize,Result<Reply,String>)>,String>{
    if requests.is_empty()||requests.len()>100{return Err("Coalesced groups need 1–100 requests".into());}
    if requests.iter().map(Vec::len).sum::<usize>()>64*1024||requests.iter().map(|r|Msg::parse(r).body.len()).sum::<usize>()>32*1024{return Err("Coalesced groups allow 64 KiB total requests and 32 KiB total bodies".into());}
    let io=crate::groups::h2_io(&target,&upstream).await?;let state=Arc::new(Mutex::new(State::default()));let gate=Gate{io,state:state.clone()};
    let(mut sender,connection)=h2::client::handshake(gate).await.map_err(|e|e.to_string())?;let driver=tokio::spawn(connection);let _guard=Abort(driver.abort_handle());
    tokio::time::timeout(Duration::from_secs(2),async{while state.lock().unwrap().flushes==0{if driver.is_finished(){return Err("HTTP/2 connection failed during startup".to_string());}tokio::time::sleep(Duration::from_millis(1)).await;}Ok(())}).await.map_err(|_|"HTTP/2 settings did not flush")??;
    state.lock().unwrap().armed=true;let mut responses=Vec::new();
    for(i,raw)in requests.iter().enumerate(){
        let msg=Msg::parse(raw);let mut words=msg.first.split_whitespace();let method=words.next().ok_or("Missing method")?;let path=words.next().ok_or("Missing path")?;if !path.starts_with('/'){return Err("Coalesced requests need origin-form paths".into());}
        let mut request=hudsucker::hyper::Request::builder().method(method).uri(format!("{}{path}",target.url())).version(hudsucker::hyper::Version::HTTP_2);
        for(k,v)in &msg.headers{if !["host","connection","keep-alive","proxy-connection","transfer-encoding","upgrade"].contains(&k.to_ascii_lowercase().as_str()){request=request.header(k,v);}}
        let request=request.body(()).map_err(|e|e.to_string())?;
        sender=tokio::time::timeout(Duration::from_secs(2),sender.ready()).await.map_err(|_|"Server stream limit prevents staging this group; no requests released")?.map_err(|e|e.to_string())?;
        let(response,mut body)=sender.send_request(request,msg.body.is_empty()).map_err(|e|e.to_string())?;if !msg.body.is_empty(){body.send_data(bytes::Bytes::from(msg.body),true).map_err(|e|e.to_string())?;}responses.push((i,response));
    }
    let count=requests.len();tokio::time::timeout(Duration::from_secs(2),async{loop{if complete(&state.lock().unwrap().bytes)==count{return Ok(());}if driver.is_finished(){return Err("Connection failed before all requests could be staged".to_string());}tokio::time::sleep(Duration::from_millis(1)).await;}}).await.map_err(|_|"Complete request frames could not be staged; no requests released")??;
    let at=Instant::now();{let mut state=state.lock().unwrap();state.released=true;if let Some(w)=state.waker.take(){w.wake();}}
    let mut tasks=tokio::task::JoinSet::new();for(i,response)in responses{tasks.spawn(async move{let result=async{let res=response.await.map_err(|e|e.to_string())?;let status=res.status().as_u16();let(parts,mut body)=res.into_parts();let mut bytes=Vec::new();while let Some(chunk)=body.data().await{let chunk=chunk.map_err(|e|e.to_string())?;if bytes.len()+chunk.len()>16*1024*1024{return Err("HTTP/2 response exceeded 16 MiB".into());}bytes.extend_from_slice(&chunk);body.flow_control().release_capacity(chunk.len()).map_err(|e|e.to_string())?;}let headers=parts.headers.iter().map(|(k,v)|(k.to_string(),String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();Ok(Reply{status,elapsed:at.elapsed(),raw:Msg{first:format!("HTTP/2 {status}"),headers,body:bytes}.render()})}.await;(i,result)});}
    let mut out=Vec::new();while let Some(result)=tasks.join_next().await{out.push(result.map_err(|e|e.to_string())?);}Ok(out)
}
#[cfg(test)]mod tests{use super::*;#[test]fn requires_complete_header_blocks_and_end_stream(){let headers=[0,0,0,1,1,0,0,0,1];assert_eq!(complete(&headers),0);let mut bytes=headers.to_vec();bytes.extend_from_slice(&[0,0,0,9,4,0,0,0,1]);assert_eq!(complete(&bytes),1);bytes.extend_from_slice(&[0,0,1,1,5,0,0,0,3]);assert_eq!(complete(&bytes),1);bytes.push(0);assert_eq!(complete(&bytes),2);}}
