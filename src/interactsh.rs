//! Bridge to the official client: it owns registration, decryption and polling.
use crate::callbacks::{Interaction, Note};
use std::{
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, BufReader};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn interaction(line: &str) -> Option<Interaction> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let protocol = match value["protocol"].as_str()?.to_ascii_lowercase().as_str() {
        "http" | "https" => "HTTP",
        "dns" => "DNS",
        "smtp" | "smtps" => "SMTP",
        _ => return None,
    };
    let request = value["raw-request"].as_str().unwrap_or("");
    let full_id = value["full-id"]
        .as_str()
        .or_else(|| value["unique-id"].as_str())
        .unwrap_or("");
    if request.is_empty() && full_id.is_empty() {
        return None;
    }
    Some(Interaction {
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        protocol: protocol.into(),
        peer: value["remote-address"].as_str().unwrap_or("unknown").into(),
        payload: format!(
            "{full_id}\n{}",
            &request[..request.floor_char_boundary(64 * 1024)]
        ),
    })
}
fn endpoint(text: &str) -> Option<String> {
    let text = text.trim();
    if text.len() > 253
        || text.is_empty()
        || !text.contains('.')
        || text.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || p.starts_with('-')
                || p.ends_with('-')
                || p.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-')
        })
    {
        return None;
    }
    Some(format!("https://{text}"))
}
#[cfg(test)]
pub async fn run(binary:String,server:String,cancel:Arc<AtomicBool>,notify:impl Fn(Note))->Result<(),String>{run_inner(binary,server,None,cancel,notify).await}
pub async fn run_saved(binary:String,server:String,session:Vec<u8>,cancel:Arc<AtomicBool>,notify:impl Fn(Note))->Result<(),String>{run_inner(binary,server,Some(session),cancel,notify).await}
async fn stop(child:&mut tokio::process::Child){
    if let Some(id)=child.id(){let _=tokio::process::Command::new("kill").args(["-INT",&id.to_string()]).status().await;}
    if tokio::time::timeout(Duration::from_secs(2),child.wait()).await.is_err(){let _=child.kill().await;let _=child.wait().await;}
}
async fn run_inner(binary:String,server:String,saved:Option<Vec<u8>>,cancel:Arc<AtomicBool>,notify:impl Fn(Note))->Result<(),String>{
    let path=std::env::temp_dir().join(format!("ferrite-oast-{}",crate::callbacks::token()?));let mut builder=std::fs::DirBuilder::new();
    #[cfg(unix)]{use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}
    builder.create(&path).map_err(|e|e.to_string())?;let dir=Directory(path);let payload=dir.0.join("payload.txt");let session=dir.0.join("session.yaml");
    let persistent=saved.is_some();let mut checkpointed=false;
    if let Some(saved)=saved{if saved.len()>65536{return Err("Interactsh session exceeds 64 KiB".into());}if !saved.is_empty(){crate::project::atomic_write(&session,&saved).map_err(|e|e.to_string())?;checkpointed=true;}}
    loop {
        let _=std::fs::remove_file(&payload);
        let mut command=tokio::process::Command::new(&binary);command.args(["-auth=false","-json","-n","1","-pi","5","-duc","-ps","-psf"]).arg(&payload).current_dir(&dir.0).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
        if persistent{command.arg("-sf").arg(&session);}
        if !server.trim().is_empty(){command.arg("-server").arg(server.trim());}
        let mut child=command.spawn().map_err(|e|format!("Install interactsh-client or set its executable path: {e}"))?;
        let mut reader=BufReader::new(child.stdout.take().ok_or("Client stdout unavailable")?);let mut line=Vec::new();let mut announced=false;let mut restart=false;
        notify(Note::Status("Registering/resuming Interactsh; polling every five seconds".into()));
        let result=async{
            while !cancel.load(Ordering::Relaxed){
                tokio::select!{
                    byte=reader.read_u8()=>match byte{
                        Ok(b'\n')=>{if let Ok(text)=std::str::from_utf8(&line){if let Some(i)=interaction(text){notify(Note::Interaction(i));}}line.clear();},
                        Ok(b)=>{if line.len()>=128*1024{return Err("Interactsh JSON line exceeded 128 KiB".into());}line.push(b);},
                        Err(e)if e.kind()==std::io::ErrorKind::UnexpectedEof=>return Err("Interactsh client exited; check server availability and client configuration".into()),
                        Err(e)=>return Err(e.to_string()),
                    },
                    _=tokio::time::sleep(Duration::from_millis(100))=>{}
                }
                if !announced&&std::fs::metadata(&payload).is_ok_and(|m|m.len()<=4096){if let Ok(text)=std::fs::read_to_string(&payload){if let Some(base)=text.lines().find_map(endpoint){
                    if persistent&&!checkpointed{restart=true;break;}notify(Note::Endpoint(base));announced=true;
                }}}
            }
            Ok(())
        }.await;
        if persistent{stop(&mut child).await;}else{let _=child.kill().await;let _=child.wait().await;}
        if persistent&&std::fs::metadata(&session).is_ok_and(|m|m.len()<=65536){if let Ok(bytes)=std::fs::read(&session){if !bytes.is_empty(){notify(Note::Session(bytes));checkpointed=true;}}}
        if restart&&!checkpointed{return Err("Client did not save a resumable session on interrupt".into());}
        if !restart||cancel.load(Ordering::Relaxed){return result;}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_official_interactions_and_rejects_logs() {
        let i=interaction(r#"{"protocol":"https","full-id":"abc.example.test","raw-request":"GET /token HTTP/1.1","remote-address":"1.2.3.4"}"#).unwrap();
        assert_eq!(i.protocol, "HTTP");
        assert!(i.payload.contains("/token"));
        assert!(interaction("[INF] hello").is_none());
        assert!(interaction(r#"{"protocol":"dns"}"#).is_none());
        assert!(endpoint("abc.example.test").is_some());
        assert!(endpoint("bad/host.test").is_none());
        assert!(endpoint("bad..test").is_none());
    }
}

#[cfg(test)]
mod bridge_regressions {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn official_cli_bridge_announces_endpoint_correlates_json_and_stops_child() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ferrite-client-fixture-{}",
            crate::callbacks::token().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let dir = Directory(dir);
        let binary = dir.0.join("client");
        std::fs::write(&binary,r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -psf) shift; printf '%s\n' 'session.example.test' > "$1" ;;
  esac
  shift
done
printf '%s\n' '{"protocol":"dns","full-id":"probe.session.example.test","remote-address":"127.0.0.1"}'
while :; do sleep 1; done
"#).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let notes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = notes.clone();
        let task = tokio::spawn(async move {
            run(
                binary.to_string_lossy().into_owned(),
                String::new(),
                flag,
                |note| {
                    record.lock().unwrap().push(note);
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let ready = {
                    let notes = notes.lock().unwrap();
                    notes.iter().any(|n| matches!(n, Note::Endpoint(_)))
                        && notes.iter().any(|n| matches!(n, Note::Interaction(_)))
                };
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        cancel.store(true, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let notes = notes.lock().unwrap();
        assert!(
            notes
                .iter()
                .any(|n| matches!(n,Note::Endpoint(e) if e=="https://session.example.test"))
        );
        assert!(notes.iter().any(
            |n| matches!(n,Note::Interaction(i) if i.protocol=="DNS"&&i.payload.contains("probe"))
        ));
    }
}

#[cfg(test)]mod live_tests{
    use super::*;
    struct Abort(tokio::task::AbortHandle);impl Drop for Abort{fn drop(&mut self){self.0.abort();}}
    async fn exercise(saved:Vec<u8>,previous:Option<String>)->Result<(Vec<u8>,String),String>{
        let binary=std::env::var("FERRITE_INTERACTSH_CLIENT").map_err(|_|"Set FERRITE_INTERACTSH_CLIENT to the official executable")?;
        let notes=Arc::new(std::sync::Mutex::new(Vec::new()));let collected=notes.clone();let cancel=Arc::new(AtomicBool::new(false));let flag=cancel.clone();
        let task=tokio::spawn(async move{run_saved(binary,String::new(),saved,flag,|note|collected.lock().unwrap().push(note)).await});let _guard=Abort(task.abort_handle());
        let result=async{
            let base=tokio::time::timeout(Duration::from_secs(45),async{loop{if let Some(base)=notes.lock().unwrap().iter().find_map(|n|match n{Note::Endpoint(base)=>Some(base.clone()),_=>None}){break Ok(base);}if task.is_finished(){break Err("Client exited before registration");}tokio::time::sleep(Duration::from_millis(100)).await;}}).await.map_err(|_|"Public registration timed out")??;
            let endpoint=previous.unwrap_or_else(||base.clone());let token=crate::callbacks::token()?;let target=crate::http::Target::from_url(&endpoint).ok_or("Invalid service URL")?;
            let raw=format!("GET /ferrite-self-test-{token} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",target.host_header());crate::http::send(&target,raw.as_bytes(),&crate::http::Upstream::None).await?;
            tokio::time::timeout(Duration::from_secs(30),async{loop{if notes.lock().unwrap().iter().any(|n|matches!(n,Note::Interaction(i)if i.protocol=="HTTP"&&i.payload.contains(&token))){break;}tokio::time::sleep(Duration::from_millis(100)).await;}}).await.map_err(|_|"Public HTTP callback was not polled")?;
            Ok::<_,String>(base)
        }.await;
        cancel.store(true,Ordering::Relaxed);tokio::time::timeout(Duration::from_secs(5),task).await.map_err(|_|"Client did not stop")?.map_err(|e|e.to_string())??;
        let base=result?;let saved=notes.lock().unwrap().iter().rev().find_map(|n|match n{Note::Session(bytes)=>Some(bytes.clone()),_=>None}).ok_or("No resumable session was saved")?;Ok((saved,base))
    }
    #[tokio::test]#[ignore="registers with a public Interactsh service; requires explicit network access and official client"]
    async fn resumes_public_session(){let(saved,old)=exercise(vec![],None).await.unwrap();let(_,new)=exercise(saved,Some(old)).await.unwrap();assert!(!new.is_empty());eprintln!("Live Interactsh verification passed: encrypted polling, HTTP callback correlation, checkpoint and restart against the original payload.");}
}
