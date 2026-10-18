//! Project-owned browser state. Credential delivery always requires an exact origin.
use serde::{Serialize,Deserialize};
use std::collections::BTreeMap;
#[derive(Clone,Default,PartialEq,Serialize,Deserialize)]#[serde(default)]
pub struct Storage{pub local:BTreeMap<String,String>,pub session:BTreeMap<String,String>}
#[derive(Clone,Default,PartialEq,Serialize,Deserialize)]#[serde(default)]
pub struct Token{pub enabled:bool,pub origin:String,pub key:String,pub session:bool,pub header:String,pub prefix:String}
#[derive(Clone,Default,PartialEq,Serialize,Deserialize)]#[serde(default)]
pub struct Auth{pub origins:Vec<String>,pub storage:BTreeMap<String,Storage>,pub tokens:Vec<Token>}
pub fn origin(value:&str)->Option<String>{let u=url::Url::parse(value).ok()?;if !matches!(u.scheme(),"http"|"https")||!u.username().is_empty()||u.password().is_some()||u.path()!="/"||u.query().is_some()||u.fragment().is_some(){return None;}Some(u.origin().ascii_serialization())}
fn header(name:&str)->bool{!name.is_empty()&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')&&!["host","cookie","content-length","connection","transfer-encoding","proxy-authorization"].iter().any(|k|name.eq_ignore_ascii_case(k))}
impl Auth{
    pub fn validate(&self)->Result<(),String>{
        if self.origins.len()>10||self.storage.len()>11||self.tokens.len()>20{return Err("Browser state supports 10 SSO origins and 20 token mappings".into());}
        for value in &self.origins{origin(value).ok_or("SSO entries must be exact HTTP(S) origins")?;}
        for(key,state)in &self.storage{origin(key).ok_or("Invalid storage origin")?;if state.local.len()+state.session.len()>1000||state.local.iter().chain(&state.session).any(|(k,v)|k.len()>4096||v.len()>64*1024){return Err("Browser storage exceeds per-origin limits".into());}}
        for token in &self.tokens{origin(&token.origin).ok_or("Token mapping needs an exact origin")?;if !header(&token.header)||token.prefix.contains(['\r','\n']){return Err("Invalid token header mapping".into());}}
        if serde_json::to_vec(self).map_err(|e|e.to_string())?.len()>1024*1024{return Err("Browser state exceeds 1 MiB".into());}Ok(())
    }
    pub fn apply(&self,target:&crate::http::Target,raw:&[u8])->Vec<u8>{let mut m=crate::http::Msg::parse(raw);for token in self.tokens.iter().take(20).filter(|t|t.enabled&&origin(&t.origin).is_some_and(|o|o==target.url())&&header(&t.header)){
        if let Some(state)=self.storage.get(&target.url()){let values=if token.session{&state.session}else{&state.local};if let Some(value)=values.get(&token.key){let value=format!("{}{value}",token.prefix);if !value.contains(['\r','\n']){m.set_header(&token.header,value);}}}
    }m.render()}
    pub fn bootstrap(&self)->String{format!(r#"(() => {{const states={};const s=states[location.origin];if(!s)return;try{{if(sessionStorage.getItem('__ferrite_bootstrap'))return;for(const[k,v]of Object.entries(s.local))localStorage.setItem(k,v);for(const[k,v]of Object.entries(s.session))sessionStorage.setItem(k,v);sessionStorage.setItem('__ferrite_bootstrap','1');}}catch{{}}}})()"#,serde_json::to_string(&self.storage).unwrap_or_else(|_|"{}".into()))}
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn stored_tokens_are_exact_origin_bound_and_structural_headers_are_rejected(){
        let mut auth=Auth::default();auth.storage.insert("https://app.test".into(),Storage{local:BTreeMap::from([("token".into(),"user-token".into())]),..Default::default()});auth.tokens.push(Token{enabled:true,origin:"https://app.test".into(),key:"token".into(),header:"Authorization".into(),prefix:"Bearer ".into(),..Default::default()});auth.validate().unwrap();
        let raw=b"GET / HTTP/1.1\r\n\r\n";let target=crate::http::Target::from_url("https://app.test/").unwrap();assert_eq!(crate::http::Msg::parse(&auth.apply(&target,raw)).header("authorization"),Some("Bearer user-token"));for url in ["http://app.test/","https://app.test:8443/","https://evil.test/"]{assert!(crate::http::Msg::parse(&auth.apply(&crate::http::Target::from_url(url).unwrap(),raw)).header("authorization").is_none());}auth.tokens[0].header="Host".into();assert!(auth.validate().is_err());
    }
    #[test]fn allowed_origins_reject_paths_credentials_and_non_http_schemes(){for invalid in ["https://u:p@app.test/","https://app.test/path","https://app.test/?x=1","file:///tmp/x"]{assert!(origin(invalid).is_none());}assert_eq!(origin("https://app.test/"),Some("https://app.test".into()));}
}
