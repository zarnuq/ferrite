//! Import API descriptions as editable, unsent requests.
use crate::{Action, Env, Event, http::{self, Msg, Target}};
use eframe::egui;
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Operation { pub name: String, pub target: Target, pub request: Vec<u8> }
fn reference<'a>(root: &'a Value, v: &'a Value) -> &'a Value {
    v.get("$ref").and_then(Value::as_str).and_then(|r| r.strip_prefix('#')).and_then(|p| root.pointer(p)).unwrap_or(v)
}
fn sample(root: &Value, schema: &Value, depth: usize) -> Value {
    if depth > 5 { return Value::Null; }
    let s = reference(root, schema);
    if let Some(v) = s.get("example").or(s.get("default")).or_else(|| s.get("enum").and_then(|e| e.get(0))) { return v.clone(); }
    match s.get("type").and_then(Value::as_str).unwrap_or(if s.get("properties").is_some() { "object" } else { "string" }) {
        "object" => Value::Object(s.get("properties").and_then(Value::as_object).map(|p| p.iter().map(|(k,v)| (k.clone(),sample(root,v,depth+1))).collect()).unwrap_or_default()),
        "array" => json!([sample(root, &s["items"], depth+1)]),
        "integer" | "number" => json!(1), "boolean" => json!(true), _ => json!("test"),
    }
}
fn text(v: Value) -> String { v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()) }
fn operation(name: String, method: &str, url: &str, headers: Vec<(String,String)>, body: Vec<u8>) -> Result<Operation,String> {
    let u = url::Url::parse(url).map_err(|e| e.to_string())?;
    if !matches!(u.scheme(), "http" | "https") { return Err("API URL must be HTTP(S)".into()); }
    if !u.username().is_empty() || u.password().is_some() { return Err("API URL must not contain credentials".into()); }
    let target = Target::from_url(url).ok_or("API URL must be HTTP(S)")?;
    let mut msg = Msg {first: format!("{method} {} HTTP/1.1",http::url_path(url)),headers,body};
    msg.set_header("Host",target.host_header()); msg.set_header("Connection","close".into());
    if !msg.body.is_empty() { msg.set_header("Content-Length",msg.body.len().to_string()); }
    Ok(Operation {name,target,request:msg.render()})
}

pub fn parse(input: &str, base: &str) -> Result<Vec<Operation>,String> {
    if input.trim_start().starts_with('<') { return wsdl(input,base); }
    let root: Value = serde_json::from_str(input).map_err(|e| format!("Use JSON OpenAPI/Postman/GraphQL, or XML WSDL: {e}"))?;
    let mut out = Vec::new();
    if root.get("openapi").is_some() || root.get("swagger").is_some() {
        let default_base = root["servers"][0]["url"].as_str().map(str::to_string).unwrap_or_else(|| format!("{}://{}{}",root["schemes"][0].as_str().unwrap_or("https"),root["host"].as_str().unwrap_or("example.com"),root["basePath"].as_str().unwrap_or("")));
        let base = if base.trim().is_empty() {default_base.as_str()} else {base};
        for (path,item) in root["paths"].as_object().ok_or("OpenAPI paths is missing")? {
            let item = reference(&root,item);
            for method in ["get","post","put","patch","delete","head","options","trace"] {
                let Some(op) = item.get(method) else {continue};
                let mut path = path.clone(); let mut query = Vec::new(); let mut headers = Vec::new();
                let mut body = Vec::new();
                let params = item["parameters"].as_array().into_iter().flatten().chain(op["parameters"].as_array().into_iter().flatten());
                for p in params {
                    let p = reference(&root,p); let name = p["name"].as_str().unwrap_or("param");
                    let value = text(p.get("example").cloned().unwrap_or_else(|| sample(&root,p.get("schema").unwrap_or(p),0)));
                    match p["in"].as_str().unwrap_or("") {
                        "path" => path = path.replace(&format!("{{{name}}}"), &percent_encoding::utf8_percent_encode(&value,percent_encoding::NON_ALPHANUMERIC).to_string()),
                        "query" => query.push((name.to_string(),value)),
                        "header" => headers.push((name.to_string(),value)),
                        "cookie" => headers.push(("Cookie".into(),format!("{name}={value}"))),
                        "body" => {body = serde_json::to_vec(&sample(&root,&p["schema"],0)).unwrap(); headers.push(("Content-Type".into(),"application/json".into()));},
                        _ => {},
                    }
                }
                if let Some(request_body) = op.get("requestBody") {
                    let rb = reference(&root,request_body);
                    if let Some(content) = rb["content"].as_object() {
                        if let Some((mime,media)) = content.iter().find(|(k,_)| k.as_str() == "application/json").or_else(|| content.iter().next()) {
                            let value = media.get("example").cloned().unwrap_or_else(|| sample(&root,&media["schema"],0));
                            body = if mime.contains("json") {serde_json::to_vec(&value).unwrap()} else if mime == "application/x-www-form-urlencoded" {url::form_urlencoded::Serializer::new(String::new()).extend_pairs(value.as_object().into_iter().flatten().map(|(k,v)| (k.clone(),text(v.clone())))).finish().into_bytes()} else {text(value).into_bytes()};
                            headers.push(("Content-Type".into(),mime.clone()));
                        }
                    }
                }
                let mut url = url::Url::parse(&format!("{}{path}",base.trim_end_matches('/'))).map_err(|e| e.to_string())?;
                url.query_pairs_mut().extend_pairs(query);
                out.push(operation(op["operationId"].as_str().unwrap_or(path.as_str()).into(),&method.to_uppercase(),url.as_str(),headers,body)?);
            }
        }
    } else if root.get("item").is_some() {
        let vars: Vec<_> = root["variable"].as_array().into_iter().flatten().filter_map(|v| Some((v["key"].as_str()?.to_string(),text(v["value"].clone())))).collect();
        postman(&root["item"],base,&vars,&mut out,0)?;
    } else if root.pointer("/data/__schema").is_some() || root.get("__schema").is_some() {
        graphql(&root,base,&mut out)?;
    } else { return Err("Unrecognized API definition".into()); }
    if out.len() > 1000 {return Err("Definition exceeds 1,000 operations".into());}
    Ok(out)
}
fn postman(items: &Value, base: &str, vars: &[(String,String)], out: &mut Vec<Operation>, depth: usize) -> Result<(),String> {
    if depth > 16 {return Err("Postman nesting exceeds 16 levels".into());}
    for item in items.as_array().into_iter().flatten() {
        if out.len() >= 1000 {return Err("Too many operations".into());}
        if item.get("item").is_some() {postman(&item["item"],base,vars,out,depth+1)?; continue;}
        let r = &item["request"];
        let mut url = r["url"].as_str().or_else(|| r["url"]["raw"].as_str()).unwrap_or("").to_string();
        for (k,v) in vars {url = url.replace(&format!("{{{{{k}}}}}"),v);}
        if !base.is_empty() {let u = url::Url::parse(&url).map_err(|e|e.to_string())?; url = format!("{}{}",base.trim_end_matches('/'),http::url_path(u.as_str()));}
        if url.contains("{{") {return Err("Resolve Postman URL variables before importing".into());}
        let headers = r["header"].as_array().into_iter().flatten().filter(|h| h["disabled"] != true).filter_map(|h|Some((h["key"].as_str()?.into(),h["value"].as_str()?.into()))).collect();
        let body = match r["body"]["mode"].as_str() {Some("raw") => r["body"]["raw"].as_str().unwrap_or("").as_bytes().to_vec(),Some("urlencoded")=>url::form_urlencoded::Serializer::new(String::new()).extend_pairs(r["body"]["urlencoded"].as_array().into_iter().flatten().filter_map(|v|Some((v["key"].as_str()?,v["value"].as_str()?)))).finish().into_bytes(),Some(mode)=>return Err(format!("Postman body mode {mode} needs manual preparation")),_=>Vec::new()};
        out.push(operation(item["name"].as_str().unwrap_or("Request").into(),r["method"].as_str().unwrap_or("GET"),&url,headers,body)?);
    }
    Ok(())
}
fn graphql(root: &Value, endpoint: &str, out: &mut Vec<Operation>) -> Result<(),String> {
    let schema = root.pointer("/data/__schema").unwrap_or(&root["__schema"]);
    let types = schema["types"].as_array().ok_or("GraphQL introspection needs types")?;
    for (key,kind) in [("queryType","query"),("mutationType","mutation")] {
        let name = schema[key]["name"].as_str().unwrap_or("");
        let Some(t) = types.iter().find(|t|t["name"] == name) else {continue};
        for field in t["fields"].as_array().into_iter().flatten() {
            let name = field["name"].as_str().unwrap_or("field");
            let mut vars = serde_json::Map::new(); let mut definitions = Vec::new(); let mut args = Vec::new();
            for a in field["args"].as_array().into_iter().flatten() {
                let n = a["name"].as_str().unwrap_or("arg");
                let ty = graphql_type(&a["type"]);
                definitions.push(format!("${n}:{ty}")); args.push(format!("{n}:${n}"));
                vars.insert(n.into(),graphql_sample(&a["type"]));
            }
            let mut ty = &field["type"]; while ty["ofType"].is_object() {ty=&ty["ofType"];}
            let selection = if matches!(ty["kind"].as_str(),Some("OBJECT"|"INTERFACE"|"UNION")) {" { __typename }"} else {""};
            let defs=if definitions.is_empty(){String::new()}else{format!("({})",definitions.join(","))};
            let args=if args.is_empty(){String::new()}else{format!("({})",args.join(","))};
            let body=serde_json::to_vec(&json!({"query":format!("{kind} Ferrite{defs} {{ {name}{args}{selection} }}"),"variables":vars})).unwrap();
            out.push(operation(format!("{kind} {name}"),"POST",endpoint,vec![("Content-Type".into(),"application/json".into())],body)?);
        }
    }
    Ok(())
}
fn graphql_sample(t: &Value) -> Value {
    match t["kind"].as_str() {
        Some("NON_NULL") => graphql_sample(&t["ofType"]),
        Some("LIST") => json!([graphql_sample(&t["ofType"])]),
        _ => match t["name"].as_str() { Some("Int" | "Float") => json!(1), Some("Boolean") => json!(true), _ => json!("test") },
    }
}
fn graphql_type(t: &Value) -> String {match t["kind"].as_str(){Some("NON_NULL")=>format!("{}!",graphql_type(&t["ofType"])),Some("LIST")=>format!("[{}]",graphql_type(&t["ofType"])),_=>t["name"].as_str().unwrap_or("String").into()}}
fn wsdl(input: &str, base: &str) -> Result<Vec<Operation>,String> {
    use quick_xml::{Reader, events::Event as Xml};
    let mut reader = Reader::from_str(input); let mut names=std::collections::BTreeSet::new(); let mut endpoint=base.to_string(); let mut ns=String::new();
    loop {match reader.read_event().map_err(|e|e.to_string())? {
        Xml::Start(e)|Xml::Empty(e)=>{
            let local=e.local_name();
            for a in e.attributes() {let a=a.map_err(|e|e.to_string())?;let value=a.decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder()).map_err(|e|e.to_string())?.into_owned();
                if local.as_ref()==b"operation" && a.key.as_ref()==b"name" {names.insert(value.clone());}
                if local.as_ref()==b"address" && a.key.as_ref()==b"location" && base.is_empty() {endpoint=value.clone();}
                if a.key.as_ref()==b"targetNamespace" {ns=value;}
            }
        },Xml::Eof=>break,_=>{}
    }}
    if names.is_empty(){return Err("No WSDL operations found".into());}
    names.into_iter().map(|name| {
        let body=format!(r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><{name} xmlns="{}"/></soap:Body></soap:Envelope>"#,ns.replace('&',"&amp;").replace('"',"&quot;"));
        operation(name,"POST",&endpoint,vec![("Content-Type".into(),"text/xml; charset=utf-8".into())],body.into_bytes())
    }).collect()
}

#[derive(Default)]
pub struct Api { input:String, base:String, path:String, message:String, pub operations:Vec<Operation>, selected:usize, busy:bool }
impl Api {
    pub fn received(&mut self,result:Result<String,String>) {self.busy=false;match result {Ok(text)=>{self.input=text;self.import();},Err(e)=>self.message=e}}
    fn import(&mut self) {match parse(&self.input,&self.base) {Ok(ops)=>{self.message=format!("{} unsent request templates. Review sample values and authentication before sending.",ops.len());self.operations=ops;self.selected=0;},Err(e)=>self.message=e}}
    pub fn ui(&mut self,ui:&mut egui::Ui,env:&mut Env) {
        ui.horizontal(|ui| {ui.label("Base URL / GraphQL endpoint");ui.add(egui::TextEdit::singleline(&mut self.base).desired_width(400.0));});
        ui.horizontal(|ui| {ui.add(egui::TextEdit::singleline(&mut self.path).hint_text("File path or definition URL").desired_width(400.0));
            if ui.button("Read file").clicked(){match std::fs::read_to_string(&self.path){Ok(s)=>{self.input=s;self.import();},Err(e)=>self.message=e.to_string()}}
            for (label,introspect) in [("Fetch definition",false),("GraphQL introspection",true)] {if ui.add_enabled(!self.busy,egui::Button::new(label)).clicked(){
                let url=if introspect {self.base.clone()}else{self.path.clone()}; let upstream=env.upstream();let client=env.session(true);self.busy=true;
                env.spawn(async move {let result=async{let t=Target::from_url(&url).ok_or("Invalid HTTP(S) URL")?;
                    let body=if introspect {serde_json::to_vec(&json!({"query":"{__schema{queryType{name} mutationType{name} types{kind name fields{name args{name type{kind name ofType{kind name ofType{kind name}}}} type{kind name ofType{kind name ofType{kind name}}}}}}}"})).unwrap()}else{Vec::new()};
                    let op=operation("Definition".into(),if introspect{"POST"}else{"GET"},&url,vec![("Content-Type".into(),"application/json".into())],body)?;
                    let(_,r)=client.send(&t,&op.request,&upstream).await;let r=r?;if r.status!=200{return Err(format!("Definition returned {}",r.status));}String::from_utf8(Msg::parse(&r.raw).decoded_body()).map_err(|e|e.to_string())}.await;Event::Api(result)});
            }}
        });
        ui.horizontal(|ui|{if ui.button("Import pasted definition").clicked(){self.import();}ui.label(&self.message);});
        ui.collapsing("Definition JSON / WSDL XML",|ui|{ui.add(egui::TextEdit::multiline(&mut self.input).desired_rows(8).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));});
        ui.horizontal(|ui|{if ui.button("All to Repeater").clicked(){for op in &self.operations {env.actions.push(Action::Repeater(op.target.clone(),op.request.clone()));}}});
        egui::ScrollArea::vertical().max_height(220.0).show(ui,|ui|{for(i,op)in self.operations.iter().enumerate(){ui.selectable_value(&mut self.selected,i,&op.name);}});
        if let Some(op)=self.operations.get(self.selected){ui.horizontal(|ui|{if ui.button("Send to Repeater").clicked(){env.actions.push(Action::Repeater(op.target.clone(),op.request.clone()));}if ui.button("Scan selected").clicked(){env.actions.push(Action::Scan(op.target.clone(),op.request.clone()));}});ui.monospace(String::from_utf8_lossy(&op.request));}
    }
}
#[cfg(test)] mod tests {use super::*;
    #[test]fn imports_openapi_refs_paths_and_json(){let ops=parse(r##"{"openapi":"3.0.0","servers":[{"url":"https://example.com/v1"}],"paths":{"/users/{id}":{"post":{"parameters":[{"name":"id","in":"path","schema":{"type":"integer"}}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/User"}}}}}}},"components":{"schemas":{"User":{"type":"object","properties":{"name":{"type":"string"}}}}}}"##,"").unwrap();assert_eq!(ops.len(),1);let m=Msg::parse(&ops[0].request);assert!(m.first.contains("/v1/users/1"));assert_eq!(serde_json::from_slice::<Value>(&m.body).unwrap()["name"],"test");}
    #[test]fn imports_postman_and_wsdl(){assert_eq!(parse(r#"{"item":[{"name":"x","request":{"method":"GET","url":"https://example.com/a"}}]}"#,"").unwrap().len(),1);let ops=parse(r#"<definitions targetNamespace="urn:t"><operation name="GetUser"/><address location="https://example.com/soap"/></definitions>"#,"").unwrap();assert!(String::from_utf8_lossy(&ops[0].request).contains("GetUser"));}
}
