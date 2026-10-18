//! Explicit opt-in: launches only ephemeral headless profiles and local fixtures.
use super::*;
use crate::robust_tests::{Reply, fixture};

async fn inspect(html: String, headers: Vec<(String, String)>) -> Result<Value, String> {
    let server =
        fixture(move |_| Reply::body(200, &[("Content-Type", "text/html")], html.as_bytes())).await;
    let (proxy, task) = crate::features_tests::start_proxy(Default::default()).await;
    let process = Process::start_with_pin(proxy, "test").await;
    let (mut process, socket) = match process {
        Ok(p) => p,
        Err(e) => {
            task.abort();
            return Err(e);
        }
    };
    let mut cdp = Cdp {
        socket,
        id: 0,
        origin: url::Url::parse(&server.target.url()).unwrap().origin(),
        headers,
        recorded: vec![],
    };
    let result=async {
        cdp.command("Page.enable",json!({})).await?;
        cdp.command("Fetch.enable",json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]})).await?;
        cdp.command("Page.addScriptToEvaluateOnNewDocument",json!({"source":include_str!("../../assets/dom-probe.js")})).await?;
        cdp.command("Page.navigate",json!({"url":format!("{}/#ferrite_canary",server.target.url())})).await?;
        cdp.settle(500).await?;
        cdp.eval("({events:window.__ferriteDOM,prototype:({}).ferrite_canary||null,links:[...document.querySelectorAll('a')].map(a=>a.href)})").await
    }.await;
    process.close().await;
    task.abort();
    result
}

#[tokio::test]
#[ignore = "requires installed Chromium; run the documented browser test command"]
async fn dom_sink_positive_and_text_content_negative_controls() {
    let data=inspect("<div id='unsafe'></div><div id='safe'></div><script>let marker=location.hash.slice(1);document.querySelector('#unsafe').innerHTML=marker;document.querySelector('#safe').textContent=marker;let a=document.createElement('a');a.href='/javascript-only';document.body.append(a);</script>".into(),vec![]).await.unwrap();
    let events = data["events"].as_array().unwrap();
    assert_eq!(
        events.iter().filter(|e| e["sink"] == "innerHTML").count(),
        1
    );
    assert!(events.iter().all(|e| e["sink"] != "textContent"));
    assert!(
        data["links"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u.as_str().unwrap().ends_with("/javascript-only"))
    );
}

#[tokio::test]
#[ignore = "requires installed Chromium; run the documented browser test command"]
async fn browser_records_messages_and_prototype_pollution_evidence() {
    let data=inspect("<script>Object.prototype.ferrite_canary='fixture-pollution';window.postMessage('fixture-message',location.origin);</script>".into(),vec![]).await.unwrap();
    assert_eq!(data["prototype"], "fixture-pollution");
    let events = data["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["kind"] == "prototype"));
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "message" && e["value"] == "fixture-message")
    );
}

#[tokio::test]
#[ignore = "requires installed Chromium; run the documented browser test command"]
async fn browser_blocks_other_origin_requests_instead_of_leaking_authentication() {
    let forbidden = fixture(|_| Reply::body(200, &[], b"should never arrive")).await;
    let html = format!(
        "<script>fetch('{}').catch(()=>{{}});</script>",
        forbidden.target.url()
    );
    let data = inspect(
        html,
        vec![("Authorization".into(), "Bearer fixture-only".into())],
    )
    .await
    .unwrap();
    assert!(data["events"].is_array());
    assert!(
        forbidden.seen.lock().unwrap().is_empty(),
        "browser sent a cross-origin request"
    );
}

#[test]
fn stale_browser_events_cannot_overwrite_the_active_run() {
    let mut lab = BrowserLab {
        run: 42,
        status: "active".into(),
        cancel: Some(Arc::new(AtomicBool::new(false))),
        ..Default::default()
    };
    lab.on_note(41, Note::Status("stale".into()));
    lab.on_note(
        41,
        Note::Page(Page {
            url: "http://stale.invalid/".into(),
            links: vec![],
            evidence: json!({}),
        }),
    );
    lab.on_note(41, Note::Done);
    assert_eq!(lab.status, "active");
    assert!(lab.pages.is_empty());
    assert!(lab.cancel.is_some());
}

#[tokio::test]
#[ignore = "requires installed Chromium; run the documented browser test command"]
async fn workflow_replay_fills_clicks_asserts_messages_and_records_source_sink_traces() {
    let html = "<input id='value'><button id='go' onclick=\"document.querySelector('#out').innerHTML=document.querySelector('#value').value\">Go</button><div id='out'></div><script>addEventListener('message',e=>document.querySelector('#out').setAttribute('srcdoc',e.data));const source=new URLSearchParams(location.search).get('q');</script>";
    let server =
        fixture(move |_| Reply::body(200, &[("Content-Type", "text/html")], html.as_bytes())).await;
    let (proxy, task) = crate::features_tests::start_proxy(Default::default()).await;
    let (mut process, socket) = Process::start_with_pin(proxy, "test").await.unwrap();
    let mut cdp = Cdp {
        socket,
        id: 0,
        origin: url::Url::parse(&server.target.url()).unwrap().origin(),
        headers: vec![],
        recorded: vec![],
    };
    let scope = crate::rules::Compiled::new(Default::default());
    let cancel = AtomicBool::new(false);
    let result = async {
        cdp.command("Page.enable", json!({})).await?;
        cdp.command("Runtime.enable", json!({})).await?;
        cdp.command("Runtime.addBinding", json!({"name":"__ferriteRecord"}))
            .await?;
        cdp.command(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
        )
        .await?;
        cdp.command(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source":include_str!("../../assets/dom-probe.js")}),
        )
        .await?;
        cdp.command(
            "Page.navigate",
            json!({"url":format!("{}/?q=ferrite_canary",server.target.url())}),
        )
        .await?;
        cdp.settle(300).await?;
        replay(
            &mut cdp,
            &[
                Step::Fill {
                    selector: "#value".into(),
                    value: "ferrite_canary'\"".into(),
                },
                Step::Click {
                    selector: "#go".into(),
                },
                Step::AssertText {
                    selector: "#out".into(),
                    text: "ferrite_canary".into(),
                },
                Step::PostMessage {
                    data: json!("ferrite_canary-message"),
                },
                Step::Wait { ms: 50 },
            ],
            &scope,
            &cancel,
        )
        .await?;
        let data = cdp
            .eval("({events:window.__ferriteDOM,actions:window.__ferriteActions})")
            .await?;
        assert!(cdp.recorded.iter().any(|a| matches!(a, Step::Fill { .. })));
        assert!(cdp.recorded.iter().any(|a| matches!(a, Step::Click { .. })));
        assert!(
            replay(
                &mut cdp,
                &[Step::Navigate {
                    url: "http://outside.invalid/".into()
                }],
                &scope,
                &cancel
            )
            .await
            .is_err()
        );
        assert!(
            replay(
                &mut cdp,
                &[Step::AssertText {
                    selector: "#missing".into(),
                    text: "nope".into()
                }],
                &scope,
                &cancel
            )
            .await
            .is_err()
        );
        Ok::<_, String>(data)
    }
    .await;
    process.close().await;
    task.abort();
    let data = result.unwrap();
    let events = data["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["source"] == "get"));
    assert!(events.iter().any(|e| e["sink"] == "innerHTML"));
    assert!(events.iter().any(|e| e["sink"] == "setAttribute:srcdoc"));
    let actions = data["actions"].as_array().unwrap();
    assert!(actions.iter().any(|a| a["action"] == "fill"));
    assert!(actions.iter().any(|a| a["action"] == "click"));
}
