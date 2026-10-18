use super::*;
use crate::{
    groups::{self, Mode},
    http::{self, Upstream},
};
use http_body_util::{BodyExt, Full};
use hudsucker::{
    futures::{SinkExt, StreamExt},
    hyper::{self, Response, service::service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};

struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn http2_preserves_binary_body_authority_and_independent_member_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let record = captured.clone();
    let _server = Abort(tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let record = record.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = body.collect().await.unwrap().to_bytes();
                record
                    .lock()
                    .unwrap()
                    .push((parts.uri, parts.headers, body.to_vec()));
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(body)))
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    }));
    let target = Target::from_url(&format!("http://{address}")).unwrap();
    let raw=[format!("POST /binary HTTP/1.1\r\nHost: wrong.invalid\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\n").as_bytes(),b"\0\xffAB"].concat();
    let invalid = b"GE(T / HTTP/1.1\r\n\r\n".to_vec();
    let results = tokio::time::timeout(
        DEADLINE,
        groups::send(target, vec![raw, invalid], Upstream::None, Mode::Http2),
    )
    .await
    .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().find(|(i, _)| *i == 1).unwrap().1.is_err());
    let result = results
        .into_iter()
        .find(|(i, _)| *i == 0)
        .unwrap()
        .1
        .unwrap();
    assert_eq!(Msg::parse(&result.raw).body, b"\0\xffAB");
    let records = captured.lock().unwrap();
    assert_eq!(records.len(), 1);
    let (uri, headers, body) = &records[0];
    assert_eq!(uri.authority().unwrap().as_str(), address.to_string());
    assert!(headers.get("connection").is_none());
    assert!(headers.get("proxy-connection").is_none());
    assert_eq!(body, b"\0\xffAB");
}

#[tokio::test]
async fn oversized_http2_group_is_rejected_or_completes_without_barrier_deadlock() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _server = Abort(tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(io),
                service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                        bytes::Bytes::from_static(b"ok"),
                    )))
                }),
            )
            .await;
    }));
    let target = Target::from_url(&format!("http://{address}")).unwrap();
    let jobs = (0..101)
        .map(|_| request(&target, "GET", "/", b""))
        .collect();
    let results = tokio::time::timeout(
        Duration::from_secs(2),
        groups::send(target, jobs, Upstream::None, Mode::Http2),
    )
    .await;
    assert!(
        results.is_ok(),
        "101-member group deadlocked before any request could pass the barrier"
    );
    assert_eq!(results.unwrap().len(), 101);
}

#[tokio::test]
async fn proxy_forwards_more_than_capture_limit_without_truncating_browser_bytes() {
    let body = vec![b'x'; crate::retention::MESSAGE + 65536];
    let expected = body.clone();
    let server =
        fixture(move |_| Reply::body(200, &[("Content-Type", "application/octet-stream")], &body))
            .await;
    let (proxy, task) = crate::features_tests::start_proxy(Default::default()).await;
    let _proxy = Abort(task);
    let mut socket = tokio::net::TcpStream::connect(proxy).await.unwrap();
    socket
        .write_all(
            format!(
                "GET {}/large HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                server.target.url(),
                server.target.host_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(DEADLINE, socket.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Msg::parse(&raw).decoded_body(), expected);
}

#[tokio::test]
async fn proxy_preserves_gzip_encoding_and_payload_for_streamed_responses() {
    use std::io::Write;
    let original = b"fixture-compressed-body".repeat(5000);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();
    let server = fixture(move |_| {
        Reply::body(
            200,
            &[("Content-Encoding", "gzip"), ("Content-Type", "text/plain")],
            &compressed,
        )
    })
    .await;
    let (proxy, task) = crate::features_tests::start_proxy(Default::default()).await;
    let _proxy = Abort(task);
    let response = http::send(
        &server.target,
        &request(&server.target, "GET", "/gzip", b""),
        &Upstream::Http(proxy.to_string()),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    let msg = Msg::parse(&response.raw);
    assert_eq!(msg.header("content-encoding"), Some("gzip"));
    assert_eq!(msg.decoded_body(), original);
}

#[tokio::test]
async fn proxy_websocket_upgrade_echoes_text_binary_and_negotiated_protocol() {
    use hudsucker::tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{
            Message,
            client::IntoClientRequest,
            handshake::server::{Request as WsRequest, Response as WsResponse},
        },
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _server = Abort(tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let mut ws = accept_hdr_async(io, |request: &WsRequest, mut response: WsResponse| {
            assert_eq!(
                request.headers().get("sec-websocket-protocol").unwrap(),
                "fixture"
            );
            response
                .headers_mut()
                .insert("sec-websocket-protocol", "fixture".parse().unwrap());
            Ok(response)
        })
        .await
        .unwrap();
        for _ in 0..2 {
            let message = ws.next().await.unwrap().unwrap();
            ws.send(message).await.unwrap();
        }
    }));
    let (proxy, task) = crate::features_tests::start_proxy(Default::default()).await;
    let _proxy = Abort(task);
    let mut request = format!("ws://{address}/echo")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "fixture".parse().unwrap());
    let (mut socket, response) = tokio::time::timeout(
        DEADLINE,
        http::websocket(request, &Upstream::Http(proxy.to_string())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        "fixture"
    );
    for message in [
        Message::Text("hello".into()),
        Message::Binary(bytes::Bytes::from_static(b"\0\xffAB")),
    ] {
        socket.send(message.clone()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(DEADLINE, socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            message
        );
    }
}

async fn tls_server(protocol: &'static [u8]) -> (Target, Abort) {
    use hudsucker::{
        rcgen::{CertificateParams, KeyPair},
        rustls::{self, pki_types::PrivatePkcs8KeyDer},
    };
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    config.alpn_protocols = vec![protocol.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Abort(tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let Ok(tls) = acceptor.accept(io).await else {
            return;
        };
        if protocol == b"h2" {
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(tls),
                    service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            bytes::Bytes::from_static(b"tls-h2"),
                        )))
                    }),
                )
                .await;
        }
    }));
    (
        Target::from_url(&format!("https://{address}")).unwrap(),
        task,
    )
}

#[tokio::test]
async fn http2_tls_accepts_fixture_certificate_and_negotiates_h2() {
    let (target, _server) = tls_server(b"h2").await;
    let requests = vec![request(&target, "GET", "/tls", b"")];
    let results = tokio::time::timeout(
        DEADLINE,
        groups::send(target, requests, Upstream::None, Mode::Http2),
    )
    .await
    .unwrap();
    let response = results.into_iter().next().unwrap().1.unwrap();
    assert_eq!(Msg::parse(&response.raw).body, b"tls-h2");
}

#[tokio::test]
async fn http2_tls_reports_error_when_target_only_supports_http1() {
    let (target, _server) = tls_server(b"http/1.1").await;
    let requests = vec![request(&target, "GET", "/tls", b"")];
    let results = tokio::time::timeout(
        DEADLINE,
        groups::send(target, requests, Upstream::None, Mode::Http2),
    )
    .await
    .unwrap();
    assert!(results.into_iter().next().unwrap().1.is_err());
}

#[tokio::test]
async fn individual_http2_client_send_applies_cookies_and_preserves_wire_evidence() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = Target::from_url(&format!("http://{address}")).unwrap();
    let server = Abort(tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(io),
                service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        assert_eq!(request.version(), hyper::Version::HTTP_2);
                        assert_eq!(request.headers()["cookie"], "sid=user");
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(body)))
                    },
                ),
            )
            .await;
    }));
    let jar: crate::session::Shared = Arc::default();
    jar.lock()
        .unwrap()
        .set_cookie(&target.url(), "sid=user; Path=/")
        .unwrap();
    let client = crate::session::Client::new(jar, true, true);
    let raw = request(&target, "POST", "/binary", b"\0\xffpayload");
    let (sent, reply) = tokio::time::timeout(
        DEADLINE,
        client.send_protocol(&target, &raw, &Upstream::None, true),
    )
    .await
    .unwrap();
    assert_eq!(Msg::parse(&sent).header("cookie"), Some("sid=user"));
    let reply = reply.unwrap();
    assert!(reply.raw.starts_with(b"HTTP/2 200"));
    assert_eq!(Msg::parse(&reply.raw).body, b"\0\xffpayload");
    drop(server);
}

#[tokio::test]
async fn coalesced_http2_releases_all_complete_requests_and_preserves_binary_bodies(){
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();let captured=Arc::new(Mutex::new(Vec::new()));let record=captured.clone();
    let _server=Abort(tokio::spawn(async move{let(io,_)=listener.accept().await.unwrap();let _=hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(io),service_fn(move|r:hyper::Request<hyper::body::Incoming>|{let record=record.clone();async move{let body=r.into_body().collect().await.unwrap().to_bytes();record.lock().unwrap().push(body.to_vec());Ok::<_,std::convert::Infallible>(Response::new(Full::new(body)))}})).await;}));
    let target=Target::from_url(&format!("http://{address}")).unwrap();let jobs:Vec<_>=[b"\0\xffa".as_slice(),b"second",b"third"].iter().map(|b|request(&target,"POST","/",b)).collect();let out=tokio::time::timeout(DEADLINE,groups::send(target,jobs,Upstream::None,Mode::Coalesced)).await.unwrap();assert_eq!(out.len(),3);for(_,r)in out{assert_eq!(r.unwrap().status,200);}assert_eq!(captured.lock().unwrap().len(),3);assert!(captured.lock().unwrap().iter().any(|b|b==b"\0\xffa"));
}
#[tokio::test]
async fn coalesced_limits_reject_before_connecting(){let target=Target::from_url("http://127.0.0.1:1/").unwrap();let raw=request(&target,"POST","/",&vec![0;33*1024]);let out=groups::send(target,vec![raw],Upstream::None,Mode::Coalesced).await;assert!(out[0].1.as_ref().err().unwrap().contains("32 KiB"));}
