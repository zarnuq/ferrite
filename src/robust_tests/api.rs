use crate::{api_import::parse, http::Msg};
use serde_json::{Value, json};

fn openapi(operation: Value) -> Value {
    json!({"openapi":"3.0.3","servers":[{"url":"https://example.test/v1"}],"paths":{"/items/{id}":{"post":operation}}})
}

#[test]
fn required_path_query_header_cookie_and_body_values_survive_import() {
    let spec = openapi(json!({"operationId":"saveItem","parameters":[
        {"name":"id","in":"path","example":"one/two"},
        {"name":"q","in":"query","example":"space & plus+"},
        {"name":"X-Tenant","in":"header","example":"team-a"},
        {"name":"session","in":"cookie","example":"abc"}
    ],"requestBody":{"content":{"application/json":{"example":{"message":"hello"}}}}}));
    let operations = parse(&spec.to_string(), "").unwrap();
    assert_eq!(operations.len(), 1);
    let request = Msg::parse(&operations[0].request);
    assert!(request.first.starts_with("POST /v1/items/one%2Ftwo?"));
    let path = request.first.split_whitespace().nth(1).unwrap();
    let url = url::Url::parse(&format!("https://example.test{path}")).unwrap();
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "q").unwrap().1,
        "space & plus+"
    );
    assert_eq!(request.header("x-tenant"), Some("team-a"));
    assert_eq!(request.header("cookie"), Some("session=abc"));
    assert_eq!(
        request
            .header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        request.body.len()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        json!({"message":"hello"})
    );
}

#[test]
fn explicit_base_overrides_untrusted_definition_server() {
    let spec = openapi(json!({}));
    let operations = parse(&spec.to_string(), "http://127.0.0.1:9000/api").unwrap();
    assert_eq!(operations[0].target.url(), "http://127.0.0.1:9000");
    assert!(
        Msg::parse(&operations[0].request)
            .first
            .starts_with("POST /api/items/")
    );
}

#[test]
fn local_refs_array_defaults_enums_and_recursion_are_bounded() {
    let mut spec = openapi(json!({"requestBody":{"$ref":"#/components/requestBodies/Item"}}));
    spec["components"] = json!({"requestBodies":{"Item":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}},"schemas":{"Item":{"type":"object","properties":{"enabled":{"type":"boolean"},"items":{"type":"array","items":{"type":"integer"}},"state":{"enum":["draft","sent"]},"count":{"default":7},"child":{"$ref":"#/components/schemas/Item"}}}}});
    let operations = parse(&spec.to_string(), "").unwrap();
    let body: Value = serde_json::from_slice(&Msg::parse(&operations[0].request).body).unwrap();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["items"], json!([1]));
    assert_eq!(body["state"], "draft");
    assert_eq!(body["count"], 7);
    assert!(
        body.to_string().len() < 20_000,
        "recursive schemas must terminate"
    );
}

#[test]
fn form_encoded_body_round_trips_special_characters() {
    let spec = openapi(
        json!({"requestBody":{"content":{"application/x-www-form-urlencoded":{"example":{"a":"hello & goodbye","b":"+"}}}}}),
    );
    let operations = parse(&spec.to_string(), "").unwrap();
    let request = Msg::parse(&operations[0].request);
    let pairs: Vec<_> = url::form_urlencoded::parse(&request.body).collect();
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "a" && v == "hello & goodbye")
    );
    assert!(pairs.iter().any(|(k, v)| k == "b" && v == "+"));
}

#[test]
fn postman_nested_folders_variables_and_disabled_headers() {
    let spec = json!({"variable":[{"key":"base","value":"https://example.test"}],"item":[{"name":"folder","item":[{"name":"read","request":{"method":"GET","url":{"raw":"{{base}}/items?q=a"},"header":[{"key":"X-Enabled","value":"yes"},{"key":"X-Disabled","value":"no","disabled":true}]}}]}]});
    let operations = parse(&spec.to_string(), "").unwrap();
    let request = Msg::parse(&operations[0].request);
    assert_eq!(operations[0].name, "read");
    assert_eq!(request.header("x-enabled"), Some("yes"));
    assert!(request.header("x-disabled").is_none());
    assert!(request.first.contains("/items?q=a"));
}

#[test]
fn postman_rejects_unresolved_variables_and_unsupported_file_bodies() {
    for request in [
        json!({"url":"{{unknown}}/x"}),
        json!({"url":"https://example.test/","body":{"mode":"file"}}),
    ] {
        assert!(parse(&json!({"item":[{"request":request}]}).to_string(), "").is_err());
    }
}

#[test]
fn graphql_preserves_non_null_list_types_and_object_selection() {
    let spec = json!({"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","fields":[{"name":"items","args":[{"name":"ids","type":{"kind":"NON_NULL","ofType":{"kind":"LIST","ofType":{"kind":"SCALAR","name":"ID"}}}}],"type":{"kind":"OBJECT","name":"Item"}}]}]}}});
    let operations = parse(&spec.to_string(), "https://example.test/graphql").unwrap();
    let body: Value = serde_json::from_slice(&Msg::parse(&operations[0].request).body).unwrap();
    assert!(body["query"].as_str().unwrap().contains("$ids:[ID]!"));
    assert!(body["query"].as_str().unwrap().contains("__typename"));
    assert!(
        body["variables"]["ids"].is_array(),
        "GraphQL list arguments must generate array variables"
    );
}

#[test]
fn wsdl_escapes_namespaces_and_deduplicates_operations() {
    let spec = r#"<definitions targetNamespace="urn:example&amp;test"><operation name="Read"/><operation name="Read"/><address location="https://example.test/soap"/></definitions>"#;
    let operations = parse(spec, "").unwrap();
    assert_eq!(operations.len(), 1);
    assert!(String::from_utf8_lossy(&operations[0].request).contains("urn:example&amp;test"));
}

#[test]
fn imports_reject_url_credentials_and_non_http_schemes() {
    for base in [
        "file:///tmp/spec",
        "ftp://example.test",
        "https://user:secret@example.test",
    ] {
        assert!(
            parse(&openapi(json!({})).to_string(), base).is_err(),
            "accepted {base}"
        );
    }
}

#[test]
fn malformed_and_unknown_definitions_return_errors_without_panicking() {
    for input in [
        "",
        "{",
        "[]",
        "null",
        "true",
        "123",
        "{}",
        "<definitions>",
        "{\"openapi\":\"3\"}",
    ] {
        let result = std::panic::catch_unwind(|| parse(input, "https://example.test"));
        assert!(result.is_ok(), "parser panicked for {input:?}");
        assert!(
            result.unwrap().is_err(),
            "malformed input unexpectedly succeeded: {input:?}"
        );
    }
    for i in 0..256 {
        let value = json!({"openapi":"3.0.0","paths":i,"components":[i],"servers":null});
        assert!(
            std::panic::catch_unwind(|| parse(&value.to_string(), "https://example.test")).is_ok()
        );
    }
}

#[test]
fn definition_operation_budget_is_enforced() {
    let items: Vec<_> = (0..1001)
        .map(|i| json!({"request":{"url":format!("https://example.test/{i}")}}))
        .collect();
    assert!(parse(&json!({"item":items}).to_string(), "").is_err());
}
