# Testing workflows

Select tools from the dropdown at the top left. These features extend Ferrite's
existing proxy, scanner and manual tools; they do not implement every Burp feature.

## Sessions and identities

In **Sessions → User identities**, add a user/role, set an exact origin such as
`https://app.example`, and enter its authentication headers. Log in using the
proxied browser, then click **Snapshot cookies** for that identity. Repeat for
the other users. The snapshots are independent and saved in the project.

Under **Session macros**, an optional `validity` request checks authentication
before the login chain. Its expected status defaults to 200. Use
`expect_body_regex` when the application returns 200 for logged-out pages too.
A valid response skips login and can extract a fresh token. An invalid response
runs `steps`, checks the session again, and blocks the tool request if login
still failed. Network/check/extraction errors stop the request rather than
silently sending a request with missing credentials.

Example configuration (replace the URLs and login body):

```json
[{
  "name": "Login when expired",
  "enabled": false,
  "origin": "https://app.example",
  "path_regex": "^/submit",
  "validity": {
    "url": "https://app.example/session",
    "request": "GET /session HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n",
    "expect_status": 200,
    "expect_body_regex": "\"authenticated\":true",
    "extract": [{"name":"csrf","json_pointer":"/csrf","url_encode":true}]
  },
  "steps": [{
    "url": "https://app.example/login",
    "request": "POST /login HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nConnection: close\r\n\r\nusername=example&password=replace-me",
    "expect_status": 200
  }]
}]
```

Enable **Use session cookies** in the sending tool. The request template can use
`{{csrf}}`. Chains are serialized to avoid overlapping login/token refreshes.
Steps stay on the configured origin; cross-origin SSO is not automated.

## Authorization comparison

Right-click a request in Proxy, Target or Repeater → **Test authorization**.
Configure identities in Sessions, then click **Compare identities**.

The view sends the original request, an anonymous variant, and up to 20 identities
matching the request's origin. It shows status, retained body length, byte-position
similarity and a body diff. Each response retains up to 1 MiB; the diff compares
the first 64 KiB with a bounded computation time. Save selected request/response
evidence to Organizer.

Anonymous replay strips Cookie, Authorization, Proxy-Authorization, common
X-API/auth/CSRF token headers, and headers named by saved identities. Named
variants then apply their own headers and host/path-bound cookie snapshot.
Authentication embedded in URLs or bodies needs manual request editing. Similar
responses are a review signal, not an automatic access-control finding.

GET, HEAD and OPTIONS can run immediately. Explicitly enable **Replay
state-changing methods** to compare other methods. Replay responses do not
replace the main session cookie jar or run login macros.

## Intruder

**Pause** stops new work; active requests can finish. **Stop** drains active
requests and preserves the next unqueued position. **Resume unsent payloads**
uses the original target, template, payloads and processing configuration even
if the draft has since been edited.

Projects preserve the attack plan and checkpoint. Loading never starts an attack.
Requests queued at save time have uncertain delivery and are marked unfinished;
resuming skips them to avoid replaying a potentially completed mutation.

A batch retains at most 10,000 rows. Resuming a full batch evicts its rows and
continues at the next position. Export needed evidence before continuing.
Retained request/response evidence is also subject to the 64 MiB limit.

Under **Payload processing and resource pool**, choose regex replacement followed
by Base64, SHA-256, lowercase or uppercase. Prefix/suffix and optional URL encoding
are applied afterwards. Numbers and wordlist loading remain available.

Resource pools are shared with Scans and enforce concurrency, spacing and
429/503 backoff. Configure them in **Scans → Shared resource pools**. Pool quota
changes take effect when users of the old pool have finished.

## Browser Lab

**Render / inspect** runs isolated headless Chromium through Ferrite.
**Record in Chromium** opens a separate visible window. Interact with the page,
then press **Stop** in Ferrite. Select the observations and click **Copy recorded
actions as workflow**. Paste the JSON into **Workflow replay**, then **Apply
workflow**. Fill/click recordings survive page navigations. They can contain
passwords and other entered values.

Workflow steps are saved with the project and run once after the first page
loads. Supported actions:

```json
[
  {"action":"navigate","url":"https://app.example/login"},
  {"action":"fill","selector":"#username","value":"example"},
  {"action":"fill","selector":"#password","value":"replace-me"},
  {"action":"click","selector":"button[type=submit]"},
  {"action":"wait","ms":500},
  {"action":"assert_text","selector":"body","text":"Welcome"},
  {"action":"post_message","data":{"type":"probe","value":"ferrite_canary"}}
]
```

Workflows support at most 100 steps. A wait is capped at 10 seconds. Navigation
and authenticated browser traffic stay on the starting origin; explicit
workflow navigation also respects scope. Session jar cookies are copied into the
isolated browser and custom headers are origin-bound. Selecting DOM options to
submit forms or probe prototypes affects inspection, not interactive recording.

DOM observations include marker-bearing URL/search/storage sources, dangerous
HTML/attribute sinks and stacks, messages, duplicate named elements and prototype
canaries. These are marker observations, not complete JavaScript taint tracking
or proof of XSS. Post-message replay uses the real page origin; it does not spoof
an external sender. Chromium profiles are temporary and removed after a run.

## Public callbacks

Install the official `interactsh-client` separately and open **Callbacks → Public
Interactsh service**. Set the executable path and optionally a self-hosted server.
Click **Start Interactsh**, then **Use callback URL above** to configure scanner
probes. Enable callback probes in the Scans policy before queueing a scan.

The official process handles registration, encrypted interaction decoding and
five-second polling. Ferrite reads its JSON output, correlates HTTP/DNS evidence
with original probes, and stops the process on Stop or project switch. The
scanner base supports `{{token}}`, allowing each probe a distinct DNS label.
Generated HTTP URLs support nested labels without depending on a wildcard TLS
certificate for that nested hostname.

The executable is not bundled. Public registration is performed only when you
start it. The bridge regression uses a local fake CLI; public-service operation
has not been tested here. Interactsh CLI options are documented in the
[official README](https://github.com/projectdiscovery/interactsh#usage).

## Repeater groups and HTTP/2

Each tab has an **HTTP/2** checkbox; its choice persists with the project. The raw
editor uses HTTP/1-style headers. HTTPS negotiates `h2` with ALPN; plain HTTP uses
HTTP/2 prior knowledge. Single sends still apply session macros and cookies.

Assign tabs a group name and filter groups above the tabs. Duplicating a tab
preserves its group and protocol choice. **Send group** supports sequential,
connection-reuse, parallel last-byte release and HTTP/2 multiplexing. Groups
contain at most 100 idle tabs on one origin. Disable session macros before a
synchronized group send and prepare any tokens in advance.

Last-byte mode prepares every connection before release. HTTP/2 multiplexing
does not guarantee a single physical TCP packet.

## Scanner confirmation

Signature-based active findings are reported only when a second probe reproduces
the signature and a neutral control does not match. Timing checks retain their
baseline/zero-delay confirmation. Unique markers reduce cross-run collisions.

Insertion points include query/form values, nested JSON strings/numbers, cookies,
text multipart fields and existing User-Agent/Referer/X-Forwarded-For headers.
Multipart uploads and sibling fields are preserved. A scan uses at most 200
insertion points. Duplicate active findings are suppressed across restore by
endpoint, method, finding type and parameter. Reflected XSS still needs browser
validation; signatures and controls cannot prove every issue exploitable.
