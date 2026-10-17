//! Decoder tab: chained encode/decode steps, each output feeding the next box.

use base64::{Engine, engine::general_purpose::STANDARD};
use eframe::egui;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

#[derive(Clone, Copy)]
enum Codec {
    Url,
    Base64,
    Hex,
    Html,
    Rot13,
    Gzip,
}

const CODECS: [(Codec, &str); 6] = [
    (Codec::Url, "URL"),
    (Codec::Base64, "Base64"),
    (Codec::Hex, "Hex"),
    (Codec::Html, "HTML"),
    (Codec::Rot13, "ROT13"),
    (Codec::Gzip, "gzip"),
];

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

fn encode(c: Codec, s: &str) -> String {
    match c {
        Codec::Url => utf8_percent_encode(s, NON_ALPHANUMERIC).to_string(),
        Codec::Base64 => STANDARD.encode(s),
        Codec::Hex => s.bytes().map(|b| format!("{b:02x}")).collect(),
        Codec::Html => s.chars().map(|c| format!("&#x{:x};", c as u32)).collect(),
        Codec::Rot13 => rot13(s),
        Codec::Gzip => {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = e.write_all(s.as_bytes());
            e.finish().map(|b| b.iter().map(|x| format!("{x:02x}")).collect()).unwrap_or_default()
        }
    }
}

fn decode(c: Codec, s: &str) -> Result<String, String> {
    let bytes = match c {
        Codec::Url => percent_decode_str(&s.replace('+', " ")).collect(),
        Codec::Base64 => {
            // Accepts URL-safe alphabet, missing padding and line breaks.
            let s: String = s
                .chars()
                .filter(|c| !c.is_whitespace())
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    c => c,
                })
                .collect();
            let s = s.trim_end_matches('=');
            STANDARD.decode(format!("{s}{}", "=".repeat((4 - s.len() % 4) % 4))).map_err(|e| e.to_string())?
        }
        Codec::Hex => {
            let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if h.len() % 2 != 0 {
                return Err("odd number of hex digits".into());
            }
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
        }
        Codec::Html => return Ok(html_decode(s)),
        Codec::Rot13 => return Ok(rot13(s)),
        Codec::Gzip => {
            let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() % 2 != 0 {
                return Err("gzip expects hex input".into());
            }
            let raw: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            crate::http::decode("gzip", &raw).ok_or("not valid gzip")?
        }
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn html_decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let entity = rest.find(';').filter(|&e| e <= 10).map(|e| &rest[1..e]);
        let ch = entity.and_then(|e| match e {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => e
                .strip_prefix("#x")
                .or_else(|| e.strip_prefix("#X"))
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| e.strip_prefix('#').map(|d| d.parse()))
                .and_then(|n| n.ok())
                .and_then(char::from_u32),
        });
        match (ch, entity) {
            (Some(c), Some(e)) => {
                out.push(c);
                rest = &rest[e.len() + 2..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out + rest
}

const HASHES: [&str; 4] = ["MD5", "SHA-1", "SHA-256", "SHA-512"];

fn hash(name: &str, s: &str) -> String {
    use sha2::Digest;
    let bytes: Vec<u8> = match name {
        "MD5" => md5::Md5::digest(s).to_vec(),
        "SHA-1" => sha1::Sha1::digest(s).to_vec(),
        "SHA-256" => sha2::Sha256::digest(s).to_vec(),
        _ => sha2::Sha512::digest(s).to_vec(),
    };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// UTC date for a unix timestamp (civil-from-days, Howard Hinnant's algorithm).
fn utc(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn jwt(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 3 || !parts[0].starts_with("eyJ") {
        return None;
    }
    let json = |p: &str| -> Option<serde_json::Value> { serde_json::from_str(&decode(Codec::Base64, p).ok()?).ok() };
    let (header, payload) = (json(parts[0])?, json(parts[1])?);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let mut times = String::new();
    for claim in ["iat", "nbf", "exp"] {
        if let Some(t) = payload.get(claim).and_then(|v| v.as_i64()) {
            let note = if claim == "exp" && t < now { " (expired)" } else { "" };
            times += &format!("{claim}: {}{note}\n", utc(t));
        }
    }
    Some(format!(
        "Header:\n{}\n\nPayload:\n{}\n\n{times}Signature: {}",
        serde_json::to_string_pretty(&header).ok()?,
        serde_json::to_string_pretty(&payload).ok()?,
        if parts[2].is_empty() { "(none)" } else { parts[2] }
    ))
}

/// Guesses the encoding and decodes one layer.
fn smart(s: &str) -> Result<String, String> {
    let t = s.trim();
    if let Some(j) = jwt(t) {
        return Ok(j);
    }
    let b = t.as_bytes();
    if b.windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()) {
        return decode(Codec::Url, t);
    }
    if t.contains('&') && t.contains(';') && html_decode(t) != t {
        return decode(Codec::Html, t);
    }
    if t.len() >= 2 && t.len() % 2 == 0 && b.iter().all(u8::is_ascii_hexdigit) {
        return decode(Codec::Hex, t);
    }
    if t.len() >= 4 && b.iter().all(|c| c.is_ascii_alphanumeric() || b"+/=-_".contains(c)) {
        if let Ok(d) = decode(Codec::Base64, t) {
            if !d.contains('\u{fffd}') {
                return Ok(d);
            }
        }
    }
    Err("no encoding recognised".into())
}

pub struct Decoder {
    steps: Vec<String>,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder { steps: vec![String::new()] }
    }
}

impl Decoder {
    pub fn load(&mut self, text: String) {
        self.steps = vec![text];
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let mut push = None;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for (i, step) in self.steps.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::multiline(step)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(5)
                            .desired_width(ui.available_width() - 200.0),
                    );
                    ui.vertical(|ui| {
                        ui.menu_button("Decode as…", |ui| {
                            for (c, name) in CODECS {
                                if ui.button(name).clicked() {
                                    push = Some((i, decode(c, step).unwrap_or_else(|e| format!("[error: {e}]"))));
                                    ui.close();
                                }
                            }
                        });
                        ui.menu_button("Encode as…", |ui| {
                            for (c, name) in CODECS {
                                if ui.button(name).clicked() {
                                    push = Some((i, encode(c, step)));
                                    ui.close();
                                }
                            }
                        });
                        ui.menu_button("Hash…", |ui| {
                            for name in HASHES {
                                if ui.button(name).clicked() {
                                    push = Some((i, hash(name, step)));
                                    ui.close();
                                }
                            }
                        });
                        if ui.button("Smart decode").clicked() {
                            push = Some((i, smart(step).unwrap_or_else(|e| format!("[{e}]"))));
                        }
                        ui.weak(format!("{} chars", step.chars().count()));
                    });
                });
                ui.separator();
            }
        });
        if let Some((i, out)) = push {
            self.steps.truncate(i + 1);
            self.steps.push(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for (c, _) in CODECS {
            assert_eq!(decode(c, &encode(c, "a b&<é>")).unwrap(), "a b&<é>");
        }
        assert_eq!(encode(Codec::Rot13, "Hello"), "Uryyb");
        assert_eq!(decode(Codec::Rot13, "Uryyb").unwrap(), "Hello");
        assert_eq!(decode(Codec::Base64, "aGk").unwrap(), "hi");
        assert_eq!(decode(Codec::Base64, "Pz8_\n").unwrap(), "???");
        assert_eq!(hash("SHA-256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hash("MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IiLCJleHAiOjF9.sig";
        assert!(smart(token).unwrap().contains("\"sub\": \"bob\"") && smart(token).unwrap().contains("(expired)"));
        assert_eq!(smart("a%20b").unwrap(), "a b");
        assert_eq!(smart("aGVsbG8=").unwrap(), "hello");
        assert_eq!(smart("68656c6c6f").unwrap(), "hello");
        assert_eq!(html_decode("&lt;a&gt; &amp;&#65;&#x42; & x"), "<a> &AB & x");
    }
}
