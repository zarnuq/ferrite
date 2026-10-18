//! Limits apply to retained evidence, never to bytes forwarded by the proxy.
pub const MESSAGE: usize = 1024 * 1024;
pub const BYTES: usize = 64 * 1024 * 1024;
pub const ROWS: usize = 10_000;

pub fn clip(mut raw: Vec<u8>) -> Vec<u8> {
    if raw.len() > MESSAGE {
        raw.truncate(MESSAGE);
        raw.extend_from_slice(b"\n[ferrite: retained evidence truncated at 1 MiB]\n");
    }
    raw
}
