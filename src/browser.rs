//! Launch a dedicated Chromium profile through this instance's proxy listener.

use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::rcgen::{KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    process::{Command, Stdio},
};

pub(crate) fn ca_fingerprint(pem: &str) -> io::Result<String> {
    let key = KeyPair::from_pem(pem).map_err(|e| io::Error::other(format!("could not read Ferrite CA key: {e}")))?;
    // Hudsucker uses the CA key for its generated server certificates too.
    Ok(STANDARD.encode(Sha256::digest(key.subject_public_key_info())))
}

pub(crate) fn command(profile: &Path, mut addr: SocketAddr, fingerprint: &str) -> Command {
    // A wildcard bind address is not a browser destination.
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
        });
    }
    let mut cmd = Command::new("chromium");
    let mut profile_arg = std::ffi::OsString::from("--user-data-dir=");
    profile_arg.push(profile);
    cmd.arg(profile_arg)
        .arg(format!("--proxy-server=http://{addr}"))
        .arg("--proxy-bypass-list=<-loopback>")
        .arg(format!("--ignore-certificate-errors-spki-list={fingerprint}"));
    cmd
}

pub fn launch(addr: SocketAddr) -> io::Result<()> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::other("HOME is not set"))?;
    let profile = Path::new(&home).join(".config/chromium-ferrite");
    let pem = std::fs::read_to_string(crate::proxy::config_dir().join("ca.key"))
        .map_err(|e| io::Error::new(e.kind(), format!("Ferrite CA is not ready: {e}")))?;
    let fingerprint = ca_fingerprint(&pem)?;
    let mut child = command(&profile, addr, &fingerprint)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("could not launch chromium: {e}")))?;
    // Reap Chromium without blocking the UI thread.
    std::thread::spawn(move || { let _ = child.wait(); });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_arguments_preserve_profile_and_proxy_routing() {
        let cmd = command(Path::new("/tmp/home with spaces/.config/chromium-ferrite"), "127.0.0.1:8080".parse().unwrap(), "test-fingerprint");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, [
            "--user-data-dir=/tmp/home with spaces/.config/chromium-ferrite",
            "--proxy-server=http://127.0.0.1:8080",
            "--proxy-bypass-list=<-loopback>",
            "--ignore-certificate-errors-spki-list=test-fingerprint",
        ]);
        for (listen, proxy) in [
            ("0.0.0.0:9090", "--proxy-server=http://127.0.0.1:9090"),
            ("[::]:9090", "--proxy-server=http://[::1]:9090"),
        ] {
            let cmd = command(Path::new("/tmp/profile"), listen.parse().unwrap(), "test-fingerprint");
            assert_eq!(cmd.get_args().nth(1).unwrap(), proxy);
        }
    }

    #[test]
    fn fingerprint_is_stable_and_changes_with_ca() {
        let key = KeyPair::generate().unwrap();
        let pem = key.serialize_pem();
        let fingerprint = ca_fingerprint(&pem).unwrap();
        assert_eq!(fingerprint, ca_fingerprint(&pem).unwrap());
        assert_eq!(STANDARD.decode(&fingerprint).unwrap().len(), 32);
        assert_ne!(fingerprint, ca_fingerprint(&KeyPair::generate().unwrap().serialize_pem()).unwrap());
        assert!(ca_fingerprint("invalid key").is_err());
    }
}
