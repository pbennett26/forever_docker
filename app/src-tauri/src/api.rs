//! bnetserver REST API (port 8081): login, 30-day launcher token, login tickets, server status.
//!
//! The portal host name is resolved to the configured server address here, and only the embedded CA is trusted,
//! so this works before the hosts file and the system certificate store are set up.

use crate::config::{Server, CA_PEM};
use crate::i18n::{t, tf};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;

pub type Result<T> = std::result::Result<T, String>;

pub struct Api {
    client: reqwest::Client,
    base: String,
}

#[derive(Deserialize)]
pub struct Remembered {
    pub token: String,
    pub expires: u64,
}

#[derive(Deserialize)]
pub struct GameAccount {
    pub name: String,
}

#[derive(Deserialize)]
pub struct LauncherLogin {
    pub login_ticket: String,
    pub email: String,
    #[serde(default)]
    pub game_accounts: Vec<GameAccount>,
}

pub async fn resolve(address: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((address, port))
        .await
        .map_err(|e| format!("{} : {e}", tf("address_not_found", &[&address])))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| tf("address_not_found", &[&address]))
}

fn basic(ticket: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{ticket}:")))
}

impl Api {
    pub async fn new(server: &Server) -> Result<Self> {
        let addr = resolve(&server.address, server.rest_port).await?;
        let ca = reqwest::Certificate::from_pem(CA_PEM.as_bytes()).map_err(|e| e.to_string())?;
        let builder = reqwest::Client::builder();
        #[cfg(not(windows))]
        let builder = builder.use_rustls_tls();
        #[cfg(windows)]
        let builder = builder.use_native_tls();
        let client = builder
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .resolve(&server.portal, addr)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client, base: format!("https://{}:{}/bnetserver", server.portal, server.rest_port) })
    }

    async fn post(&self, path: &str, body: Option<serde_json::Value>, ticket: Option<&str>) -> Result<(u16, String)> {
        let mut req = self.client.post(format!("{}{path}", self.base));
        if let Some(t) = ticket {
            req = req.header("Authorization", basic(t));
        }
        req = match body {
            Some(b) => req.json(&b),
            None => req.header("Content-Length", "0"),
        };
        let res = req.send().await.map_err(describe)?;
        let status = res.status().as_u16();
        Ok((status, res.text().await.map_err(describe)?))
    }

    /// Returns a login ticket, or an error message for the user.
    pub async fn login(&self, email: &str, password: &str) -> Result<String> {
        let body = json!({"version": "1.0", "inputs": [
            {"input_id": "account_name", "value": email},
            {"input_id": "password", "value": password},
        ]});
        let (_, text) = self.post("/login/", Some(body), None).await?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| t("unexpected_answer").to_string())?;
        if let Some(t) = v.get("login_ticket").and_then(|t| t.as_str()) {
            return Ok(t.to_string());
        }
        if v.get("authentication_state").and_then(|s| s.as_str()) == Some("AUTHENTICATOR") {
            return Err(t("authenticator").into());
        }
        Err(t("bad_login").into())
    }

    pub async fn remember(&self, ticket: &str) -> Result<Remembered> {
        let (status, text) = self.post("/launcher/remember/", None, Some(ticket)).await?;
        serde_json::from_str(&text).map_err(|_| tf("remember_refused", &[&status]))
    }

    /// Exchanges the launcher token for a fresh login ticket. Err("expired") when the token is no longer valid.
    pub async fn launcher_login(&self, token: &str) -> Result<LauncherLogin> {
        let (status, text) = self.post("/launcher/login/", None, Some(token)).await?;
        match status {
            200 => serde_json::from_str(&text).map_err(|_| t("unexpected_answer").into()),
            401 => Err("expired".into()),
            403 => Err(t("banned").into()),
            _ => Err(tf("server_error", &[&status])),
        }
    }

    pub async fn forget(&self, token: &str) {
        let _ = self.post("/launcher/forget/", None, Some(token)).await;
    }
}

fn describe(e: reqwest::Error) -> String {
    if e.is_connect() || e.is_timeout() {
        t("unreachable").into()
    } else {
        tf("network_error", &[&e])
    }
}

/// A post of the website blog, as served by `<website>/api/news`.
#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewsItem {
    pub title: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub date: String,
}

/// Latest blog posts of the website (public certificate, unlike the bnetserver API). Relative links are made absolute.
pub async fn news(website: &str) -> Result<Vec<NewsItem>> {
    let base = website.trim_end_matches('/');
    let client = reqwest::Client::builder().timeout(Duration::from_secs(6)).build().map_err(|e| e.to_string())?;
    let res = client.get(format!("{base}/api/news")).send().await.map_err(describe)?;
    if !res.status().is_success() {
        return Err(tf("no_news", &[&res.status().as_u16()]));
    }
    let mut items: Vec<NewsItem> = res.json().await.map_err(|_| t("unexpected_site").to_string())?;
    for item in &mut items {
        for link in [&mut item.url, &mut item.image] {
            if link.starts_with('/') {
                *link = format!("{base}{link}");
            }
        }
    }
    Ok(items)
}

/// True when something accepts TCP connections on address:port.
pub async fn port_open(address: &str, port: u16) -> bool {
    let Ok(addr) = resolve(address, port).await else { return false };
    matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
}
