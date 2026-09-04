use std::net::SocketAddr;
use std::path::PathBuf;

use openidconnect::{AuthenticationContextClass, ClientId, IssuerUrl};
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::ClientSecret;

#[derive(Deserialize, Clone)]
pub(crate) struct Cfg {
  pub(crate) jitsi_secret: Option<String>,
  pub(crate) jitsi_secret_file: Option<PathBuf>,
  pub(crate) jitsi_url: Url,
  pub(crate) jitsi_sub: String,
  #[serde(alias = "issuer_base_url")]
  pub(crate) issuer_url: IssuerUrl,
  pub(crate) base_url: Url,
  pub(crate) client_id: ClientId,
  #[serde(alias = "secret")]
  pub(crate) client_secret: Option<ClientSecret>,
  pub(crate) client_secret_file: Option<PathBuf>,
  #[serde(default = "default_listen_addr")]
  pub(crate) listen_addr: SocketAddr,
  #[serde(default)]
  #[serde(deserialize_with = "string_array")]
  pub(crate) acr_values: Option<Vec<AuthenticationContextClass>>,
  #[serde(default)]
  #[serde(deserialize_with = "string_array2")]
  pub(crate) scopes: Option<Vec<String>>,
  #[serde(default)]
  pub(crate) verify_access_token_hash: Option<bool>,
  #[serde(default)]
  pub(crate) skip_prejoin_screen: Option<bool>,
  #[serde(default)]
  pub(crate) group: String,
  #[serde(default = "default_jwt_max_age_seconds")]
  pub(crate) jwt_max_age_seconds: i64,
  #[serde(default = "default_session_max_age_seconds")]
  pub(crate) session_max_age_seconds: i64,
  #[serde(default = "default_http_timeout_seconds")]
  pub(crate) http_timeout_seconds: u64,
  #[serde(default = "default_http_connect_timeout_seconds")]
  pub(crate) http_connect_timeout_seconds: u64,
  #[serde(default)]
  #[serde(deserialize_with = "string_array2")]
  pub(crate) trusted_id_token_audiences: Option<Vec<String>>,
  #[serde(default)]
  #[serde(deserialize_with = "path_array")]
  pub(crate) ca_certificate_files: Option<Vec<PathBuf>>,
  #[serde(default)]
  pub(crate) ca_certificate_file: Option<PathBuf>,
}

fn default_listen_addr() -> SocketAddr {
  ([127, 0, 0, 1], 3000).into()
}

fn default_session_max_age_seconds() -> i64 {
  30 * 60
}

fn default_jwt_max_age_seconds() -> i64 {
  5 * 60
}

fn default_http_timeout_seconds() -> u64 {
  15
}

fn default_http_connect_timeout_seconds() -> u64 {
  5
}

pub fn path_array<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Option<Vec<PathBuf>>, D::Error> {
  let input: Option<String> = Option::deserialize(deserializer)?;

  Ok(input.map(|input| input.split(' ').map(PathBuf::from).collect()))
}

pub fn string_array2<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
  let input: Option<String> = Option::deserialize(deserializer)?;

  Ok(input.map(|input| input.split(' ').map(|acr| acr.to_string()).collect()))
}

pub fn string_array<'a, D: Deserializer<'a>>(
  deserializer: D,
) -> Result<Option<Vec<AuthenticationContextClass>>, D::Error> {
  let input: Option<String> = Option::deserialize(deserializer)?;

  Ok(input.map(|input| {
    input
      .split(' ')
      .map(|acr| AuthenticationContextClass::new(acr.to_string()))
      .collect()
  }))
}
