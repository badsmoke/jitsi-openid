use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{EncodingKey, Header};
use openidconnect::core::{CoreAuthenticationFlow, CoreGenderClaim};
use openidconnect::{
  AccessTokenHash, AuthorizationCode, ConfigurationError, CsrfToken, IdTokenClaims, Nonce,
  OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse,
};
use serde::{self, Serializer};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::{error, warn};
use url::Url;
use uuid::Uuid;

use crate::AppError::{AuthenticationContextWasNotFulfilled, IdTokenRequired};
use crate::{
  AppError, Cfg, InternalServerError, InvalidAccessToken, InvalidCode, InvalidIdTokenNonce,
  InvalidSession, InvalidState, JitsiState, MissingAccessTokenHash,
  MissingIdTokenAndUserInfoEndpoint, MyClaims, MyClient, MyTokenResponse, MyUserInfoClaims,
  Session, UnableToQueryUserInfo, UnsupportedSigningAlgorithm,
};

const COOKIE_NAME: &str = "JITSI_OPENID_SESSION";

pub(crate) fn build_routes() -> Router<JitsiState> {
  Router::new()
    .route("/room/{name}", get(room))
    .route("/callback", get(callback))
}

async fn room(
  Path(room): Path<String>,
  State(state): State<JitsiState>,
  jar: CookieJar,
) -> impl IntoResponse {
  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  let mut request = state
    .client
    .authorize_url(
      CoreAuthenticationFlow::AuthorizationCode,
      CsrfToken::new_random,
      Nonce::new_random,
    )
    .set_pkce_challenge(pkce_challenge);

  match state.config.scopes {
    None => {
      request = request
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
    }
    Some(scopes) => {
      for scope in &scopes {
        request = request.add_scope(Scope::new(scope.to_string()));
      }
    }
  };

  if let Some(acr_values) = state.config.acr_values {
    for class in acr_values {
      request = request.add_auth_context_value(class);
    }
  }

  let (auth_url, csrf_token, nonce) = request.url();

  let session_id = Uuid::new_v4();
  let session_max_age = Duration::seconds(state.config.session_max_age_seconds);
  let expires_at = OffsetDateTime::now_utc() + session_max_age;

  let mut store = state.store.write().await;
  prune_expired_sessions(&mut store);
  store.insert(
    session_id,
    Session {
      room,
      csrf_token,
      nonce,
      pkce_verifier,
      expires_at,
    },
  );

  // Build the cookie
  let cookie = Cookie::build((COOKIE_NAME, session_id.to_string()))
    .domain(
      state
        .config
        .base_url
        .host()
        .expect("Missing host in base url")
        .to_string(),
    )
    .path(state.config.base_url.path().to_string())
    .secure(state.config.base_url.scheme() == "https")
    .http_only(true)
    .same_site(SameSite::Lax)
    .max_age(session_max_age);

  (jar.add(cookie), Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
struct Callback {
  state: String,
  // session_state: String,
  code: AuthorizationCode,
}

async fn callback(
  jar: CookieJar,
  Query(callback): Query<Callback>,
  State(state): State<JitsiState>,
) -> Result<impl IntoResponse, AppError> {
  let session_id = match jar
    .get(COOKIE_NAME)
    .map(|cookie| Uuid::parse_str(cookie.value()))
  {
    Some(Ok(session_id)) => session_id,
    Some(Err(_)) => return Err(InvalidSession),
    None => return Err(InvalidSession),
  };

  let session = match state.store.write().await.remove(&session_id) {
    Some(session) => session,
    None => return Err(InvalidSession),
  };

  if session.expires_at <= OffsetDateTime::now_utc() {
    return Err(InvalidSession);
  }

  if &callback.state != session.csrf_token.secret() {
    return Err(InvalidState);
  }

  let response = state
    .client
    .exchange_code(callback.code)
    .map_err(|err| {
      error!("Configuration error: {:?}", err);
      AppError::ConfigurationError
    })?
    .set_pkce_verifier(session.pkce_verifier)
    .request_async(&state.http_client)
    .await
    .map_err(|err| {
      warn!("Authentication failed, Invalid Code: {:?}", err);
      InvalidCode
    })?;

  let jitsi_user =
    match id_token_claims(&state.config, &state.client, &response, &session.nonce)? {
      None => match user_info_claims(&state.client, &state.http_client, &response).await? {
        None => return Err(MissingIdTokenAndUserInfoEndpoint),
        Some(user) => user,
      },
      Some(user) => user,
    };

  let jwt = create_jitsi_jwt(
    jitsi_user,
    "jitsi".to_string(),
    "jitsi".to_string(),
    state.config.jitsi_sub,
    session.room.clone(),
    state.jitsi_secret.0,
    state.config.group,
    state.config.jwt_max_age_seconds,
  )
  .map_err(|err| {
    error!("Unable to create jwt: {}", err);
    InternalServerError
  })?;

  let mut url = create_jitsi_room_url(&state.config.jitsi_url, &session.room)?;
  url.query_pairs_mut().append_pair("jwt", &jwt);

  if state.config.skip_prejoin_screen.unwrap_or(true) {
    url.set_fragment(Some("config.prejoinConfig.enabled=false"));
  }

  Ok(Redirect::to(url.as_str()))
}

fn create_jitsi_room_url(jitsi_url: &Url, room: &str) -> Result<Url, AppError> {
  let mut url = jitsi_url.clone();
  url.set_query(None);
  url.set_fragment(None);
  {
    let mut segments = url.path_segments_mut().map_err(|_| InternalServerError)?;
    segments.push(room);
  }
  Ok(url)
}

fn prune_expired_sessions(store: &mut std::collections::HashMap<Uuid, Session>) {
  let now = OffsetDateTime::now_utc();
  store.retain(|_, session| session.expires_at > now);
}

fn id_token_claims(
  config: &Cfg,
  client: &MyClient,
  response: &MyTokenResponse,
  nonce: &Nonce,
) -> Result<Option<JitsiUser>, AppError> {
  let id_token = match response.id_token() {
    Some(id_token) => id_token,
    None => {
      return if config.acr_values.is_none() {
        Ok(None)
      } else {
        Err(IdTokenRequired)
      };
    }
  };

  let id_token_verifier = match &config.trusted_id_token_audiences {
    Some(trusted_audiences) => client
      .id_token_verifier()
      .set_other_audience_verifier_fn(|aud| {
        trusted_audiences
          .iter()
          .any(|trusted_audience| **aud == trusted_audience.as_str())
      }),
    None => client.id_token_verifier(),
  };
  let claims = id_token
    .claims(&id_token_verifier, nonce)
    .map_err(InvalidIdTokenNonce)?;

  if let Some(acr_values) = &config.acr_values {
    if let Some(auth_context) = claims.auth_context_ref() {
      if !acr_values.contains(auth_context) {
        return Err(AuthenticationContextWasNotFulfilled);
      }
    } else {
      return Err(AuthenticationContextWasNotFulfilled);
    }
  }

  if config.verify_access_token_hash.unwrap_or(true) {
    match claims.access_token_hash() {
      Some(expected_access_token_hash) => {
        let algorithm = id_token.signing_alg().map_err(|err| {
          warn!(
            "Authentication failed, UnsupportedSigningAlgorithm: {:?}",
            err
          );
          UnsupportedSigningAlgorithm
        })?;

        let actual_access_token_hash = AccessTokenHash::from_token(
          response.access_token(),
          algorithm,
          id_token
            .signing_key(&client.id_token_verifier())
            .map_err(|err| {
              error!("Invalid Signing Key: {:?}", err);
              AppError::InvalidSigningKey
            })?,
        )
        .map_err(|err| {
          warn!(
            "Authentication failed, UnsupportedSigningAlgorithm: {:?}",
            err
          );
          UnsupportedSigningAlgorithm
        })?;

        if &actual_access_token_hash != expected_access_token_hash {
          return Err(InvalidAccessToken);
        }
      }
      None => return Err(MissingAccessTokenHash),
    };
  }

  Ok(Some(JitsiUser {
    id: claims.subject().to_string(),
    email: claims.email().map(|email| email.to_string()),
    affiliation: claims.additional_claims().affiliation.clone(),
    name: get_display_name_id_token(claims),
    avatar: claims
      .picture()
      .and_then(|x| x.get(None))
      .map(|x| x.to_string()),
    moderator: claims.additional_claims().moderator,
  }))
}

async fn user_info_claims(
  client: &MyClient,
  http_client: &reqwest::Client,
  response: &MyTokenResponse,
) -> Result<Option<JitsiUser>, AppError> {
  match client.user_info(response.access_token().clone(), None) {
    Ok(request) => {
      let claims: MyUserInfoClaims = request.request_async(http_client).await.map_err(|err| {
        warn!("Authentication failed, UnableToQueryUserInfo: {:?}", err);
        UnableToQueryUserInfo
      })?;

      Ok(Some(JitsiUser {
        id: claims.subject().to_string(),
        email: claims.email().map(|email| email.to_string()),
        affiliation: claims.additional_claims().affiliation.clone(),
        name: get_display_name(&claims),
        avatar: claims
          .picture()
          .and_then(|x| x.get(None))
          .map(|x| x.to_string()),
        moderator: claims.additional_claims().moderator,
      }))
    }
    Err(ConfigurationError::MissingUrl(_)) => Ok(None),
    Err(err) => {
      error!("Unable to find user info url: {}", err);
      Err(InternalServerError)
    }
  }
}

#[derive(Serialize)]
struct JitsiClaims {
  context: JitsiContext,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  #[serde(serialize_with = "jwt_numeric_date")]
  nbf: OffsetDateTime,
  #[serde(serialize_with = "jwt_numeric_date")]
  iat: OffsetDateTime,
  #[serde(serialize_with = "jwt_numeric_date")]
  exp: OffsetDateTime,
}

#[derive(Serialize)]
struct JitsiContext {
  user: JitsiUser,
  group: Option<String>,
}

#[derive(Serialize)]
struct JitsiUser {
  id: String,
  email: Option<String>,
  affiliation: Option<String>,
  name: Option<String>,
  avatar: Option<String>,
  moderator: Option<bool>,
}

fn create_jitsi_jwt(
  user: JitsiUser,
  aud: String,
  iss: String,
  sub: String,
  room: String,
  secret: String,
  group: String,
  max_age_seconds: i64,
) -> anyhow::Result<String> {
  let iat = OffsetDateTime::now_utc();
  let exp = iat + Duration::seconds(max_age_seconds);

  let context = JitsiContext {
    user,
    group: Some(group),
  };

  let claims = JitsiClaims {
    context,
    aud,
    iss,
    sub,
    room,
    // nbf = not-before
    nbf: iat, // idk whey some jitsi configurations what this, its basically the same as iat
    iat,
    exp,
  };

  let token = jsonwebtoken::encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
  )?;

  Ok(token)
}

/// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
pub fn jwt_numeric_date<S: Serializer>(
  date: &OffsetDateTime,
  serializer: S,
) -> Result<S::Ok, S::Error> {
  let timestamp = date.unix_timestamp();
  serializer.serialize_i64(timestamp)
}

fn get_display_name_id_token(
  claims: &IdTokenClaims<MyClaims, CoreGenderClaim>,
) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}

fn get_display_name(claims: &MyUserInfoClaims) -> Option<String> {
  if let Some(name) = claims
    .name()
    .or_else(|| claims.name())
    .and_then(|name| name.get(None))
    .map(|name| name.to_string())
  {
    return Some(name);
  }

  let name = [
    claims
      .given_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .middle_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
    claims
      .family_name()
      .and_then(|name| name.get(None))
      .map(|name| name.to_string()),
  ];

  if !name.is_empty() {
    return Some(
      name
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join(" "),
    );
  }

  claims.preferred_username().map(|name| name.to_string())
}

#[cfg(test)]
mod tests {
  use jsonwebtoken::{decode, DecodingKey, Validation};
  use serde_json::Value;
  use url::Url;

  use super::{create_jitsi_jwt, create_jitsi_room_url, JitsiUser};

  #[test]
  fn jitsi_jwt_uses_stable_user_id_and_requested_room() {
    let token = create_jitsi_jwt(
      JitsiUser {
        id: "stable-subject".to_string(),
        email: Some("user@example.com".to_string()),
        affiliation: None,
        name: Some("Display Name".to_string()),
        avatar: None,
        moderator: None,
      },
      "jitsi".to_string(),
      "jitsi".to_string(),
      "meet.example.com".to_string(),
      "Räksmörgås".to_string(),
      "secret".to_string(),
      "group".to_string(),
      300,
    )
    .expect("jwt should be created");

    let mut validation = Validation::default();
    validation.set_audience(&["jitsi"]);

    let claims = decode::<Value>(
      &token,
      &DecodingKey::from_secret("secret".as_bytes()),
      &validation,
    )
    .expect("jwt should decode")
    .claims;

    assert_eq!(claims["room"], "Räksmörgås");
    assert_eq!(claims["context"]["user"]["id"], "stable-subject");
  }

  #[test]
  fn jitsi_room_url_keeps_configured_host_for_url_like_room_names() {
    let base = Url::parse("https://meet.example.com/base").expect("valid base url");

    let absolute = create_jitsi_room_url(&base, "https://evil.example/room")
      .expect("room url should be created");
    assert_eq!(absolute.host_str(), Some("meet.example.com"));
    assert_eq!(absolute.path(), "/base/https:%2F%2Fevil.example%2Froom");

    let scheme_relative =
      create_jitsi_room_url(&base, "//evil.example/room").expect("room url should be created");
    assert_eq!(scheme_relative.host_str(), Some("meet.example.com"));
    assert_eq!(scheme_relative.path(), "/base/%2F%2Fevil.example%2Froom");
  }

  #[test]
  fn jitsi_jwt_expiry_uses_configured_max_age() {
    let token = create_jitsi_jwt(
      JitsiUser {
        id: "stable-subject".to_string(),
        email: None,
        affiliation: None,
        name: None,
        avatar: None,
        moderator: None,
      },
      "jitsi".to_string(),
      "jitsi".to_string(),
      "meet.example.com".to_string(),
      "room".to_string(),
      "secret".to_string(),
      "group".to_string(),
      42,
    )
    .expect("jwt should be created");

    let mut validation = Validation::default();
    validation.set_audience(&["jitsi"]);

    let claims = decode::<Value>(
      &token,
      &DecodingKey::from_secret("secret".as_bytes()),
      &validation,
    )
    .expect("jwt should decode")
    .claims;

    assert_eq!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(), 42);
  }
}
