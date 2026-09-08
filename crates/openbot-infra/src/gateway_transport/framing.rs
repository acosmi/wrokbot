use super::{
    GatewayRequestDescriptor, GatewayRequestKind, GatewayTransportLimits, VerifiedGatewayEndpoints,
};
use crate::net::safe_http::{
    AuthorizationValue, GatewayAccept, GatewayHttpMethod, SafeHttpBudget, SafeHttpRequest,
};
use acosmi::core::{HttpPurpose, HttpRequest, HttpResponseMode, TransportError};
use http::{
    Method,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use std::time::Duration;
use zeroize::Zeroizing;

pub(super) struct Framed {
    pub(super) descriptor: GatewayRequestDescriptor,
    pub(super) request: SafeHttpRequest,
    pub(super) timeout: Duration,
}
pub(super) fn frame(
    mut request: HttpRequest,
    endpoints: &VerifiedGatewayEndpoints,
    limits: GatewayTransportLimits,
    remaining: Duration,
) -> Result<Framed, TransportError> {
    let kind = endpoints
        .classify(&request.url)
        .ok_or(TransportError::Rejected)?;
    let stream = request.context.response_mode == HttpResponseMode::Streaming;
    let expected_purpose = match kind {
        GatewayRequestKind::Catalogue => HttpPurpose::Api,
        GatewayRequestKind::Model => HttpPurpose::Model,
        GatewayRequestKind::OAuthDiscovery => HttpPurpose::OAuthDiscovery,
        GatewayRequestKind::OAuthRegistration => HttpPurpose::OAuthRegistration,
        GatewayRequestKind::OAuthToken => HttpPurpose::OAuthToken,
        GatewayRequestKind::OAuthRevocation => HttpPurpose::OAuthRevocation,
    };
    if request.context.purpose != expected_purpose
        || (stream && kind != GatewayRequestKind::Model)
        || request.context.timeout.is_zero()
    {
        return Err(TransportError::InvalidRequest);
    }
    for name in request.headers.keys() {
        if ![AUTHORIZATION, CONTENT_TYPE, ACCEPT].contains(name)
            || request.headers.get_all(name).iter().count() != 1
        {
            return Err(TransportError::InvalidRequest);
        }
    }
    let bearer = matches!(
        kind,
        GatewayRequestKind::Catalogue | GatewayRequestKind::Model
    );
    let authorization = match request.headers.get(AUTHORIZATION) {
        Some(value) if bearer => {
            let value = value.to_str().map_err(|_| TransportError::InvalidRequest)?;
            if value.len() > 16 * 1024
                || !value.strip_prefix("Bearer ").is_some_and(|token| {
                    !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())
                })
            {
                return Err(TransportError::InvalidRequest);
            }
            Some(AuthorizationValue::parse(value).map_err(|_| TransportError::InvalidRequest)?)
        }
        None if !bearer => None,
        _ => return Err(TransportError::InvalidRequest),
    };
    let accept = match request
        .headers
        .get(ACCEPT)
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| TransportError::InvalidRequest)?
    {
        Some("text/event-stream") if stream => GatewayAccept::EventStream,
        None | Some("application/json") if !stream => GatewayAccept::Json,
        _ => return Err(TransportError::InvalidRequest),
    };
    let method = match kind {
        GatewayRequestKind::Catalogue | GatewayRequestKind::OAuthDiscovery => {
            GatewayHttpMethod::GetJson
        }
        GatewayRequestKind::Model | GatewayRequestKind::OAuthRegistration => {
            GatewayHttpMethod::PostJson
        }
        GatewayRequestKind::OAuthToken | GatewayRequestKind::OAuthRevocation => {
            GatewayHttpMethod::PostForm
        }
    };
    let (expected_method, content_type) = match method {
        GatewayHttpMethod::GetJson => (Method::GET, None),
        GatewayHttpMethod::PostJson => (Method::POST, Some("application/json")),
        GatewayHttpMethod::PostForm => (Method::POST, Some("application/x-www-form-urlencoded")),
    };
    if request.method != expected_method
        || request
            .headers
            .get(CONTENT_TYPE)
            .map(|v| v.to_str())
            .transpose()
            .map_err(|_| TransportError::InvalidRequest)?
            != content_type
    {
        return Err(TransportError::InvalidRequest);
    }
    let (body_limit, response_limit, timeout) = match kind {
        GatewayRequestKind::Catalogue => (0, 4 * 1024 * 1024, Duration::from_secs(30)),
        GatewayRequestKind::Model => (8 * 1024 * 1024, 64 * 1024 * 1024, Duration::from_secs(30)),
        _ => (64 * 1024, 64 * 1024, Duration::from_secs(10)),
    };
    if request.body.len() > body_limit {
        return Err(TransportError::InvalidRequest);
    }
    match method {
        GatewayHttpMethod::GetJson => {}
        GatewayHttpMethod::PostJson => {
            // Validate a map without building a second owned Value tree of prompt/secret strings.
            use serde::Deserializer as _;
            let mut json = serde_json::Deserializer::from_slice(&request.body);
            json.deserialize_map(JsonObject)
                .map_err(|_| TransportError::InvalidRequest)?;
            json.end().map_err(|_| TransportError::InvalidRequest)?;
        }
        GatewayHttpMethod::PostForm => validate_form(&request.body, kind)?,
    }
    let timeout = timeout
        .min(limits.request_timeout)
        .min(request.context.timeout)
        .min(remaining);
    if timeout.is_zero() {
        return Err(TransportError::Timeout);
    }
    let budget = SafeHttpBudget::new(response_limit.min(limits.response_bytes), timeout)
        .map_err(|_| TransportError::InvalidRequest)?;
    let body = Zeroizing::new(std::mem::take(&mut request.body));
    let safe = SafeHttpRequest::gateway(
        request.url.clone(),
        method,
        body,
        authorization,
        accept,
        budget,
    )
    .map_err(|_| TransportError::InvalidRequest)?;
    Ok(Framed {
        descriptor: GatewayRequestDescriptor {
            kind,
            streaming: stream,
        },
        request: safe,
        timeout,
    })
}
fn validate_form(body: &[u8], kind: GatewayRequestKind) -> Result<(), TransportError> {
    let mut keys = std::collections::BTreeSet::new();
    let mut grant = None;
    for pair in body.split(|b| *b == b'&') {
        let at = pair
            .iter()
            .position(|b| *b == b'=')
            .ok_or(TransportError::InvalidRequest)?;
        let (key, rest) = pair.split_at(at);
        let value = &rest[1..];
        if !keys.insert(key) || value.is_empty() {
            return Err(TransportError::InvalidRequest);
        }
        let mut i = 0;
        while i < value.len() {
            if value[i] == b'%' {
                if i + 2 >= value.len()
                    || !value[i + 1].is_ascii_hexdigit()
                    || !value[i + 2].is_ascii_hexdigit()
                {
                    return Err(TransportError::InvalidRequest);
                }
                i += 3;
            } else {
                if !value[i].is_ascii_graphic() || matches!(value[i], b'&' | b'=') {
                    return Err(TransportError::InvalidRequest);
                }
                i += 1;
            }
        }
        if key == b"grant_type" {
            grant = Some(value);
        }
    }
    let allowed: &[&[u8]] = match (kind, grant) {
        (GatewayRequestKind::OAuthRevocation, None) => &[b"token"],
        (GatewayRequestKind::OAuthToken, Some(b"refresh_token")) => {
            &[b"grant_type", b"client_id", b"refresh_token"]
        }
        (GatewayRequestKind::OAuthToken, Some(b"authorization_code")) => {
            if keys.contains(b"expires_in".as_slice()) {
                &[
                    b"grant_type",
                    b"client_id",
                    b"code",
                    b"redirect_uri",
                    b"code_verifier",
                    b"expires_in",
                ]
            } else {
                &[
                    b"grant_type",
                    b"client_id",
                    b"code",
                    b"redirect_uri",
                    b"code_verifier",
                ]
            }
        }
        _ => return Err(TransportError::InvalidRequest),
    };
    if keys.len() != allowed.len() || allowed.iter().any(|key| !keys.contains(key)) {
        return Err(TransportError::InvalidRequest);
    }
    Ok(())
}

struct JsonObject;
impl<'de> serde::de::Visitor<'de> for JsonObject {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON object")
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(())
    }
}
