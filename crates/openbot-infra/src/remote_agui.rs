//! Unique SafeDialer-backed raw HTTP/SSE transport for remote AG-UI.

use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use openbot_application::{
    RemoteAguiAuthorization, RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use url::Url;

use crate::net::safe_http::{
    AuthorizationValue, SafeDialer, SafeHttpBudget, SafeHttpError, SafeHttpRequest,
    SafeHttpStreamResponse, SchemePolicy,
};
use crate::provider::sse::SseDecoder;

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";

/// Production transport configuration. It owns no endpoint or credential.
#[derive(Debug)]
pub struct SafeRemoteAguiTransport {
    dialer: SafeDialer,
    budget: SafeHttpBudget,
    stall_timeout: Option<Duration>,
    scheme_policy: SchemePolicy,
}

impl SafeRemoteAguiTransport {
    /// Construct with explicit egress/scheme/budget policy.
    pub fn new(
        dialer: SafeDialer,
        budget: SafeHttpBudget,
        stall_timeout: Option<Duration>,
        scheme_policy: SchemePolicy,
    ) -> Result<Self, RemoteAguiTransportError> {
        if stall_timeout.is_some_and(|value| value.is_zero()) {
            return Err(RemoteAguiTransportError::InvalidResponse);
        }
        Ok(Self {
            dialer,
            budget,
            stall_timeout,
            scheme_policy,
        })
    }
}

#[async_trait]
impl RemoteAguiTransport for SafeRemoteAguiTransport {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        let url =
            Url::parse(endpoint).map_err(|_| RemoteAguiTransportError::DestinationRejected)?;
        self.dialer
            .validate_destination(&url, self.scheme_policy)
            .await
            .map_err(map_validation_error)
    }

    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        let url = Url::parse(endpoint).map_err(|_| RemoteAguiTransportError::InvalidResponse)?;
        let authorization = authorization
            .map(|value| {
                value
                    .expose()
                    .map_err(|_| RemoteAguiTransportError::InvalidResponse)
                    .and_then(|value| {
                        AuthorizationValue::parse(value)
                            .map_err(|_| RemoteAguiTransportError::InvalidResponse)
                    })
            })
            .transpose()?;
        let request = SafeHttpRequest::post_json_with_scheme(
            url,
            self.scheme_policy,
            body,
            authorization,
            self.budget,
        )
        .map_err(map_start_error)?;
        let response = self
            .dialer
            .execute_stream(request)
            .await
            .map_err(map_start_error)?;
        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(RemoteAguiTransportError::Authentication);
            }
            StatusCode::TOO_MANY_REQUESTS => {
                return Err(RemoteAguiTransportError::RateLimited);
            }
            status if status.is_server_error() => {
                return Err(RemoteAguiTransportError::ServerUnavailable);
            }
            status if !status.is_success() => {
                return Err(RemoteAguiTransportError::InvalidResponse);
            }
            _ => {}
        }
        let content_type = response
            .header(&CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        if !content_type.eq_ignore_ascii_case(EVENT_STREAM_CONTENT_TYPE) {
            return Err(RemoteAguiTransportError::InvalidResponse);
        }
        Ok(Box::new(SafeRemoteAguiStream {
            response,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            stall_timeout: self.stall_timeout,
            ended: false,
        }))
    }
}

struct SafeRemoteAguiStream {
    response: SafeHttpStreamResponse,
    decoder: SseDecoder,
    pending: VecDeque<String>,
    stall_timeout: Option<Duration>,
    ended: bool,
}

#[async_trait]
impl RemoteAguiEventStream for SafeRemoteAguiStream {
    async fn next_data(&mut self) -> Result<Option<String>, RemoteAguiTransportError> {
        loop {
            if let Some(data) = self.pending.pop_front() {
                return Ok(Some(data));
            }
            if self.ended {
                return Ok(None);
            }
            match self.response.next_chunk(self.stall_timeout).await {
                Ok(Some(chunk)) => self.pending.extend(
                    self.decoder
                        .push(&chunk)
                        .map_err(|_| RemoteAguiTransportError::InvalidResponse)?,
                ),
                Ok(None) => {
                    self.decoder
                        .finish()
                        .map_err(|_| RemoteAguiTransportError::InvalidResponse)?;
                    self.ended = true;
                }
                Err(SafeHttpError::StreamStalled) => {
                    return Err(RemoteAguiTransportError::StreamStalled);
                }
                Err(_) => return Err(RemoteAguiTransportError::InvalidResponse),
            }
        }
    }
}

const fn map_start_error(error: SafeHttpError) -> RemoteAguiTransportError {
    match error {
        SafeHttpError::DnsUnavailable | SafeHttpError::ConnectFailed | SafeHttpError::TlsFailed => {
            RemoteAguiTransportError::Unavailable
        }
        SafeHttpError::InvalidUrl
        | SafeHttpError::SchemeRejected
        | SafeHttpError::DestinationDenied => RemoteAguiTransportError::DestinationRejected,
        SafeHttpError::DeadlineExceeded
        | SafeHttpError::ProtocolFailed
        | SafeHttpError::ResponseTooLarge
        | SafeHttpError::StreamStalled => RemoteAguiTransportError::CommitUnknown,
        SafeHttpError::InvalidBudget
        | SafeHttpError::InvalidHeader
        | SafeHttpError::InvalidAllowlist
        | SafeHttpError::PeerMismatch
        | SafeHttpError::RedirectInvalid
        | SafeHttpError::RedirectLimit
        | SafeHttpError::RedirectMethodRejected
        | SafeHttpError::SensitiveRedirectRejected => RemoteAguiTransportError::InvalidResponse,
    }
}

const fn map_validation_error(error: SafeHttpError) -> RemoteAguiTransportError {
    match error {
        SafeHttpError::DnsUnavailable => RemoteAguiTransportError::Unavailable,
        SafeHttpError::InvalidUrl
        | SafeHttpError::SchemeRejected
        | SafeHttpError::DestinationDenied => RemoteAguiTransportError::DestinationRejected,
        _ => RemoteAguiTransportError::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::net::safe_http::{CidrAllowlist, EgressPolicy};

    #[tokio::test]
    async fn real_loopback_post_and_fragmented_sse_use_the_unique_safe_dialer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                    let header_end = header_end + 4;
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap();
                    if bytes.len() >= header_end + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with("POST /agent/run "));
            assert!(request.contains("accept: text/event-stream"));
            assert!(request.contains("authorization: Bearer remote-test-secret"));
            assert!(request.ends_with(r#"{"runId":"run-1"}"#));
            let body = concat!(
                "data: {\"type\":\"RUN_STARTED\",\"threadId\":\"t\",\"runId\":\"r\"}\n\n",
                "data: {\"type\":\"RUN_FINISHED\",\"threadId\":\"t\",\"runId\":\"r\"}\n\n",
            );
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            for chunk in body.as_bytes().chunks(3) {
                stream.write_all(chunk).await.unwrap();
            }
        });
        let transport = SafeRemoteAguiTransport::new(
            SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap(),
            Some(Duration::from_secs(1)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        transport
            .validate_endpoint(&format!("http://{address}/agent/run"))
            .await
            .unwrap();
        let authorization = RemoteAguiAuthorization::new(openbot_domain::vault::SecretBytes::new(
            b"Bearer remote-test-secret".to_vec(),
        ))
        .unwrap();
        let mut stream = transport
            .start(
                &format!("http://{address}/agent/run"),
                Some(&authorization),
                br#"{"runId":"run-1"}"#.to_vec(),
            )
            .await
            .unwrap();
        assert!(
            stream
                .next_data()
                .await
                .unwrap()
                .unwrap()
                .contains("RUN_STARTED")
        );
        assert!(
            stream
                .next_data()
                .await
                .unwrap()
                .unwrap()
                .contains("RUN_FINISHED")
        );
        assert_eq!(stream.next_data().await.unwrap(), None);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn endpoint_preflight_rejects_metadata_without_opening_a_socket() {
        let transport = SafeRemoteAguiTransport::new(
            SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(std::iter::empty::<&str>()).unwrap(),
            )),
            SafeHttpBudget::new(64 * 1024, Duration::from_secs(2)).unwrap(),
            Some(Duration::from_secs(1)),
            SchemePolicy::HttpOrHttps,
        )
        .unwrap();
        assert_eq!(
            transport
                .validate_endpoint("http://169.254.169.254/latest/meta-data")
                .await,
            Err(RemoteAguiTransportError::DestinationRejected)
        );
    }
}
