//! Gloo 0.6 adds a trailing '&' when its URL already has a query. Keep the base URL query-free
//! and pass decoded pairs through `.query` exactly once, for reads AND OAuth/grant mutations.
//! Caller-owned route validation is unchanged; this module does not decide authorization.

#[cfg(any(target_arch = "wasm32", test))]
fn parts(path: &str) -> (&str, Vec<(String, String)>) {
    match path.split_once('?') {
        Some((base, query)) => (
            base,
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect(),
        ),
        None => (path, Vec::new()),
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) struct Request;

#[cfg(target_arch = "wasm32")]
pub(crate) trait PreparedRequest {
    fn prepare(self) -> Result<gloo_net::http::Request, crate::api::ApiError>;
}

#[cfg(target_arch = "wasm32")]
impl PreparedRequest for gloo_net::http::RequestBuilder {
    fn prepare(self) -> Result<gloo_net::http::Request, crate::api::ApiError> {
        self.build().map_err(|_| crate::api::ApiError::NotSubmitted)
    }
}

#[cfg(target_arch = "wasm32")]
impl PreparedRequest for gloo_net::http::Request {
    fn prepare(self) -> Result<gloo_net::http::Request, crate::api::ApiError> {
        Ok(self)
    }
}

#[cfg(target_arch = "wasm32")]
impl Request {
    pub(crate) fn decode<'a, T: serde::de::DeserializeOwned + 'a>(
        response: &'a gloo_net::http::Response,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, crate::api::ApiError>> + 'a>>
    {
        Box::pin(async move {
            let body = read_body(response).await?;
            serde_json::from_str(&body).map_err(|_| crate::api::ApiError::InvalidResponse)
        })
    }

    pub(crate) fn send(
        request: impl PreparedRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<gloo_net::http::Response, crate::api::ApiError>>,
        >,
    > {
        send_owned(request.prepare())
    }
    // Named `builder`, not `new`: this returns a `gloo_net::http::RequestBuilder`, never `Self`
    // (`Request` is a zero-sized method namespace, not a value type).
    #[inline(never)]
    fn builder(path: &str, method: gloo_net::http::Method) -> gloo_net::http::RequestBuilder {
        use web_sys::{RequestCache, RequestCredentials, RequestRedirect};
        let (base, pairs) = parts(path);
        gloo_net::http::RequestBuilder::new(base)
            .method(method)
            .query(
                pairs
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .cache(RequestCache::NoStore)
            .credentials(RequestCredentials::SameOrigin)
            .redirect(RequestRedirect::Error)
    }
    pub(crate) fn get(path: &str) -> gloo_net::http::RequestBuilder {
        Self::builder(path, gloo_net::http::Method::GET)
    }
    pub(crate) fn post(path: &str) -> gloo_net::http::RequestBuilder {
        Self::builder(path, gloo_net::http::Method::POST)
    }
    pub(crate) fn put(path: &str) -> gloo_net::http::RequestBuilder {
        Self::builder(path, gloo_net::http::Method::PUT)
    }
    pub(crate) fn patch(path: &str) -> gloo_net::http::RequestBuilder {
        Self::builder(path, gloo_net::http::Method::PATCH)
    }
    pub(crate) fn delete(path: &str) -> gloo_net::http::RequestBuilder {
        Self::builder(path, gloo_net::http::Method::DELETE)
    }
}

/// Share the browser body wait while keeping each existing typed DTO and receipt validator.
#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn read_body(
    response: &gloo_net::http::Response,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<zeroize::Zeroizing<String>, crate::api::ApiError>>
            + '_,
    >,
> {
    Box::pin(async move {
        response
            .text()
            .await
            .map(zeroize::Zeroizing::new)
            .map_err(|_| crate::api::ApiError::InvalidResponse)
    })
}

/// One browser wait implementation; bodies remain in the prepared request, never in a UI cache.
#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn send_owned(
    request: Result<gloo_net::http::Request, crate::api::ApiError>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<gloo_net::http::Response, crate::api::ApiError>>>,
> {
    Box::pin(async move {
        request?
            .send()
            .await
            .map_err(|_| crate::api::ApiError::Network)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_is_encoded_once_without_an_empty_segment() {
        for (path, expected) in [
            (
                "/api/channels?limit=50&cursor=opaque%2B%2F%3D",
                "limit=50&cursor=opaque%2B%2F%3D",
            ),
            (
                "/api/admin/people?search=Target%20%2B%20one",
                "search=Target+%2B+one",
            ),
            (
                "/api/plugins/grants?kind=skill&ref=a%26b&agentId=a%2Fb",
                "kind=skill&ref=a%26b&agentId=a%2Fb",
            ),
            (
                "/api/plugins/servers/test/connect?returnTo=settings",
                "returnTo=settings",
            ),
            ("/api/agents?hidden=true", "hidden=true"),
        ] {
            let (base, pairs) = parts(path);
            assert!(!base.contains('?'));
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            assert_eq!(encoded, expected);
            assert!(!encoded.ends_with('&'));
            assert_eq!(
                url::form_urlencoded::parse(encoded.as_bytes())
                    .into_owned()
                    .collect::<Vec<_>>(),
                pairs
            );
        }
        assert_eq!(parts("/api/me"), ("/api/me", vec![]));
        // Duplicate keys must reach the existing closed parser, not be silently merged.
        assert_eq!(parts("/api/channels?limit=1&limit=2").1.len(), 2);
    }
}
