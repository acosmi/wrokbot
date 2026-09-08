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
impl Request {
    fn new(path: &str, method: gloo_net::http::Method) -> gloo_net::http::RequestBuilder {
        let (base, pairs) = parts(path);
        gloo_net::http::RequestBuilder::new(base)
            .method(method)
            .query(
                pairs
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
    }
    pub(crate) fn get(path: &str) -> gloo_net::http::RequestBuilder {
        Self::new(path, gloo_net::http::Method::GET)
    }
    pub(crate) fn post(path: &str) -> gloo_net::http::RequestBuilder {
        Self::new(path, gloo_net::http::Method::POST)
    }
    pub(crate) fn put(path: &str) -> gloo_net::http::RequestBuilder {
        Self::new(path, gloo_net::http::Method::PUT)
    }
    pub(crate) fn patch(path: &str) -> gloo_net::http::RequestBuilder {
        Self::new(path, gloo_net::http::Method::PATCH)
    }
    pub(crate) fn delete(path: &str) -> gloo_net::http::RequestBuilder {
        Self::new(path, gloo_net::http::Method::DELETE)
    }
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
