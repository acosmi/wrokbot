//! Validated static Leptos bundle hosting and first-frame theme/locale projection.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Uri};
use axum::routing::{MethodRouter, get};
use openbot_contracts::ui::{UiLocale, UiPreferences, UiTheme};
use tower_http::services::ServeDir;

const INDEX_MAX_BYTES: u64 = 1024 * 1024;
const HTML_ROOT_MARKER: &str = "<html lang=\"en\">";
const UI_COOKIE_NAME: &str = "openbot-ui";
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
                   connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; \
                   object-src 'none'; base-uri 'none'; form-action 'self'; frame-src 'self'; frame-ancestors 'none'; \
                   worker-src 'none'; manifest-src 'none'; media-src 'none'";
const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), display-capture=(), \
                                  usb=(), hid=(), serial=(), bluetooth=(), payment=(), \
                                  publickey-credentials-create=(), publickey-credentials-get=()";

/// Validated static GUI directory and bounded UTF-8 index template.
#[derive(Clone)]
pub struct StaticApp {
    root: Arc<PathBuf>,
    index: Arc<str>,
}

impl StaticApp {
    /// Canonicalize and validate one built Trunk distribution.
    ///
    /// # Errors
    ///
    /// Returns `InvalidData` unless the root is a directory, `index.html` is bounded UTF-8,
    /// contains the one rewrite marker, and every script is same-origin external with empty body.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let root = fs::canonicalize(path)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(invalid_data("APP_DIST_DIR is not a directory"));
        }
        let index_path = root.join("index.html");
        let metadata = fs::metadata(&index_path)?;
        if !metadata.is_file() || metadata.len() > INDEX_MAX_BYTES {
            return Err(invalid_data("static index is missing or exceeds 1 MiB"));
        }
        let bytes = fs::read(index_path)?;
        let index = String::from_utf8(bytes)
            .map_err(|_| invalid_data("static index is not valid UTF-8"))?;
        validate_index(&index)?;
        Ok(Self {
            root: Arc::new(root),
            index: Arc::from(index),
        })
    }

    fn root(&self) -> &Path {
        self.root.as_path()
    }

    fn response(&self, headers: &HeaderMap) -> Response<Body> {
        let preferences = first_frame_preferences(headers);
        let html = render_index(&self.index, preferences);
        let mut response = Response::new(Body::from(html));
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(PERMISSIONS_POLICY),
        );
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        response
    }
}

/// Mount a configured bundle without changing API unmatched-path semantics.
pub fn mount(router: Router, app: StaticApp) -> Router {
    let index = index_route(app.clone());
    let fallback_app = app.clone();
    let fallback = get(move |uri: Uri, headers: HeaderMap| {
        let app = fallback_app.clone();
        async move {
            if is_spa_path(uri.path()) {
                app.response(&headers)
            } else {
                status_response(StatusCode::NOT_FOUND)
            }
        }
    });
    let files = ServeDir::new(app.root())
        .append_index_html_on_directories(false)
        .fallback(fallback);
    router
        .route("/", index.clone())
        .route("/index.html", index)
        .fallback_service(files)
}

fn index_route(app: StaticApp) -> MethodRouter {
    get(move |headers: HeaderMap| {
        let app = app.clone();
        async move { app.response(&headers) }
    })
}

fn status_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static status response is valid")
}

fn is_spa_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path == "/api"
        || path.starts_with("/api/")
        || matches!(path, "/health" | "/readiness" | "/metrics")
        || path.starts_with("/health/")
        || path.starts_with("/readiness/")
        || path.starts_with("/metrics/")
        || path.starts_with("/fonts/")
        || path.starts_with("/.well-known/")
    {
        return false;
    }
    !path
        .rsplit('/')
        .next()
        .is_some_and(|segment| segment.contains('.'))
}

fn validate_index(index: &str) -> io::Result<()> {
    if index.matches(HTML_ROOT_MARKER).count() != 1 {
        return Err(invalid_data(
            "static index must contain one html lang marker",
        ));
    }
    let lower = index.to_ascii_lowercase();
    if lower.contains("<base") {
        return Err(invalid_data("static index must not set a base URL"));
    }
    let mut rest = lower.as_str();
    let mut script_count = 0;
    while let Some(start) = rest.find("<script") {
        script_count += 1;
        rest = &rest[start..];
        let open_end = rest
            .find('>')
            .ok_or_else(|| invalid_data("unterminated script tag"))?;
        let opening = &rest[..=open_end];
        if opening.matches(" src=").count() != 1
            || !(opening.contains(" src=\"/openbot-bootstrap.mjs\"")
                || opening.contains(" src=\"./openbot-bootstrap.mjs\""))
        {
            return Err(invalid_data(
                "static index must load the one same-origin OpenBot bootstrap",
            ));
        }
        let after_open = &rest[open_end + 1..];
        let close = after_open
            .find("</script>")
            .ok_or_else(|| invalid_data("script tag has no close"))?;
        if !after_open[..close].trim().is_empty() {
            return Err(invalid_data("external script element has inline body"));
        }
        rest = &after_open[close + "</script>".len()..];
    }
    if script_count != 1 {
        return Err(invalid_data(
            "static index must contain exactly one application script",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FirstFramePreferences {
    theme: UiTheme,
    locale: UiLocale,
}

fn first_frame_preferences(headers: &HeaderMap) -> FirstFramePreferences {
    if let Some(cookie) = ui_cookie(headers) {
        return cookie;
    }
    FirstFramePreferences {
        theme: UiTheme::System,
        locale: accept_language(headers),
    }
}

/// Build the closed non-sensitive mirror cookie from stored fields and this request's host
/// fallback. Stored values win independently; an unset field retains cookie/Accept-Language.
pub(crate) fn preference_cookie(
    stored: UiPreferences,
    request_headers: &HeaderMap,
    secure: bool,
) -> HeaderValue {
    let fallback = first_frame_preferences(request_headers);
    let theme = stored.theme.unwrap_or(fallback.theme);
    let locale = stored.locale.unwrap_or(fallback.locale);
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{UI_COOKIE_NAME}=v1.{}.{}; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly{secure_attribute}",
        theme.as_str(),
        locale.as_str(),
    ))
    .expect("closed UI preference cookie is a valid header")
}

fn ui_cookie(headers: &HeaderMap) -> Option<FirstFramePreferences> {
    for header in headers.get_all(COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for pair in header.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != UI_COOKIE_NAME {
                continue;
            }
            let mut parts = value.split('.');
            if parts.next() != Some("v1") {
                return None;
            }
            let theme = match parts.next() {
                Some("system") => UiTheme::System,
                Some("light") => UiTheme::Light,
                Some("dark") => UiTheme::Dark,
                _ => return None,
            };
            let locale = match parts.next() {
                Some("en") => UiLocale::En,
                Some("zh-CN") => UiLocale::ZhCn,
                _ => return None,
            };
            if parts.next().is_some() {
                return None;
            }
            return Some(FirstFramePreferences { theme, locale });
        }
    }
    None
}

fn accept_language(headers: &HeaderMap) -> UiLocale {
    let Some(header) = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
    else {
        return UiLocale::En;
    };
    let mut best = None::<(f32, usize, UiLocale)>;
    for (order, item) in header.split(',').enumerate() {
        let mut parts = item.trim().split(';');
        let tag = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let locale = if tag == "zh" || tag.starts_with("zh-") {
            UiLocale::ZhCn
        } else if tag == "en" || tag.starts_with("en-") {
            UiLocale::En
        } else {
            continue;
        };
        let mut quality = 1.0_f32;
        for parameter in parts {
            if let Some(raw) = parameter.trim().strip_prefix("q=") {
                let Ok(parsed) = raw.parse::<f32>() else {
                    quality = 0.0;
                    break;
                };
                if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
                    quality = 0.0;
                    break;
                }
                quality = parsed;
            }
        }
        if quality == 0.0 {
            continue;
        }
        if best.is_none_or(|(best_quality, best_order, _)| {
            quality > best_quality || quality == best_quality && order < best_order
        }) {
            best = Some((quality, order, locale));
        }
    }
    best.map_or(UiLocale::En, |(_, _, locale)| locale)
}

fn render_index(index: &str, preferences: FirstFramePreferences) -> String {
    let locale = match preferences.locale {
        UiLocale::En => "en",
        UiLocale::ZhCn => "zh-CN",
    };
    let replacement = match preferences.theme {
        UiTheme::System => format!("<html lang=\"{locale}\">"),
        UiTheme::Light => format!("<html lang=\"{locale}\" class=\"light\">"),
        UiTheme::Dark => format!("<html lang=\"{locale}\" class=\"dark\">"),
    };
    index.replacen(HTML_ROOT_MARKER, &replacement, 1)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use tower::ServiceExt as _;

    const INDEX: &str = "<!doctype html><html lang=\"en\"><head>\
        <script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script>\
        </head><body></body></html>";

    #[test]
    fn index_requires_external_same_origin_empty_scripts() {
        assert!(validate_index(INDEX).is_ok());
        assert!(validate_index("<html lang=\"en\"><script>bad()</script>").is_err());
        assert!(
            validate_index("<html lang=\"en\"><script src=\"https://example.test/a.js\"></script>")
                .is_err()
        );
        assert!(
            validate_index("<html lang=\"en\"><script src=\"/a.js\">inline()</script>").is_err()
        );
        assert!(
            validate_index(
                "<html lang=\"en\"><script src=\"//example.test/openbot-bootstrap.mjs\"></script>"
            )
            .is_err()
        );
        assert!(
            validate_index(
                "<html lang=\"en\"><script src=\"/openbot-bootstrap.mjs\" src=\"//example.test/x.js\"></script>"
            )
            .is_err()
        );
        assert!(
            validate_index(
                "<html lang=\"en\"><script src=\"/openbot-bootstrap.mjs\"></script><script src=\"/openbot-bootstrap.mjs\"></script>"
            )
            .is_err()
        );
    }

    #[test]
    fn closed_cookie_wins_and_invalid_cookie_falls_back_to_accept_language() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("session=x; openbot-ui=v1.dark.zh-CN"),
        );
        headers.insert(
            axum::http::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en;q=1"),
        );
        let preferences = first_frame_preferences(&headers);
        assert_eq!(preferences.theme, UiTheme::Dark);
        assert_eq!(preferences.locale, UiLocale::ZhCn);
        assert!(render_index(INDEX, preferences).contains("lang=\"zh-CN\" class=\"dark\""));

        headers.insert(COOKIE, HeaderValue::from_static("openbot-ui=v2.dark.en"));
        assert_eq!(first_frame_preferences(&headers).locale, UiLocale::En);
        assert_eq!(first_frame_preferences(&headers).theme, UiTheme::System);

        let mirrored = preference_cookie(
            UiPreferences {
                theme: Some(UiTheme::Light),
                locale: None,
            },
            &headers,
            true,
        );
        assert_eq!(
            mirrored,
            "openbot-ui=v1.light.en; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly; Secure"
        );
    }

    #[test]
    fn accept_language_honors_quality_and_spa_does_not_hide_api_or_assets() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US;q=0.4, zh-CN;q=0.9"),
        );
        assert_eq!(accept_language(&headers), UiLocale::ZhCn);
        assert!(is_spa_path("/approvals"));
        assert!(!is_spa_path("/api/missing"));
        assert!(!is_spa_path("/missing.js"));
        assert!(!is_spa_path("/fonts/missing"));
    }

    #[tokio::test]
    async fn mounted_serve_dir_rewrites_routes_but_never_hides_missing_api_or_assets() {
        let bundle = TempBundle::new();
        let app = StaticApp::open(&bundle.0).unwrap();
        let router = mount(Router::new(), app);

        let root = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(COOKIE, "openbot-ui=v1.dark.zh-CN")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::OK);
        assert_eq!(root.headers().get(CONTENT_SECURITY_POLICY).unwrap(), CSP);
        assert_eq!(root.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let body = to_bytes(root.into_body(), INDEX_MAX_BYTES as usize)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("lang=\"zh-CN\" class=\"dark\""));

        let route = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/approvals")
                    .header(axum::http::header::ACCEPT_LANGUAGE, "zh;q=1, en;q=.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(route.status(), StatusCode::OK);
        let body = to_bytes(route.into_body(), INDEX_MAX_BYTES as usize)
            .await
            .unwrap();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("lang=\"zh-CN\"")
        );

        let asset = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(asset.into_body(), 1024).await.unwrap().as_ref(),
            b"export {};"
        );

        for uri in ["/api/missing", "/missing.js", "/fonts/missing"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    struct TempBundle(PathBuf);

    impl TempBundle {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "openbot-static-app-{}",
                uuid::Uuid::now_v7().as_simple()
            ));
            fs::create_dir(&path).unwrap();
            fs::write(path.join("index.html"), INDEX).unwrap();
            fs::write(path.join("app.js"), "export {};").unwrap();
            Self(path)
        }
    }

    impl Drop for TempBundle {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
