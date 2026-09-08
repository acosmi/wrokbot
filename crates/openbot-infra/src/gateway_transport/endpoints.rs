use super::{GatewayConfigError, GatewayRequestKind};
use std::fmt;
use url::Url;

/// Fixed wire format for one host-selected gateway model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayModelWire {
    /// Gateway OpenAI chat wire.
    OpenAi,
    /// Gateway Anthropic messages wire.
    Anthropic,
}
/// Fixed OAuth discovery profile; this does not authorize or start login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayOAuthProfile {
    /// Desktop PKCE metadata.
    Desktop,
    /// Web PKCE metadata.
    Web,
}
/// Host-reviewed OAuth endpoints. Construction validates shape; each send still needs a fence.
#[derive(Clone)]
pub struct GatewayOAuthEndpoints {
    profile: GatewayOAuthProfile,
    registration: Url,
    token: Url,
    revocation: Option<Url>,
}
impl GatewayOAuthEndpoints {
    /// Accept exact HTTPS targets; the enclosing set also enforces their configured origin.
    pub fn new(
        profile: GatewayOAuthProfile,
        registration: &str,
        token: &str,
        revocation: Option<&str>,
    ) -> Result<Self, GatewayConfigError> {
        Ok(Self {
            profile,
            registration: parse_url(registration)?,
            token: parse_url(token)?,
            revocation: revocation.map(parse_url).transpose()?,
        })
    }
}
impl fmt::Debug for GatewayOAuthEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayOAuthEndpoints([redacted])")
    }
}
/// Complete immutable destination set. SDK metadata and HttpContext cannot enlarge it.
#[derive(Clone)]
pub struct VerifiedGatewayEndpoints {
    catalogue: Url,
    picker: Url,
    model: Option<Url>,
    discovery: Option<Url>,
    oauth: Option<GatewayOAuthEndpoints>,
}
impl VerifiedGatewayEndpoints {
    /// Normalize the same API base as SDK4 and pin one optional model/wire and OAuth set.
    /// This validates routing data only, not account/current actor authority.
    pub fn new(
        base: &str,
        model: Option<(&str, GatewayModelWire)>,
        oauth: Option<GatewayOAuthEndpoints>,
    ) -> Result<Self, GatewayConfigError> {
        let base_url = parse_url(base)?;
        let normalized = base_url.as_str().trim_end_matches('/');
        let api = if normalized.ends_with("/api/v4") {
            normalized.to_owned()
        } else {
            format!("{normalized}/api/v4")
        };
        let catalogue = parse_url(&format!("{api}/managed-models"))?;
        let mut picker = catalogue.clone();
        picker.set_query(Some("picker=1"));
        if picker.as_str().len() > 2048 {
            return Err(GatewayConfigError);
        }
        let model = model
            .map(|(id, wire)| {
                if id.is_empty() || matches!(id, "." | "..") || id.chars().any(char::is_control) {
                    return Err(GatewayConfigError);
                }
                let mut encoded = String::new();
                // SDK4's encodeURIComponent-compatible path-segment encoding, not form '+' encoding.
                for byte in id.bytes() {
                    if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
                        encoded.push(char::from(byte));
                    } else {
                        use std::fmt::Write;
                        write!(&mut encoded, "%{byte:02X}").map_err(|_| GatewayConfigError)?;
                    }
                    if encoded.len() > 2048 {
                        return Err(GatewayConfigError);
                    }
                }
                let suffix = match wire {
                    GatewayModelWire::OpenAi => "chat",
                    GatewayModelWire::Anthropic => "anthropic",
                };
                parse_url(&format!("{api}/managed-models/{encoded}/{suffix}"))
            })
            .transpose()?;
        let discovery = if let Some(set) = &oauth {
            for endpoint in [&set.registration, &set.token]
                .into_iter()
                .chain(set.revocation.iter())
            {
                if endpoint.origin() != base_url.origin() {
                    return Err(GatewayConfigError);
                }
            }
            let profile = match set.profile {
                GatewayOAuthProfile::Desktop => "desktop",
                GatewayOAuthProfile::Web => "web",
            };
            Some(parse_url(&format!(
                "{}/.well-known/oauth-authorization-server/{profile}",
                base_url.origin().ascii_serialization()
            ))?)
        } else {
            None
        };
        let urls = [&catalogue, &picker]
            .into_iter()
            .chain(model.iter())
            .chain(discovery.iter())
            .chain(oauth.iter().flat_map(|set| {
                [&set.registration, &set.token]
                    .into_iter()
                    .chain(set.revocation.iter())
            }));
        let mut seen = std::collections::BTreeSet::new();
        for url in urls {
            if !seen.insert(url.as_str()) {
                return Err(GatewayConfigError);
            }
        }
        Ok(Self {
            catalogue,
            picker,
            model,
            discovery,
            oauth,
        })
    }
    pub(super) fn classify(&self, url: &Url) -> Option<GatewayRequestKind> {
        if url.as_str().len() > 2048 {
            return None;
        }
        if url == &self.catalogue || url == &self.picker {
            return Some(GatewayRequestKind::Catalogue);
        }
        if self.model.as_ref() == Some(url) {
            return Some(GatewayRequestKind::Model);
        }
        if self.discovery.as_ref() == Some(url) {
            return Some(GatewayRequestKind::OAuthDiscovery);
        }
        if let Some(set) = &self.oauth {
            if url == &set.registration {
                return Some(GatewayRequestKind::OAuthRegistration);
            }
            if url == &set.token {
                return Some(GatewayRequestKind::OAuthToken);
            }
            if set.revocation.as_ref() == Some(url) {
                return Some(GatewayRequestKind::OAuthRevocation);
            }
        }
        None
    }
}
impl fmt::Debug for VerifiedGatewayEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedGatewayEndpoints([redacted])")
    }
}
fn parse_url(raw: &str) -> Result<Url, GatewayConfigError> {
    if raw.is_empty() || raw.len() > 2048 || raw.trim() != raw || raw.chars().any(char::is_control)
    {
        return Err(GatewayConfigError);
    }
    let url = Url::parse(raw).map_err(|_| GatewayConfigError)?;
    if url.as_str().len() > 2048
        || url.scheme() != "https"
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GatewayConfigError);
    }
    Ok(url)
}
