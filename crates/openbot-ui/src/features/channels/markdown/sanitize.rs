//! URL and resource sanitization for safe Markdown rendering.
//!
//! Enforces GUI Design Specification §6.4:
//! - Rejects dangerous URL schemes (`javascript:`, `data:`, `file:`) and URLs containing credentials or control characters.
//! - Anti-phishing domain extraction: displays verified target domain chip alongside link text.
//! - Zero-network image policy: remote images are strictly converted to link chips showing the destination domain.
//! - Verified attachment policy: only authenticated, same-origin or authorized custom protocol attachments can be rendered.

use url::Url;

/// Sanitized link destination. Inline attachments require a separate trusted authority, not a URL prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafeUrl {
    /// Safe external web URL (HTTP/HTTPS) or mailto link.
    External {
        /// Normalized URL string.
        href: String,
        /// Extracted domain or authority for anti-phishing UI display.
        domain: String,
    },
    /// Dangerous, malformed, or unauthorized URL that must be neutralized as plain text.
    Inert {
        /// Raw rejected text.
        raw: String,
        /// Rejection reason code.
        reason: &'static str,
    },
}

impl SafeUrl {
    /// Sanitizes an input URL string according to strict security policies.
    pub fn parse(input: &str) -> Self {
        if input.chars().any(char::is_control) {
            return Self::Inert {
                raw: input.to_owned(),
                reason: "control_characters",
            };
        }
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Self::Inert {
                raw: input.to_owned(),
                reason: "empty_url",
            };
        }

        // A model-controlled protocol prefix cannot prove ownership or attachment authorization.
        // There is no registered attachment authority in this consumer yet.
        if trimmed.starts_with("openbot-attachment://") {
            return Self::Inert {
                raw: trimmed.to_owned(),
                reason: "attachment_authority_missing",
            };
        }

        // Relative paths must not be automatically assumed to be safe application attachments
        // unless explicit attachment authority is present.
        if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
            return Self::Inert {
                raw: trimmed.to_owned(),
                reason: "relative_attachment_unverified",
            };
        }

        // Mailto links.
        if let Some(rest) = trimmed.strip_prefix("mailto:") {
            if rest.contains('@') && !rest.contains(':') && !rest.contains('/') {
                return Self::External {
                    href: trimmed.to_owned(),
                    domain: rest.split('?').next().unwrap_or(rest).to_owned(),
                };
            }
            return Self::Inert {
                raw: trimmed.to_owned(),
                reason: "malformed_mailto",
            };
        }

        // Parse as standard URL.
        match Url::parse(trimmed) {
            Ok(parsed) => {
                // Reject dangerous schemes.
                let scheme = parsed.scheme().to_ascii_lowercase();
                if scheme != "http" && scheme != "https" {
                    return Self::Inert {
                        raw: trimmed.to_owned(),
                        reason: "forbidden_scheme",
                    };
                }

                // Reject userinfo (e.g. http://attacker:password@example.com).
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Self::Inert {
                        raw: trimmed.to_owned(),
                        reason: "userinfo_forbidden",
                    };
                }

                // Extract domain/host.
                let domain = match parsed.host_str() {
                    Some(host) => host.to_ascii_lowercase(),
                    None => {
                        return Self::Inert {
                            raw: trimmed.to_owned(),
                            reason: "missing_host",
                        };
                    }
                };

                Self::External {
                    href: parsed.to_string(),
                    domain,
                }
            }
            Err(_) => Self::Inert {
                raw: trimmed.to_owned(),
                reason: "parse_error",
            },
        }
    }

    /// Returns `true` if this URL is safe to open as an external link.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External { .. })
    }
}

/// Image rendering policy classifying image sources into safe inline attachments or remote link chips.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImagePolicy {
    /// Remote image destination that must NEVER trigger network requests; rendered as a link chip.
    RemoteChip {
        /// Target URL.
        href: String,
        /// Host domain.
        domain: String,
        /// Alternative text.
        alt: String,
        /// Title attribute if present.
        title: Option<String>,
    },
    /// Malformed or rejected image destination.
    Blocked {
        /// Alternative text.
        alt: String,
        /// Rejection reason.
        reason: &'static str,
    },
}

impl ImagePolicy {
    /// Classifies an image source and metadata according to the zero-network remote image policy.
    pub fn classify(src: &str, alt: &str, title: Option<&str>) -> Self {
        match SafeUrl::parse(src) {
            SafeUrl::External { href, domain } => Self::RemoteChip {
                href,
                domain,
                alt: alt.to_owned(),
                title: title.map(str::to_owned),
            },
            SafeUrl::Inert { reason, .. } => Self::Blocked {
                alt: alt.to_owned(),
                reason,
            },
        }
    }
}
