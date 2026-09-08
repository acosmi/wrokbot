//! SAML 2.0 SP：离线 metadata、SP-initiated request、xmlsec 签名覆盖与 profile 校验。

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use openbot_domain::identity::groups::{GroupName, GroupNormalization};
use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use samael::crypto::{
    AllowedSignatureAlgorithm, CertificateDer, Crypto, CryptoProvider, ReduceMode,
};
use samael::metadata::{EntityDescriptor, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use samael::schema::{Assertion, AuthnStatement, Response};
use samael::service_provider::ServiceProvider;
use samael::traits::ToXml;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::config::{SamlSecretConfig, SsoConfigError, validate_saml_entity_id};
use crate::auth::oidc::session_issuer::{FederatedIdentity, FederatedProvider};
use crate::auth::oidc::{EmailDomain, ProviderId};

const SAML_METADATA_NS: &[u8] = b"urn:oasis:names:tc:SAML:2.0:metadata";
const SAML_PROTOCOL_NS: &[u8] = b"urn:oasis:names:tc:SAML:2.0:protocol";
const XMLDSIG_NS: &[u8] = b"http://www.w3.org/2000/09/xmldsig#";
const SAML_PROTOCOL_URN: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const MAX_XML_BYTES: usize = 512 * 1024;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_ELEMENTS: usize = 20_000;
const MAX_XML_ATTRIBUTES_PER_ELEMENT: usize = 64;
const MAX_SUBJECT_BYTES: usize = 4096;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_EMAIL_CLAIM_VALUES: usize = 16;
const MAX_GROUP_CLAIM_VALUES: usize = 256;
const MAX_ISSUE_DELAY: Duration = Duration::minutes(5);
const MAX_CLOCK_SKEW: Duration = Duration::minutes(2);
const MAX_ASSERTION_LIFETIME: Duration = Duration::minutes(10);

const ALLOWED_SIGNATURE_ALGORITHMS: &[AllowedSignatureAlgorithm] = &[
    AllowedSignatureAlgorithm::RsaSha256,
    AllowedSignatureAlgorithm::RsaSha384,
    AllowedSignatureAlgorithm::RsaSha512,
    AllowedSignatureAlgorithm::EcdsaSha256,
    AllowedSignatureAlgorithm::EcdsaSha384,
    AllowedSignatureAlgorithm::EcdsaSha512,
];
const ALLOWED_DIGEST_ALGORITHMS: &[&str] = &[
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SamlError {
    #[error("saml_metadata_rejected")]
    MetadataRejected,
    #[error("saml_xml_rejected")]
    XmlRejected,
    #[error("saml_signature_rejected")]
    SignatureRejected,
    #[error("saml_profile_rejected")]
    ProfileRejected,
    #[error("saml_time_rejected")]
    TimeRejected,
    #[error("saml_identity_rejected")]
    IdentityRejected,
    #[error("saml_request_unavailable")]
    RequestUnavailable,
}

impl From<SsoConfigError> for SamlError {
    fn from(_: SsoConfigError) -> Self {
        Self::MetadataRejected
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SamlBinding {
    Redirect,
    Post,
}

pub enum SamlStart {
    Redirect(Url),
    Post {
        destination: Url,
        saml_request: String,
        relay_state: String,
    },
}

pub(crate) struct VerifiedSamlLogin {
    pub issuer: String,
    pub identity: FederatedIdentity,
    pub provider: FederatedProvider,
    pub assertion_id: String,
    pub assertion_expires_at: OffsetDateTime,
}

pub(crate) struct SamlRuntime {
    provider_id: ProviderId,
    idp_issuer: String,
    domains: BTreeSet<EmailDomain>,
    entry_point: Url,
    binding: SamlBinding,
    acs_url: String,
    sp_entity_id: String,
    service_provider: ServiceProvider,
    signing_certs: Vec<CertificateDer>,
    email_attribute: String,
    group_attribute: Option<String>,
    group_normalization: GroupNormalization,
}

impl SamlRuntime {
    pub(crate) fn build(
        provider_id: ProviderId,
        expected_idp_issuer: &str,
        domains: BTreeSet<EmailDomain>,
        config: SamlSecretConfig,
        public_url: &str,
        now: OffsetDateTime,
    ) -> Result<Self, SamlError> {
        validate_saml_entity_id(expected_idp_issuer)?;
        strict_xml_document(
            &config.metadata,
            SAML_METADATA_NS,
            b"EntityDescriptor",
            MAX_XML_BYTES,
        )?;
        let metadata: EntityDescriptor = config
            .metadata
            .parse()
            .map_err(|_| SamlError::MetadataRejected)?;
        if metadata.entity_id.as_deref() != Some(expected_idp_issuer) {
            return Err(SamlError::MetadataRejected);
        }
        validate_metadata_expiry(metadata.valid_until.as_ref(), now)?;
        let descriptors = metadata
            .idp_sso_descriptors
            .as_ref()
            .ok_or(SamlError::MetadataRejected)?;
        if descriptors.len() != 1 {
            return Err(SamlError::MetadataRejected);
        }
        let descriptor = &descriptors[0];
        validate_metadata_expiry(descriptor.valid_until.as_ref(), now)?;
        if !descriptor
            .protocol_support_enumeration
            .as_deref()
            .is_some_and(|value| {
                value
                    .split_ascii_whitespace()
                    .any(|item| item == SAML_PROTOCOL_URN)
            })
            || descriptor.want_authn_requests_signed == Some(true)
        {
            return Err(SamlError::MetadataRejected);
        }

        let mut selected_binding = None;
        for endpoint in &descriptor.single_sign_on_services {
            let parsed = validate_endpoint(&endpoint.location)?;
            let binding = match endpoint.binding.as_str() {
                HTTP_REDIRECT_BINDING => Some(SamlBinding::Redirect),
                HTTP_POST_BINDING => Some(SamlBinding::Post),
                _ => None,
            };
            if endpoint.location == config.entry_point {
                let binding = binding.ok_or(SamlError::MetadataRejected)?;
                if selected_binding.replace((binding, parsed)).is_some() {
                    return Err(SamlError::MetadataRejected);
                }
            }
        }
        // 即使本项目不挂 SLO，也拒绝 metadata 里的 javascript/data/file 等 action。
        for endpoint in &descriptor.single_logout_services {
            validate_endpoint(&endpoint.location)?;
            if let Some(response) = &endpoint.response_location {
                validate_endpoint(response)?;
            }
        }
        let (binding, entry_point) = selected_binding.ok_or(SamlError::MetadataRejected)?;
        let base = public_url.trim_end_matches('/');
        let acs_url = format!("{base}/api/auth/sso/saml2/sp/acs/{}", provider_id.as_str());
        let sp_entity_id = format!(
            "{base}/api/auth/sso/saml2/sp/metadata/{}",
            provider_id.as_str()
        );
        validate_endpoint(&acs_url)?;
        validate_endpoint(&sp_entity_id)?;
        let service_provider = ServiceProvider {
            entity_id: Some(sp_entity_id.clone()),
            metadata_url: Some(sp_entity_id.clone()),
            acs_url: Some(acs_url.clone()),
            idp_metadata: metadata,
            allow_idp_initiated: false,
            max_issue_delay: chrono::Duration::seconds(MAX_ISSUE_DELAY.whole_seconds()),
            max_clock_skew: chrono::Duration::seconds(MAX_CLOCK_SKEW.whole_seconds()),
            allowed_signature_algorithms: Some(ALLOWED_SIGNATURE_ALGORITHMS.to_vec()),
            ..ServiceProvider::default()
        };
        let signing_certs = service_provider
            .idp_signing_certs()
            .map_err(|_| SamlError::MetadataRejected)?
            .filter(|certs| !certs.is_empty() && certs.len() <= 16)
            .ok_or(SamlError::MetadataRejected)?;
        validate_certificates(&signing_certs, now)?;
        Ok(Self {
            provider_id,
            idp_issuer: expected_idp_issuer.to_owned(),
            domains,
            entry_point,
            binding,
            acs_url,
            sp_entity_id,
            service_provider,
            signing_certs,
            email_attribute: config.email_attribute,
            group_attribute: config.group_attribute,
            group_normalization: config.group_normalization,
        })
    }

    pub(crate) fn acs_url(&self) -> &str {
        &self.acs_url
    }

    pub(crate) fn metadata_xml(&self) -> Result<String, SamlError> {
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{}\"><md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\"><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{}\" index=\"0\" isDefault=\"true\"/></md:SPSSODescriptor></md:EntityDescriptor>",
            escape_xml_attribute(&self.sp_entity_id),
            escape_xml_attribute(&self.acs_url),
        ))
    }

    pub(crate) fn begin(
        &self,
        request_id: String,
        relay_state: String,
        now: OffsetDateTime,
    ) -> Result<SamlStart, SamlError> {
        if request_id.is_empty() || request_id.len() > 512 || !request_id.is_ascii() {
            return Err(SamlError::RequestUnavailable);
        }
        let mut request = self
            .service_provider
            .make_authentication_request(self.entry_point.as_str())
            .map_err(|_| SamlError::RequestUnavailable)?;
        request.id = request_id;
        request.issue_instant = to_chrono(now)?;
        match self.binding {
            SamlBinding::Redirect => request
                .redirect(&relay_state)
                .map_err(|_| SamlError::RequestUnavailable)?
                .map(SamlStart::Redirect)
                .ok_or(SamlError::RequestUnavailable),
            SamlBinding::Post => {
                let xml = request
                    .to_string()
                    .map_err(|_| SamlError::RequestUnavailable)?;
                Ok(SamlStart::Post {
                    destination: self.entry_point.clone(),
                    saml_request: BASE64_STANDARD.encode(xml.as_bytes()),
                    relay_state,
                })
            }
        }
    }

    pub(crate) fn verify_response(
        &self,
        encoded_response: &str,
        request_id: &str,
        expected_acs_url: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedSamlLogin, SamlError> {
        if expected_acs_url != self.acs_url
            || encoded_response.is_empty()
            || encoded_response.len() > MAX_XML_BYTES.saturating_mul(2)
        {
            return Err(SamlError::ProfileRejected);
        }
        let bytes = BASE64_STANDARD
            .decode(encoded_response)
            .map_err(|_| SamlError::XmlRejected)?;
        if bytes.len() > MAX_XML_BYTES {
            return Err(SamlError::XmlRejected);
        }
        let xml = core::str::from_utf8(&bytes).map_err(|_| SamlError::XmlRejected)?;
        strict_xml_document(xml, SAML_PROTOCOL_NS, b"Response", MAX_XML_BYTES)?;
        preflight_response_signature_shape(xml)?;

        // 先要求签名所覆盖的根就是 Response。只签 Assertion 会让外层 Destination 不在
        // 覆盖内，无法兑现第一真源的 Destination 绑定，因此 fail-closed。
        let reduced = Crypto::reduce_xml_to_signed_with_allowed_algorithms(
            xml,
            &self.signing_certs,
            ReduceMode::ValidateAndMarkNoAncestors,
            Some(ALLOWED_SIGNATURE_ALGORITHMS),
        )
        .map_err(|_| SamlError::SignatureRejected)?;
        strict_xml_document(&reduced, SAML_PROTOCOL_NS, b"Response", MAX_XML_BYTES)
            .map_err(|_| SamlError::SignatureRejected)?;
        let signed_response: Response = reduced.parse().map_err(|_| SamlError::ProfileRejected)?;
        validate_signed_response(
            &signed_response,
            request_id,
            &self.acs_url,
            &self.idp_issuer,
            now,
        )?;

        let possible = [request_id];
        let assertion = self
            .service_provider
            .parse_xml_response(xml, Some(&possible))
            .map_err(|_| SamlError::ProfileRejected)?;
        let assertion_expires_at = validate_assertion(
            &assertion,
            request_id,
            &self.acs_url,
            &self.sp_entity_id,
            &self.idp_issuer,
            now,
        )?;
        let subject = assertion
            .subject
            .as_ref()
            .and_then(|subject| subject.name_id.as_ref())
            .map(|name_id| name_id.value.trim().to_owned())
            .filter(|value| valid_identity_scalar(value))
            .ok_or(SamlError::IdentityRejected)?;
        let email = extract_email(&assertion, &self.email_attribute)?;
        let groups = extract_groups(
            &assertion,
            self.group_attribute.as_deref(),
            self.group_normalization,
        )?;
        Ok(VerifiedSamlLogin {
            issuer: self.idp_issuer.clone(),
            identity: FederatedIdentity::from_verified_saml(
                self.idp_issuer.clone(),
                subject,
                email,
                groups,
                self.group_normalization,
            ),
            provider: FederatedProvider::verified_saml(
                self.provider_id.clone(),
                self.idp_issuer.clone(),
                self.domains.clone(),
            ),
            assertion_id: assertion.id,
            assertion_expires_at,
        })
    }

    pub(crate) fn fresh_request_id() -> String {
        format!("id-{}", Uuid::now_v7())
    }
}

impl core::fmt::Debug for SamlRuntime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SamlRuntime")
            .field("provider_id", &self.provider_id)
            .field("idp_issuer", &self.idp_issuer)
            .field("domains", &self.domains)
            .field("entry_point", &self.entry_point)
            .field("binding", &self.binding)
            .field("acs_url", &self.acs_url)
            .field("sp_entity_id", &self.sp_entity_id)
            .field("signing_cert_count", &self.signing_certs.len())
            .finish_non_exhaustive()
    }
}

fn validate_signed_response(
    response: &Response,
    request_id: &str,
    acs_url: &str,
    idp_issuer: &str,
    now: OffsetDateTime,
) -> Result<(), SamlError> {
    if response.version != "2.0"
        || response.destination.as_deref() != Some(acs_url)
        || response.in_response_to.as_deref() != Some(request_id)
        || response
            .issuer
            .as_ref()
            .and_then(|issuer| issuer.value.as_deref())
            != Some(idp_issuer)
        || response
            .status
            .as_ref()
            .and_then(|status| status.status_code.value.as_deref())
            != Some(SAML_SUCCESS)
        || response.encrypted_assertion.is_some()
        || response.assertion.is_none()
    {
        return Err(SamlError::ProfileRejected);
    }
    validate_issue_instant(response.issue_instant, now)
}

fn preflight_response_signature_shape(xml: &str) -> Result<(), SamlError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Capture {
        Signature,
        Digest,
    }

    let mut reader = NsReader::from_str(xml);
    let mut depth = 0usize;
    let mut root_id = None;
    let mut signature_depth = None;
    let mut signature_count = 0usize;
    let mut signed_info_count = 0usize;
    let mut reference_count = 0usize;
    let mut reference_uri = None;
    let mut canonicalization_algorithms = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut transform_algorithms = Vec::new();
    let mut digest_algorithms = Vec::new();
    let mut capture = None;
    let mut signature_value = String::new();
    let mut digest_value = String::new();
    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|_| SamlError::SignatureRejected)?;
        match event {
            Event::Start(start) => {
                if depth == 0 {
                    root_id = attribute_value(&start, b"ID")?;
                } else if depth == 1
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Signature",
                    )
                {
                    signature_count += 1;
                    signature_depth = Some(depth + 1);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"SignedInfo",
                    )
                {
                    signed_info_count += 1;
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Reference",
                    )
                {
                    reference_count += 1;
                    reference_uri = attribute_value(&start, b"URI")?;
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"CanonicalizationMethod",
                    )
                {
                    canonicalization_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"SignatureMethod",
                    )
                {
                    signature_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Transform",
                    )
                {
                    transform_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"DigestMethod",
                    )
                {
                    digest_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"SignatureValue",
                    )
                {
                    capture = Some(Capture::Signature);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"DigestValue",
                    )
                {
                    capture = Some(Capture::Digest);
                }
                depth += 1;
            }
            Event::Empty(start) => {
                if depth == 1
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Signature",
                    )
                {
                    signature_count += 1;
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Reference",
                    )
                {
                    reference_count += 1;
                    reference_uri = attribute_value(&start, b"URI")?;
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"CanonicalizationMethod",
                    )
                {
                    canonicalization_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"SignatureMethod",
                    )
                {
                    signature_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"Transform",
                    )
                {
                    transform_algorithms.push(required_algorithm(&start)?);
                } else if signature_depth.is_some()
                    && element_matches(
                        &namespace,
                        start.local_name().as_ref(),
                        XMLDSIG_NS,
                        b"DigestMethod",
                    )
                {
                    digest_algorithms.push(required_algorithm(&start)?);
                }
            }
            Event::Text(text) => match capture {
                Some(Capture::Signature) => signature_value.push_str(
                    core::str::from_utf8(text.as_ref())
                        .map_err(|_| SamlError::SignatureRejected)?,
                ),
                Some(Capture::Digest) => digest_value.push_str(
                    core::str::from_utf8(text.as_ref())
                        .map_err(|_| SamlError::SignatureRejected)?,
                ),
                None => {}
            },
            Event::End(end) => {
                if end.local_name().as_ref() == b"SignatureValue"
                    || end.local_name().as_ref() == b"DigestValue"
                {
                    capture = None;
                }
                if signature_depth == Some(depth) && end.local_name().as_ref() == b"Signature" {
                    signature_depth = None;
                }
                depth = depth.checked_sub(1).ok_or(SamlError::SignatureRejected)?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let root_id = root_id.ok_or(SamlError::SignatureRejected)?;
    let expected_reference = format!("#{root_id}");
    if signature_count != 1
        || signed_info_count != 1
        || reference_count != 1
        || reference_uri.as_deref() != Some(expected_reference.as_str())
        || canonicalization_algorithms.len() != 1
        || canonicalization_algorithms[0] != EXCLUSIVE_C14N
        || signature_algorithms.len() != 1
        || !ALLOWED_SIGNATURE_ALGORITHMS
            .iter()
            .any(|allowed| allowed.signature_uri() == signature_algorithms[0].as_str())
        || transform_algorithms.len() != 2
        || transform_algorithms[0] != ENVELOPED_SIGNATURE
        || transform_algorithms[1] != EXCLUSIVE_C14N
        || digest_algorithms.len() != 1
        || !ALLOWED_DIGEST_ALGORITHMS.contains(&digest_algorithms[0].as_str())
        || signature_value.trim().is_empty()
        || digest_value.trim().is_empty()
    {
        return Err(SamlError::SignatureRejected);
    }
    Ok(())
}

fn required_algorithm(start: &quick_xml::events::BytesStart<'_>) -> Result<String, SamlError> {
    attribute_value(start, b"Algorithm")?.ok_or(SamlError::SignatureRejected)
}

fn attribute_value(
    start: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
) -> Result<Option<String>, SamlError> {
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| SamlError::SignatureRejected)?;
        if attribute.key.as_ref() == name {
            let value = core::str::from_utf8(attribute.value.as_ref())
                .map_err(|_| SamlError::SignatureRejected)?;
            if value.contains('&') || value.chars().any(char::is_control) {
                return Err(SamlError::SignatureRejected);
            }
            return Ok(Some(value.to_owned()));
        }
    }
    Ok(None)
}

fn validate_assertion(
    assertion: &Assertion,
    request_id: &str,
    acs_url: &str,
    audience: &str,
    idp_issuer: &str,
    now: OffsetDateTime,
) -> Result<OffsetDateTime, SamlError> {
    if assertion.version != "2.0"
        || !valid_identity_scalar(&assertion.id)
        || assertion.issuer.value.as_deref() != Some(idp_issuer)
    {
        return Err(SamlError::ProfileRejected);
    }
    validate_issue_instant(assertion.issue_instant, now)?;
    let authn_statements = assertion
        .authn_statements
        .as_deref()
        .filter(|statements| !statements.is_empty())
        .ok_or(SamlError::ProfileRejected)?;
    validate_authn_statements(authn_statements, now)?;
    let conditions = assertion
        .conditions
        .as_ref()
        .ok_or(SamlError::ProfileRejected)?;
    let expiry = conditions.not_on_or_after.ok_or(SamlError::TimeRejected)?;
    let conditions_expiry = validate_window(conditions.not_before, expiry, now)?;
    if !conditions
        .audience_restrictions
        .as_ref()
        .is_some_and(|restrictions| {
            !restrictions.is_empty()
                && restrictions
                    .iter()
                    .all(|restriction| restriction.audience.iter().any(|value| value == audience))
        })
    {
        return Err(SamlError::ProfileRejected);
    }
    let confirmations = assertion
        .subject
        .as_ref()
        .and_then(|subject| subject.subject_confirmations.as_ref())
        .ok_or(SamlError::ProfileRejected)?;
    let mut bearer_expiry = None;
    for confirmation in confirmations {
        if confirmation.method.as_deref() != Some("urn:oasis:names:tc:SAML:2.0:cm:bearer") {
            continue;
        }
        let Some(data) = confirmation.subject_confirmation_data.as_ref() else {
            continue;
        };
        if data.recipient.as_deref() != Some(acs_url)
            || data.in_response_to.as_deref() != Some(request_id)
            || data.address.is_some()
            || data.content.is_some()
        {
            continue;
        }
        let Some(expiry) = data.not_on_or_after else {
            continue;
        };
        if let Ok(expiry) = validate_window(data.not_before, expiry, now) {
            bearer_expiry =
                Some(bearer_expiry.map_or(expiry, |current: OffsetDateTime| current.min(expiry)));
        }
    }
    let effective_expiry = conditions_expiry.min(bearer_expiry.ok_or(SamlError::ProfileRejected)?);
    if effective_expiry > now + MAX_ASSERTION_LIFETIME + MAX_CLOCK_SKEW {
        return Err(SamlError::TimeRejected);
    }
    // validate_window 接受 expiry 后的 clock skew；replay 行必须覆盖同一个有效窗口，不能
    // 在 verifier 仍接受 assertion 时提前消失。
    Ok(effective_expiry + MAX_CLOCK_SKEW)
}

fn validate_authn_statements(
    statements: &[AuthnStatement],
    now: OffsetDateTime,
) -> Result<(), SamlError> {
    for statement in statements {
        let instant = statement
            .authn_instant
            .map(from_chrono)
            .transpose()?
            .ok_or(SamlError::ProfileRejected)?;
        if statement.authn_context.is_none() {
            return Err(SamlError::ProfileRejected);
        }
        if instant > now + MAX_CLOCK_SKEW {
            return Err(SamlError::TimeRejected);
        }
        if statement
            .session_not_on_or_after
            .map(from_chrono)
            .transpose()?
            .is_some_and(|expiry| now >= expiry + MAX_CLOCK_SKEW)
        {
            return Err(SamlError::TimeRejected);
        }
    }
    Ok(())
}

fn extract_email(assertion: &Assertion, configured: &str) -> Result<String, SamlError> {
    let mut values = attribute_values(assertion, configured);
    if values.is_empty() && configured == "email" {
        values.extend(attribute_values(assertion, "mail"));
        values.extend(attribute_values(
            assertion,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ));
    }
    if values.len() > MAX_EMAIL_CLAIM_VALUES {
        return Err(SamlError::IdentityRejected);
    }
    let mut emails: BTreeSet<String> = values
        .into_iter()
        .filter(|value| crate::auth::oidc::email::claim_looks_like_an_address(value))
        .map(str::to_owned)
        .collect();
    if emails.is_empty()
        && configured == "email"
        && let Some(name_id) = assertion
            .subject
            .as_ref()
            .and_then(|subject| subject.name_id.as_ref())
            .map(|name_id| name_id.value.trim())
            .filter(|value| crate::auth::oidc::email::claim_looks_like_an_address(value))
    {
        emails.insert(name_id.to_owned());
    }
    if emails.len() != 1 {
        return Err(SamlError::IdentityRejected);
    }
    Ok(emails.pop_first().expect("len 已判为 1"))
}

fn extract_groups(
    assertion: &Assertion,
    configured: Option<&str>,
    normalization: GroupNormalization,
) -> Result<BTreeSet<GroupName>, SamlError> {
    let Some(configured) = configured else {
        return Ok(BTreeSet::new());
    };
    let values = attribute_values(assertion, configured);
    if values.len() > MAX_GROUP_CLAIM_VALUES {
        return Err(SamlError::IdentityRejected);
    }
    let mut groups = BTreeSet::new();
    for value in values {
        if value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(SamlError::IdentityRejected);
        }
        if let Some(group) = GroupName::fold(value, normalization) {
            groups.insert(group);
        }
    }
    Ok(groups)
}

fn attribute_values<'a>(assertion: &'a Assertion, name: &str) -> Vec<&'a str> {
    assertion
        .attribute_statements
        .iter()
        .flatten()
        .flat_map(|statement| &statement.attributes)
        .filter(|attribute| {
            attribute.name.as_deref() == Some(name)
                || attribute.friendly_name.as_deref() == Some(name)
        })
        .flat_map(|attribute| &attribute.values)
        .filter_map(|value| value.value.as_deref())
        .collect()
}

fn validate_metadata_expiry(
    value: Option<&DateTime<Utc>>,
    now: OffsetDateTime,
) -> Result<(), SamlError> {
    if let Some(expiry) = value {
        let expiry = from_chrono(*expiry).map_err(|_| SamlError::MetadataRejected)?;
        if expiry <= now + MAX_CLOCK_SKEW {
            return Err(SamlError::MetadataRejected);
        }
    }
    Ok(())
}

fn validate_certificates(
    certificates: &[CertificateDer],
    now: OffsetDateTime,
) -> Result<(), SamlError> {
    let now = Asn1Time::from_unix(now.unix_timestamp()).map_err(|_| SamlError::MetadataRejected)?;
    for certificate in certificates {
        let certificate =
            X509::from_der(certificate.der_data()).map_err(|_| SamlError::MetadataRejected)?;
        if certificate
            .not_before()
            .compare(&now)
            .map_err(|_| SamlError::MetadataRejected)?
            .is_gt()
            || !certificate
                .not_after()
                .compare(&now)
                .map_err(|_| SamlError::MetadataRejected)?
                .is_gt()
        {
            return Err(SamlError::MetadataRejected);
        }
        certificate
            .public_key()
            .map_err(|_| SamlError::MetadataRejected)?;
    }
    Ok(())
}

fn validate_endpoint(raw: &str) -> Result<Url, SamlError> {
    if raw.is_empty() || raw.len() > MAX_URL_BYTES || raw.chars().any(char::is_control) {
        return Err(SamlError::MetadataRejected);
    }
    let url = Url::parse(raw).map_err(|_| SamlError::MetadataRejected)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str() != raw
    {
        return Err(SamlError::MetadataRejected);
    }
    Ok(url)
}

fn validate_issue_instant(value: DateTime<Utc>, now: OffsetDateTime) -> Result<(), SamlError> {
    let value = from_chrono(value)?;
    if value > now + MAX_CLOCK_SKEW || value + MAX_ISSUE_DELAY < now {
        Err(SamlError::TimeRejected)
    } else {
        Ok(())
    }
}

fn validate_window(
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: DateTime<Utc>,
    now: OffsetDateTime,
) -> Result<OffsetDateTime, SamlError> {
    let expiry = from_chrono(not_on_or_after)?;
    if not_before
        .map(from_chrono)
        .transpose()?
        .is_some_and(|start| now + MAX_CLOCK_SKEW < start)
        || now >= expiry + MAX_CLOCK_SKEW
    {
        Err(SamlError::TimeRejected)
    } else {
        Ok(expiry)
    }
}

fn to_chrono(value: OffsetDateTime) -> Result<DateTime<Utc>, SamlError> {
    DateTime::from_timestamp(value.unix_timestamp(), value.nanosecond())
        .ok_or(SamlError::TimeRejected)
}

fn from_chrono(value: DateTime<Utc>) -> Result<OffsetDateTime, SamlError> {
    OffsetDateTime::from_unix_timestamp_nanos(
        value
            .timestamp_nanos_opt()
            .ok_or(SamlError::TimeRejected)?
            .into(),
    )
    .map_err(|_| SamlError::TimeRejected)
}

fn valid_identity_scalar(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SUBJECT_BYTES && !value.chars().any(char::is_control)
}

fn strict_xml_document(
    xml: &str,
    expected_namespace: &[u8],
    expected_local_name: &[u8],
    max_bytes: usize,
) -> Result<(), SamlError> {
    if xml.is_empty()
        || xml.len() > max_bytes
        || xml.as_bytes().contains(&0)
        || xml.contains("<!DOCTYPE")
        || xml.contains("<!ENTITY")
    {
        return Err(SamlError::XmlRejected);
    }
    let mut reader = NsReader::from_str(xml);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut elements = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|_| SamlError::XmlRejected)?;
        match event {
            Event::Start(start) => {
                if depth == 0 {
                    if root_seen
                        || root_closed
                        || !element_matches(
                            &namespace,
                            start.local_name().as_ref(),
                            expected_namespace,
                            expected_local_name,
                        )
                    {
                        return Err(SamlError::XmlRejected);
                    }
                    root_seen = true;
                }
                validate_attributes(&start)?;
                depth = depth.checked_add(1).ok_or(SamlError::XmlRejected)?;
                elements += 1;
                if depth > MAX_XML_DEPTH || elements > MAX_XML_ELEMENTS {
                    return Err(SamlError::XmlRejected);
                }
            }
            Event::Empty(start) => {
                if depth == 0 {
                    if root_seen
                        || root_closed
                        || !element_matches(
                            &namespace,
                            start.local_name().as_ref(),
                            expected_namespace,
                            expected_local_name,
                        )
                    {
                        return Err(SamlError::XmlRejected);
                    }
                    root_seen = true;
                    root_closed = true;
                }
                validate_attributes(&start)?;
                elements += 1;
                if elements > MAX_XML_ELEMENTS {
                    return Err(SamlError::XmlRejected);
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(SamlError::XmlRejected)?;
                if depth == 0 {
                    root_closed = true;
                }
            }
            Event::Text(text) if depth == 0 => {
                if !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return Err(SamlError::XmlRejected);
                }
            }
            Event::CData(_) if depth == 0 => return Err(SamlError::XmlRejected),
            Event::DocType(_) | Event::PI(_) => return Err(SamlError::XmlRejected),
            Event::Eof => break,
            _ => {}
        }
    }
    if root_seen && root_closed && depth == 0 {
        Ok(())
    } else {
        Err(SamlError::XmlRejected)
    }
}

fn validate_attributes(start: &quick_xml::events::BytesStart<'_>) -> Result<(), SamlError> {
    let mut count = 0usize;
    for attribute in start.attributes().with_checks(true) {
        attribute.map_err(|_| SamlError::XmlRejected)?;
        count += 1;
        if count > MAX_XML_ATTRIBUTES_PER_ELEMENT {
            return Err(SamlError::XmlRejected);
        }
    }
    Ok(())
}

fn element_matches(
    namespace: &ResolveResult<'_>,
    local_name: &[u8],
    expected_namespace: &[u8],
    expected_local_name: &[u8],
) -> bool {
    local_name == expected_local_name
        && matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == expected_namespace)
}

fn escape_xml_attribute(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_DER_BASE64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6H3yHJdqdNCah3hVBs6//CoHo5GcYluT90b9+A8Jy5jyjCk+WFTvb3cGAuH9MMZCEAvXmMJr0pD3XFOHeguXzLXz+vkQTyb3fw/6QTI6wi2zYchdLajsUSXGujDUdKTfwWn7S7Q3vfaVYZymt69kdG/JhXa8tZ1dPzJKGLsthaKfMx8DQ0/AG9lXSKBrJtY39muVbRi4gCZHnxemQIMRaE7FDr83Jn6Ixugi0XG2MTY3XMT1lITALd3UMqkxs5PxrLMyt5wbxPzNFw3ZjcNIPSngxvtDBgeK3iMoARk/wOINqm+Kel9PXRI77By/hTtJPshRpSqCke4KBPPbGP7qfAgMBAAECggEAAVwBg4CEnD6pRD1kV6/W9TyVE6e3aQ07wZl/6zezz+Bb86+Q7T5dIDn6aSpFI7/+QjiTUInCV/nAdIsJK0rhdb6QpHusm525mUzL1dn5S34j3rYr8re6lBIFQTUc84g9ia/fhULd+zB7vgLi4bZQm6R8nLbGdMUbH3trBo0znGktarBW9BzSC3VbTNNAD0ffWiaC3JMWRY5dzwlmFE15nnzD89uotfyaWqTM3LEjT1bp+xRZllLE9K8OjwI+mCpGNkHIVMAEgGc8XKLa7Z8cOIADvE9NwUfeCcSE0jID8jEYGXpJKNP6Za+2azYC3KkVDiePMVHzp0BccGZ8LjIQIQKBgQDf5wZfhM6dk4YVGKpXFv/SrkklNMYMufKYyn1hgPJufbE7SBqV25W5wjeHG2WqrnZs+7jgu5FRTRL4XIu6StbInWVK1IfqGpIS3Y1QG8GBzTfB0vVv1qta5AfEM3all6xzTEuqs4LWS8Ou+0v7OeFbF0la3o3fBRJN+XuAIygWowKBgQDUzf9A90igB15gXCNxDU8Qgxdy6Y8CZFJ/2fakYtngOIY8mhjWEbQnly6gLO4z/iqRLDqt84hpYEHzYfZ+Tc13Q3FD4b3/YHGH37dzwIiIzQALxI86GQjPr+h2cXHRdIO05LQRLBP6g/UNf9ucw0SdbCLVmGMZZxGpEfU1YbbX1QKBgALjCqz+nF9hwI/TEpcu37uKrbzCEm+lkiAwNC+mpvmPu1JFWrpl62dKvsaKLuRlfXdoQ3j6UiRXNxBmuRJ81oodpWmyldIJ56pAmwrWYMdYqwhfvPRlMy5n1EXOWBBIhVuzNyKLT/uNXIeMC+3AUEyJX1PBnNisSxEgT1xWl7S7AoGAFn7wTN3XP5OH1ofm9zyA7y3sfKlUBNy2G+3etOH+RkWzaxSfK4ITmVvSAfy98aEcvtv+GAV2li0my6O/evqejc0DXDmw7B414jc0HXhs9ok1SAkvWuTqmYnu+RZlAc9fXPAQWQBf3Eu2zAaIILpDtqCHziydzUGoDEdptIrv2UECgYAH/bT70ViUbuVU/KHYCqR/9VJ11fkQoQegQw+JSQIkuyvMsaTNR/E3Kr0G31z6zq8/06Gwdj4rnjlqyr9+U6hLquHdGAwwJ4ZVCfhpSK5KMHGvV93UzhGLMfYSg2ir3+siUZ08ZMB5BG43ujXy6zjXGuGhJxU+5lW/IKO/QttV/g==";
    const TEST_CERT_DER_BASE64: &str = "MIIDIzCCAgugAwIBAgIUX4VCIW1pLys81pciNp1/JOQoi4QwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UEAwwVT3BlbkJvdCBTQU1MIFRlc3QgSWRQMCAXDTI2MDgyMzE5NDEzNloYDzIxMjYwNzMwMTk0MTM2WjAgMR4wHAYDVQQDDBVPcGVuQm90IFNBTUwgVGVzdCBJZFAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6H3yHJdqdNCah3hVBs6//CoHo5GcYluT90b9+A8Jy5jyjCk+WFTvb3cGAuH9MMZCEAvXmMJr0pD3XFOHeguXzLXz+vkQTyb3fw/6QTI6wi2zYchdLajsUSXGujDUdKTfwWn7S7Q3vfaVYZymt69kdG/JhXa8tZ1dPzJKGLsthaKfMx8DQ0/AG9lXSKBrJtY39muVbRi4gCZHnxemQIMRaE7FDr83Jn6Ixugi0XG2MTY3XMT1lITALd3UMqkxs5PxrLMyt5wbxPzNFw3ZjcNIPSngxvtDBgeK3iMoARk/wOINqm+Kel9PXRI77By/hTtJPshRpSqCke4KBPPbGP7qfAgMBAAGjUzBRMB0GA1UdDgQWBBRiEZ5u2WJHOQeOrautNPOahGlEDTAfBgNVHSMEGDAWgBRiEZ5u2WJHOQeOrautNPOahGlEDTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA4VkmWF6Q/Eb255tJWnlg3rot5RBNihPY9YL9TLtxdhkCzq+0KsFoafrdQLR2tzMZ6fKzBgGf1XPiciHLfapddQRIvm5AgId87Taeo6hBfqzsv8kJEBgEkT5XTwjsxXcG++a+RRKCweOBx2hhcd0lWpC905KaAbOcw3EOkpjjGPVjXqIQ/9OiPus2ILuQPJJH3zTGXUPO0wIxEINOBmBCFnp1/xNJl5UzHbIfifrVY0n5VPg4FCC8TSQr950YapOr2eAbbVr4sRtyrAYaYBdKgAnpqllB7Uh0dIESP+JyE07YNBUdBQCxzrF0na5GqJALXyL/YlLfTKoRSgbQJv+xW";
    const NOW: i64 = 1_800_000_000;

    fn runtime() -> SamlRuntime {
        runtime_for_issuer("https://idp.example/entity")
    }

    fn runtime_for_issuer(issuer: &str) -> SamlRuntime {
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{issuer}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERT_DER_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        );
        SamlRuntime::build(
            ProviderId::parse("acme-saml").unwrap(),
            issuer,
            [EmailDomain::parse("example.com").unwrap()]
                .into_iter()
                .collect(),
            SamlSecretConfig {
                entry_point: "https://idp.example/sso".to_owned(),
                metadata,
                email_attribute: "email".to_owned(),
                group_attribute: Some("groups".to_owned()),
                group_normalization: GroupNormalization::TrimLowercase,
            },
            "https://app.example",
            OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        )
        .unwrap()
    }

    fn response_template(
        destination: &str,
        signature_algorithm: &str,
        digest_algorithm: &str,
    ) -> String {
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="response-1" Version="2.0" IssueInstant="2027-01-15T08:00:00Z" Destination="{destination}" InResponseTo="request-1"><saml:Issuer>https://idp.example/entity</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{signature_algorithm}"/><ds:Reference URI="#response-1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="{digest_algorithm}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="assertion-1" Version="2.0" IssueInstant="2027-01-15T08:00:00Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">directory-person-1</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2027-01-15T08:10:00Z" Recipient="https://app.example/api/auth/sso/saml2/sp/acs/acme-saml" InResponseTo="request-1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="2027-01-15T08:10:00Z"><saml:AudienceRestriction><saml:Audience>https://app.example/api/auth/sso/saml2/sp/metadata/acme-saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2027-01-15T08:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema">Person@Example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue> Risk </saml:AttributeValue><saml:AttributeValue>Finance</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"##
        )
    }

    fn sign(template: &str) -> String {
        let key = BASE64_STANDARD.decode(TEST_KEY_DER_BASE64).unwrap();
        Crypto::sign_xml(template.as_bytes(), &key).unwrap()
    }

    #[test]
    fn strict_xml_preflight_rejects_dtd_wrong_root_trailing_root_and_depth_bombs() {
        let valid = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
        assert!(strict_xml_document(valid, SAML_PROTOCOL_NS, b"Response", 1024).is_ok());
        for bad in [
            r#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
            r#"<Response xmlns="urn:example:wrong"/>"#,
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
        ] {
            assert_eq!(
                strict_xml_document(bad, SAML_PROTOCOL_NS, b"Response", 4096),
                Err(SamlError::XmlRejected)
            );
        }
        let deep = format!(
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">{}{}</samlp:Response>",
            "<x>".repeat(MAX_XML_DEPTH),
            "</x>".repeat(MAX_XML_DEPTH)
        );
        assert_eq!(
            strict_xml_document(&deep, SAML_PROTOCOL_NS, b"Response", MAX_XML_BYTES),
            Err(SamlError::XmlRejected)
        );
    }

    #[test]
    fn allowed_algorithms_exclude_sha1_sha224_and_dsa() {
        let uris: BTreeSet<&str> = ALLOWED_SIGNATURE_ALGORITHMS
            .iter()
            .map(AllowedSignatureAlgorithm::signature_uri)
            .collect();
        assert!(uris.iter().all(|uri| !uri.contains("sha1")));
        assert!(uris.iter().all(|uri| !uri.contains("sha224")));
        assert!(!uris.contains("http://www.w3.org/2009/xmldsig11#dsa-sha256"));
        assert!(uris.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));
        assert_eq!(
            runtime_for_issuer("urn:example:idp:directory").idp_issuer,
            "urn:example:idp:directory"
        );

        let unsafe_transform = response_template(
            "https://app.example/api/auth/sso/saml2/sp/acs/acme-saml",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )
        .replace(
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
            "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"/>",
        )
        .replace(
            "<ds:DigestValue/>",
            "<ds:DigestValue>nonempty</ds:DigestValue>",
        )
        .replace(
            "<ds:SignatureValue/>",
            "<ds:SignatureValue>nonempty</ds:SignatureValue>",
        );
        assert_eq!(
            preflight_response_signature_shape(&unsafe_transform),
            Err(SamlError::SignatureRejected)
        );
    }

    #[test]
    fn signed_response_is_bound_to_destination_audience_recipient_request_and_identity() {
        let runtime = runtime();
        let good = sign(&response_template(
            runtime.acs_url(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ));
        let encoded = BASE64_STANDARD.encode(good.as_bytes());
        let verified = runtime
            .verify_response(
                &encoded,
                "request-1",
                runtime.acs_url(),
                OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
            )
            .unwrap();
        assert_eq!(verified.assertion_id, "assertion-1");
        assert_eq!(verified.identity.subject(), "directory-person-1");
        assert_eq!(verified.identity.email(), "Person@Example.com");
        assert_eq!(
            verified.assertion_expires_at,
            OffsetDateTime::from_unix_timestamp(NOW).unwrap() + Duration::minutes(12),
            "replay expiry 必须覆盖 assertion 的 10 分钟有效期与 2 分钟 clock skew"
        );

        let group_bomb = response_template(
            runtime.acs_url(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )
        .replace(
            "<saml:AttributeValue> Risk </saml:AttributeValue><saml:AttributeValue>Finance</saml:AttributeValue>",
            &"<saml:AttributeValue>risk</saml:AttributeValue>"
                .repeat(MAX_GROUP_CLAIM_VALUES + 1),
        );
        let group_bomb = sign(&group_bomb);
        assert_eq!(
            runtime
                .verify_response(
                    &BASE64_STANDARD.encode(group_bomb),
                    "request-1",
                    runtime.acs_url(),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                )
                .err(),
            Some(SamlError::IdentityRejected)
        );

        let unsigned = response_template(
            runtime.acs_url(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        );
        assert_eq!(
            runtime
                .verify_response(
                    &BASE64_STANDARD.encode(unsigned),
                    "request-1",
                    runtime.acs_url(),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                )
                .err(),
            Some(SamlError::SignatureRejected)
        );

        let wrong_destination = sign(&response_template(
            "https://app.example/wrong-acs",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ));
        assert_eq!(
            runtime
                .verify_response(
                    &BASE64_STANDARD.encode(wrong_destination),
                    "request-1",
                    runtime.acs_url(),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                )
                .err(),
            Some(SamlError::ProfileRejected)
        );

        for malformed_profile in [
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace(
                "<saml:SubjectConfirmationData ",
                "<saml:SubjectConfirmationData Address=\"203.0.113.55\" ",
            ),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace(
                "https://app.example/api/auth/sso/saml2/sp/metadata/acme-saml",
                "https://other-sp.example/metadata",
            ),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace(
                "Recipient=\"https://app.example/api/auth/sso/saml2/sp/acs/acme-saml\"",
                "Recipient=\"https://other-sp.example/acs\"",
            ),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace(
                "InResponseTo=\"request-1\"",
                "InResponseTo=\"other-request\"",
            ),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace("2027-01-15T08:10:00Z", "2027-01-15T09:00:00Z"),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace(
                "AuthnInstant=\"2027-01-15T08:00:00Z\"",
                "AuthnInstant=\"2027-01-15T09:00:00Z\"",
            ),
            response_template(
                runtime.acs_url(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )
            .replace("2027-01-15T08:10:00Z", "2026-01-15T08:10:00Z"),
        ] {
            let signed = sign(&malformed_profile);
            assert!(
                runtime
                    .verify_response(
                        &BASE64_STANDARD.encode(signed),
                        "request-1",
                        runtime.acs_url(),
                        OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                    )
                    .is_err(),
                "Audience/Recipient/InResponseTo/assertion/authn time 任一错都必须拒绝"
            );
        }

        let sha1 = sign(&response_template(
            runtime.acs_url(),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        ));
        assert_eq!(
            runtime
                .verify_response(
                    &BASE64_STANDARD.encode(sha1),
                    "request-1",
                    runtime.acs_url(),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                )
                .err(),
            Some(SamlError::SignatureRejected)
        );

        let sha1_digest = sign(&response_template(
            runtime.acs_url(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        ));
        assert_eq!(
            runtime
                .verify_response(
                    &BASE64_STANDARD.encode(sha1_digest),
                    "request-1",
                    runtime.acs_url(),
                    OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
                )
                .err(),
            Some(SamlError::SignatureRejected),
            "安全 SignatureMethod 不能掩盖 SHA-1 DigestMethod"
        );
    }
}
