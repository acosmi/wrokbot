//! Actual SDK TokenSet ownership with a continuous all-six erase responsibility.

use std::{fmt::Write, mem, time::Duration};

use chrono::{DateTime, Datelike, TimeDelta, Timelike, Utc};
use zeroize::Zeroize;

use super::{
    CheckedExpiry, ClockSample, CodeTokenStart, InitialError, OwnedTokenBinding, ParsedTokenFields,
    ReplyInvalidReason, ReplyResources, TokenSetGuard,
};

fn invalid(reason: ReplyInvalidReason) -> InitialError {
    InitialError::ProtocolInvalid(reason)
}

fn checked_expiry(
    start: ClockSample,
    expires_in: std::num::NonZeroI64,
) -> Result<CheckedExpiry, InitialError> {
    let seconds = expires_in.get();
    if seconds <= 0 {
        return Err(invalid(ReplyInvalidReason::ExpiryInteger));
    }
    let delta = TimeDelta::try_seconds(seconds)
        .ok_or_else(|| invalid(ReplyInvalidReason::ClockOrExpiry))?;
    let wall_expiry = start
        .wall
        .checked_add_signed(delta)
        .ok_or_else(|| invalid(ReplyInvalidReason::ClockOrExpiry))?;
    let mono_expiry = start
        .mono
        .checked_add(Duration::from_secs(seconds as u64))
        .ok_or_else(|| invalid(ReplyInvalidReason::ClockOrExpiry))?;
    if !(0..=9999).contains(&wall_expiry.year()) || wall_expiry.nanosecond() >= 1_000_000_000 {
        return Err(invalid(ReplyInvalidReason::ClockOrExpiry));
    }
    let encoded_wall_expiry = wall_expiry
        .with_nanosecond((wall_expiry.nanosecond() / 1_000_000) * 1_000_000)
        .ok_or_else(|| invalid(ReplyInvalidReason::ClockOrExpiry))?;
    Ok(CheckedExpiry {
        original_start: start,
        wall_expiry,
        mono_expiry,
        encoded_wall_expiry,
    })
}

fn fields_valid(fields: &ParsedTokenFields) -> Result<(), InitialError> {
    if fields.token_type.as_str() != "Bearer" {
        return Err(invalid(ReplyInvalidReason::TokenType));
    }
    if !super::reply::graphic_token(fields.access_token.as_str())
        || !super::reply::graphic_token(fields.refresh_token.as_str())
    {
        return Err(invalid(ReplyInvalidReason::FieldLimit));
    }
    if !super::reply::scope_valid(fields.scope.as_str()) {
        return Err(invalid(ReplyInvalidReason::ScopeShape));
    }
    Ok(())
}

pub(super) fn assemble_tokens(
    mut fields: ParsedTokenFields,
    mut binding: OwnedTokenBinding,
    start: CodeTokenStart,
    resources: ReplyResources,
) -> Result<TokenSetGuard, InitialError> {
    resources.budget.check(&resources.clock)?;
    fields_valid(&fields)?;
    if !super::reply::client_id_valid(binding.client_id.as_str())
        || binding.server_url.as_str() != resources.metadata.sdk_metadata().issuer.as_str()
    {
        return Err(invalid(ReplyInvalidReason::ReplyBinding));
    }
    let expiry = checked_expiry(start.original, fields.expires_in)?;

    // The actual SDK object is all-empty when this Drop-armed owner is created.
    // Only infallible allocation moves follow; no bare TokenSet escapes.
    let mut owner = TokenSetGuard {
        sdk: acosmi::TokenSet {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: String::with_capacity(24),
            scope: String::new(),
            client_id: String::new(),
            server_url: String::new(),
        },
        expiry,
        resources,
    };
    owner.sdk.access_token = mem::take(&mut *fields.access_token);
    owner.sdk.refresh_token = mem::take(&mut *fields.refresh_token);
    owner.sdk.scope = mem::take(&mut *fields.scope);
    owner.sdk.client_id = mem::take(&mut *binding.client_id);
    owner.sdk.server_url = mem::take(&mut *binding.server_url);

    let encoded = owner.expiry.encoded_wall_expiry;
    write!(
        &mut owner.sdk.expires_at,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        encoded.year(),
        encoded.month(),
        encoded.day(),
        encoded.hour(),
        encoded.minute(),
        encoded.second(),
        encoded.nanosecond() / 1_000_000,
    )
    .map_err(|_| invalid(ReplyInvalidReason::ClockOrExpiry))?;
    if owner.sdk.expires_at.len() != 24 {
        return Err(invalid(ReplyInvalidReason::ClockOrExpiry));
    }
    let decoded = DateTime::parse_from_rfc3339(&owner.sdk.expires_at)
        .map_err(|_| invalid(ReplyInvalidReason::ClockOrExpiry))?
        .with_timezone(&Utc);
    if decoded != owner.expiry.encoded_wall_expiry {
        return Err(invalid(ReplyInvalidReason::ClockOrExpiry));
    }
    owner.final_checks()?;
    Ok(owner)
}

impl TokenSetGuard {
    /// SDK5's own Zeroize erases only two fields; this owner always erases six.
    pub(super) fn erase(&mut self) {
        self.sdk.access_token.zeroize();
        self.sdk.refresh_token.zeroize();
        self.sdk.expires_at.zeroize();
        self.sdk.scope.zeroize();
        self.sdk.client_id.zeroize();
        self.sdk.server_url.zeroize();
    }

    fn final_checks(&self) -> Result<(), InitialError> {
        let now = self.resources.budget.check(&self.resources.clock)?;
        let expiry = &self.expiry;
        if now.mono < expiry.original_start.mono
            || now.mono >= expiry.mono_expiry
            || now.wall < expiry.original_start.wall
            || now.wall >= expiry.wall_expiry
            || now.wall >= expiry.encoded_wall_expiry
        {
            return Err(invalid(ReplyInvalidReason::ClockOrExpiry));
        }
        if !super::reply::client_id_valid(&self.sdk.client_id)
            || self.sdk.server_url != self.resources.metadata.sdk_metadata().issuer
        {
            return Err(invalid(ReplyInvalidReason::ReplyBinding));
        }
        Ok(())
    }
}

impl Drop for TokenSetGuard {
    fn drop(&mut self) {
        self.erase();
    }
}

/// Inspect only logical field emptiness while the actual owned storage is alive.
#[cfg(test)]
pub(super) fn test_final_check_and_erase(
    owner: &mut TokenSetGuard,
) -> (Result<(), InitialError>, [bool; 6]) {
    let result = owner.final_checks();
    if result.is_err() {
        owner.erase();
    }
    (
        result,
        [
            owner.sdk.access_token.is_empty(),
            owner.sdk.refresh_token.is_empty(),
            owner.sdk.expires_at.is_empty(),
            owner.sdk.scope.is_empty(),
            owner.sdk.client_id.is_empty(),
            owner.sdk.server_url.is_empty(),
        ],
    )
}
