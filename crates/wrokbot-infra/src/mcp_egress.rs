//! Canonical per-server MCP private-egress authority shared by catalog, OAuth and runtime.

use crate::net::safe_http::CidrAllowlist;

/// Database and wire cap for one custom MCP server.
pub(crate) const MAX_MCP_EGRESS_CIDRS: usize = 32;
/// Exact encoded list budget, including commas between PostgreSQL array elements.
pub(crate) const MAX_MCP_EGRESS_CIDR_BYTES: usize = 2_048;

/// Stored egress authority is malformed, non-canonical, duplicated, unsorted or oversized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidStoredMcpEgress;

/// Parse the one canonical representation accepted from PostgreSQL.
pub(crate) fn parse_stored_mcp_egress(
    entries: &[String],
) -> Result<CidrAllowlist, InvalidStoredMcpEgress> {
    let comma_bytes = entries.len().saturating_sub(1);
    let encoded_bytes = entries
        .iter()
        .try_fold(comma_bytes, |total, entry| total.checked_add(entry.len()))
        .ok_or(InvalidStoredMcpEgress)?;
    if entries.len() > MAX_MCP_EGRESS_CIDRS
        || encoded_bytes > MAX_MCP_EGRESS_CIDR_BYTES
        || entries.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(InvalidStoredMcpEgress);
    }
    let allowlist = CidrAllowlist::parse_exact(entries.iter().map(String::as_str))
        .map_err(|_| InvalidStoredMcpEgress)?;
    if allowlist.len() != entries.len() {
        return Err(InvalidStoredMcpEgress);
    }
    Ok(allowlist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_authority_is_bounded_sorted_unique_and_exact() {
        let valid = vec!["10.0.0.0/8".to_owned(), "127.0.0.1/32".to_owned()];
        assert_eq!(parse_stored_mcp_egress(&valid).unwrap().len(), 2);
        for invalid in [
            vec!["127.0.0.1/32".to_owned(), "10.0.0.0/8".to_owned()],
            vec!["10.0.0.0/8".to_owned(), "10.0.0.0/8".to_owned()],
            vec!["10.0.0.1/8".to_owned()],
            vec!["127.0.0.1".to_owned()],
        ] {
            assert_eq!(
                parse_stored_mcp_egress(&invalid),
                Err(InvalidStoredMcpEgress)
            );
        }
        assert!(parse_stored_mcp_egress(&vec!["10.0.0.0/8".to_owned(); 33]).is_err());
        assert!(parse_stored_mcp_egress(&[format!("10.0.0.0/{}", "8".repeat(2_048))]).is_err());
    }
}
