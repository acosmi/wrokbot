//! Pure user-created channel presentation rules.

/// Fixed upstream private-channel description persisted for user-created channels.
pub const PRIVATE_AGENT_CHANNEL_DESCRIPTION: &str = "Private agent channel.";
/// Maximum derived channel-name length in Unicode code points.
pub const MAX_CHANNEL_NAME_CODE_POINTS: usize = 120;

/// Deriving a name without any selected Agent is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("channel_agents_empty")]
pub struct EmptyChannelAgents;

/// Join canonical Agent names and truncate to 120 Unicode code points with one ellipsis.
pub fn derive_channel_name(names: &[String]) -> Result<String, EmptyChannelAgents> {
    if names.is_empty() {
        return Err(EmptyChannelAgents);
    }
    let joined = names.join(", ");
    if joined.chars().count() <= MAX_CHANNEL_NAME_CODE_POINTS {
        return Ok(joined);
    }
    let mut truncated = joined
        .chars()
        .take(MAX_CHANNEL_NAME_CODE_POINTS - 1)
        .collect::<String>();
    truncated.push('…');
    Ok(truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names_are_joined_in_the_supplied_order() {
        assert_eq!(
            derive_channel_name(&["Alpha".to_owned(), "Beta".to_owned()]).unwrap(),
            "Alpha, Beta"
        );
        assert_eq!(derive_channel_name(&[]), Err(EmptyChannelAgents));
    }

    #[test]
    fn names_truncate_by_unicode_code_point_with_one_ellipsis() {
        let name = derive_channel_name(&["界".repeat(140)]).unwrap();
        assert_eq!(name.chars().count(), MAX_CHANNEL_NAME_CODE_POINTS);
        assert!(name.ends_with('…'));
    }
}
