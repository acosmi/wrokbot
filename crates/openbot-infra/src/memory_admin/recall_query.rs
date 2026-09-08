//! Bounded literal Han candidate expansion; no segmentation or text normalization.

use openbot_application::{MAX_MEMORY_QUERY_BYTES, MemoryAdministrationError};

/// New query-work budget, independent of the existing 4 KiB input budget.
const MAX_HAN_LITERAL_TERMS: usize = 32;

pub(super) struct RecallQuery<'a> {
    pub(super) han_literals: Vec<&'a str>,
    pub(super) non_han_query: String,
}

pub(super) fn prepare(query: &str) -> Result<RecallQuery<'_>, MemoryAdministrationError> {
    if query.is_empty() || query.len() > MAX_MEMORY_QUERY_BYTES || query.as_bytes().contains(&0) {
        return Err(MemoryAdministrationError::InvalidInput { field: "query" });
    }

    let mut han_literals = Vec::new();
    let mut non_han_query = String::with_capacity(query.len());
    let mut han_start = None;
    for (index, character) in query.char_indices() {
        if is_han_ideograph(character) {
            if han_start.is_none() {
                han_start = Some(index);
                // Prevent Latin/numeric text on opposite sides from becoming a new word.
                non_han_query.push(' ');
            }
        } else {
            if let Some(start) = han_start.take() {
                add_literal(&mut han_literals, &query[start..index])?;
            }
            // C-locale PostgreSQL can keep fullwidth punctuation inside a word. The Han
            // supplement treats this explicit punctuation set as separators. ASCII apostrophes,
            // hyphens and all other text retain simple-parser semantics. The original FTS
            // branch still receives the original query, including for all English-only input.
            non_han_query.push(if is_cjk_separator(character) {
                ' '
            } else {
                character
            });
        }
    }
    if let Some(start) = han_start {
        add_literal(&mut han_literals, &query[start..])?;
    }
    Ok(RecallQuery {
        han_literals,
        non_han_query,
    })
}

fn add_literal<'a>(
    literals: &mut Vec<&'a str>,
    term: &'a str,
) -> Result<(), MemoryAdministrationError> {
    if !literals.contains(&term) {
        if literals.len() == MAX_HAN_LITERAL_TERMS {
            return Err(MemoryAdministrationError::InvalidInput { field: "query" });
        }
        literals.push(term);
    }
    Ok(())
}

/// Unified/compatibility Han ideographs (Lo), Unicode 17.0 Scripts.txt ranges.
/// Radicals, punctuation, iteration marks and other scripts keep simple FTS semantics.
/// Source: https://www.unicode.org/Public/17.0.0/ucd/Scripts.txt
fn is_han_ideograph(character: char) -> bool {
    matches!(
        u32::from(character),
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFA6D
            | 0xFA70..=0xFAD9
            | 0x20000..=0x2A6DF
            | 0x2A700..=0x2B81D
            | 0x2B820..=0x2CEAD
            | 0x2CEB0..=0x2EBE0
            | 0x2EBF0..=0x2EE5D
            | 0x2F800..=0x2FA1D
            | 0x30000..=0x3134A
            | 0x31350..=0x33479
    )
}

fn is_cjk_separator(character: char) -> bool {
    matches!(
        character,
        '、' | '。'
            | '〈'
            | '〉'
            | '《'
            | '》'
            | '「'
            | '」'
            | '『'
            | '』'
            | '【'
            | '】'
            | '〔'
            | '〕'
            | '〖'
            | '〗'
            | '〘'
            | '〙'
            | '〚'
            | '〛'
            | '〝'
            | '〞'
            | '〟'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '…'
            | '—'
    ) || matches!(
        u32::from(character),
        0xFF01..=0xFF0F | 0xFF1A..=0xFF20 | 0xFF3B..=0xFF40 | 0xFF5B..=0xFF65
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_bytes_and_han_boundaries_are_preserved() {
        let english = "O'Reilly, GPT-4 tea%_ 123";
        let plan = prepare(english).unwrap();
        assert!(plan.han_literals.is_empty());
        assert_eq!(plan.non_han_query, english);

        let plan = prepare("Rust乌龙茶，简洁_回答% Rust乌龙茶").unwrap();
        assert_eq!(plan.han_literals, ["乌龙茶", "简洁", "回答"]);
        assert_eq!(plan.non_han_query, "Rust   _ % Rust ");
        let plan = prepare("O'Reilly乌龙茶 GPT-4，Rust；tea").unwrap();
        assert_eq!(plan.non_han_query, "O'Reilly  GPT-4 Rust tea");
    }

    #[test]
    fn han_extensions_match_without_normalization() {
        let plan = prepare("㐀 𠀀 𰀀 﨑 烏龍茶 乌龙茶").unwrap();
        assert_eq!(
            plan.han_literals,
            ["㐀", "𠀀", "𰀀", "﨑", "烏龍茶", "乌龙茶"]
        );
        for character in ['A', 'あ', '한', '。', '〇', '\u{2A6E0}', '\u{3347A}'] {
            assert!(!is_han_ideograph(character));
        }
    }

    #[test]
    fn adapter_budget_is_closed_and_does_not_truncate() {
        let invalid = MemoryAdministrationError::InvalidInput { field: "query" };
        for query in [
            String::new(),
            "tea\0乌龙茶".to_owned(),
            "x".repeat(MAX_MEMORY_QUERY_BYTES + 1),
        ] {
            assert!(matches!(prepare(&query), Err(error) if error == invalid));
        }
        assert!(prepare(&"x".repeat(MAX_MEMORY_QUERY_BYTES)).is_ok());
        let boundary = format!("{}x", "茶".repeat((MAX_MEMORY_QUERY_BYTES - 1) / 3));
        assert_eq!(boundary.len(), MAX_MEMORY_QUERY_BYTES);
        assert!(prepare(&boundary).is_ok());
        assert!(prepare(&format!("{boundary}x")).is_err());

        let terms: Vec<String> = (0..=MAX_HAN_LITERAL_TERMS)
            .map(|index| {
                format!(
                    "茶{}",
                    char::from_u32(0x4E00 + u32::try_from(index).unwrap()).unwrap()
                )
            })
            .collect();
        assert!(prepare(&terms[..MAX_HAN_LITERAL_TERMS].join(" ")).is_ok());
        assert!(prepare(&terms.join(" ")).is_err());
        assert_eq!(
            prepare(&vec!["茶"; 100].join(" ")).unwrap().han_literals,
            ["茶"]
        );
        assert!(prepare(" %_，。 ").unwrap().han_literals.is_empty());
    }
}
